///|
/// Computes the Castagnoli CRC-32C checksum (RFC 9260 Appendix B).
pub fn crc32c(data : Bytes) -> UInt32 {
  @crc32c.crc32c(data)
}

///|
/// Seals a 64-byte HMAC-SHA256 authenticated stateless SCTP state cookie.
pub fn seal_cookie(secret : Bytes, payload : @cookie.CookiePayload) -> Bytes {
  @cookie.seal_cookie(secret, payload)
}

///|
/// Verifies and opens a 64-byte HMAC-SHA256 state cookie with constant-time MAC
/// and expiration checks.
pub fn open_cookie(
  secret : Bytes,
  cookie : Bytes,
  now_ms : UInt64,
  lifetime_ms : UInt64,
) -> @cookie.CookiePayload raise @cookie.CookieError {
  @cookie.open_cookie(secret, cookie, now_ms, lifetime_ms)
}

///|
/// Encodes an RFC 9260 SCTP packet with 4-byte chunk padding and Castagnoli CRC-32C.
pub fn encode_packet(pkt : @packet.Packet) -> Bytes raise @packet.PacketError {
  @packet.encode_packet(pkt)
}

///|
/// Decodes and verifies an RFC 9260 wire SCTP packet.
pub fn decode_packet(
  raw : BytesView,
) -> @packet.Packet raise @packet.PacketError {
  @packet.decode_packet(raw)
}

///|
/// Creates a client configuration with RFC 9260 defaults.
pub fn client_config(
  local_port : UInt32,
  remote_port : UInt32,
  local_vtag : UInt32,
  initial_tsn : UInt32,
  num_outbound_streams~ : UInt32 = 16U,
  num_inbound_streams~ : UInt32 = 16U,
) -> @association.Config {
  @association.Config::default_client(
    local_port,
    remote_port,
    local_vtag,
    initial_tsn,
    num_outbound_streams~,
    num_inbound_streams~,
  )
}

///|
/// Creates a server configuration with RFC 9260 defaults and HMAC cookie secret.
pub fn server_config(
  local_port : UInt32,
  remote_port : UInt32,
  local_vtag : UInt32,
  initial_tsn : UInt32,
  cookie_secret : Bytes,
  num_outbound_streams~ : UInt32 = 16U,
  num_inbound_streams~ : UInt32 = 16U,
) -> @association.Config {
  @association.Config::default_server(
    local_port,
    remote_port,
    local_vtag,
    initial_tsn,
    cookie_secret,
    num_outbound_streams~,
    num_inbound_streams~,
  )
}

///|
/// Creates a new Sans-I/O client SCTP association.
pub fn new_client(
  cfg : @association.Config,
) -> @association.Association raise @association.AssocError {
  @association.Association::new_client(cfg)
}

///|
/// Creates a new Sans-I/O server SCTP association.
pub fn new_server(
  cfg : @association.Config,
) -> @association.Association raise @association.AssocError {
  @association.Association::new_server(cfg)
}

///|
/// Statelessly validates an incoming `INIT` packet and returns a signed `INIT_ACK`
/// containing a 64-byte HMAC-SHA256 cookie without allocating session state.
pub fn process_stateless_init(
  cfg : @association.Config,
  raw_pkt : BytesView,
  now_ms : UInt64,
) -> Bytes raise @association.AssocError {
  @association.Association::process_stateless_init(cfg, raw_pkt, now_ms)
}

///|
/// Reliable ordered send options on `stream_id`.
pub fn reliable_opts(
  stream_id : UInt32,
  ppid~ : UInt32 = 0U,
) -> @association.SendOptions {
  @association.SendOptions::reliable(stream_id, ppid~)
}

///|
/// Reliable unordered (`U=1`) send options on `stream_id`.
pub fn unordered_opts(
  stream_id : UInt32,
  ppid~ : UInt32 = 0U,
) -> @association.SendOptions {
  @association.SendOptions::unordered(stream_id, ppid~)
}

///|
/// RFC 3758 PR-SCTP send options bounded by maximum retransmissions.
pub fn partial_retransmit_opts(
  stream_id : UInt32,
  max_retransmits : Int32,
  ppid~ : UInt32 = 0U,
  unordered~ : Bool = false,
) -> @association.SendOptions {
  {
    stream_id,
    ppid,
    unordered,
    reliability: @association.ReliabilityPolicy::MaxRetransmits(max_retransmits),
  }
}

///|
/// RFC 3758 PR-SCTP send options bounded by millisecond lifetime.
pub fn partial_timed_opts(
  stream_id : UInt32,
  lifetime_ms : UInt64,
  ppid~ : UInt32 = 0U,
  unordered~ : Bool = false,
) -> @association.SendOptions {
  {
    stream_id,
    ppid,
    unordered,
    reliability: @association.ReliabilityPolicy::TimedMs(lifetime_ms),
  }
}

///|
/// Drives a full 4-way RFC 9260 Cookie handshake (`INIT` -> `INIT_ACK` ->
/// `COOKIE_ECHO` -> `COOKIE_ACK`) over an in-memory channel between `client`
/// and `server`, returning `(client_to_server_packets, server_to_client_packets)`.
pub fn run_handshake_loop(
  client : @association.Association,
  server : @association.Association,
  now_ms : UInt64,
) -> (Int32, Int32) raise @association.AssocError {
  let mut c2s = 0
  let mut s2c = 0
  let mut t = now_ms

  let mut to_server = client.connect(t)
  let mut to_client : Array[Bytes] = []
  let mut rounds = 0

  while (
          client.state() != @association.AssocState::Established ||
          server.state() != @association.AssocState::Established
        ) &&
        rounds < 16 {
    rounds = rounds + 1
    if to_server.length() > 0 {
      let batch = to_server
      to_server = []
      for i = 0; i < batch.length(); i = i + 1 {
        c2s = c2s + 1
        t = t + 5UL
        let _ = server.handle_packet(batch[i][:], t)
        let reply = server.poll_outbound()
        for j = 0; j < reply.length(); j = j + 1 {
          to_client.push(reply[j])
        }
      }
    }
    if to_client.length() > 0 {
      let batch = to_client
      to_client = []
      for i = 0; i < batch.length(); i = i + 1 {
        s2c = s2c + 1
        t = t + 5UL
        let _ = client.handle_packet(batch[i][:], t)
        let reply = client.poll_outbound()
        for j = 0; j < reply.length(); j = j + 1 {
          to_server.push(reply[j])
        }
      }
    }
    if to_server.length() == 0 && to_client.length() == 0 {
      break
    }
  }

  (c2s, s2c)
}
