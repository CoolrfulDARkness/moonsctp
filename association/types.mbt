///|
/// Default advertised receiver window (64 KiB).
pub const DEFAULT_A_RWND : UInt32 = 65536U

///|
/// Default maximum DATA chunk payload size (1200 bytes for safe UDP/IP MTU).
pub const DEFAULT_MAX_PAYLOAD_SIZE : Int32 = 1200

///|
/// Default state cookie lifetime in milliseconds (60 seconds).
pub const DEFAULT_COOKIE_LIFETIME_MS : UInt64 = 60000UL

///|
/// Default initial retransmission timeout in milliseconds (RFC 9260: 1s).
pub const DEFAULT_RTO_INITIAL_MS : UInt64 = 1000UL

///|
/// Default minimum retransmission timeout in milliseconds.
pub const DEFAULT_RTO_MIN_MS : UInt64 = 200UL

///|
/// Default maximum retransmission timeout in milliseconds (RFC 9260: 60s).
pub const DEFAULT_RTO_MAX_MS : UInt64 = 60000UL

///|
/// Default maximum single user message size (64 KiB, anti-OOM bound).
pub const DEFAULT_MAX_MESSAGE_SIZE : Int32 = 65536

///|
/// RFC 9260 Section 4 SCTP association states.
#derive(Debug, Eq)
pub(all) enum AssocState {
  Closed
  CookieWait
  CookieEchoed
  Established
  ShutdownPending
  ShutdownSent
  ShutdownReceived
  ShutdownAckSent
}

///|
/// RFC 3758 PR-SCTP per-message reliability policy.
#derive(Debug, Eq)
pub(all) enum ReliabilityPolicy {
  Reliable
  MaxRetransmits(Int32)
  TimedMs(UInt64)
}

///|
/// Per-message send options.
#derive(Debug, Eq)
pub(all) struct SendOptions {
  stream_id : UInt32
  ppid : UInt32
  unordered : Bool
  reliability : ReliabilityPolicy
}

///|
/// Creates default reliable ordered send options on the given stream.
pub fn SendOptions::reliable(
  stream_id : UInt32,
  ppid~ : UInt32 = 0U,
) -> SendOptions {
  { stream_id, ppid, unordered: false, reliability: Reliable, }
}

///|
/// Creates unordered send options on the given stream.
pub fn SendOptions::unordered(
  stream_id : UInt32,
  ppid~ : UInt32 = 0U,
  reliability~ : ReliabilityPolicy = Reliable,
) -> SendOptions {
  { stream_id, ppid, unordered: true, reliability, }
}

///|
/// A fully reassembled user message delivered by the association.
#derive(Debug, Eq)
pub(all) struct DeliveredMessage {
  stream_id : UInt32
  ppid : UInt32
  unordered : Bool
  payload : Bytes
}

///|
/// High-level events produced by the Sans-I/O SCTP association.
#derive(Debug, Eq)
pub(all) enum Event {
  Connected
  Message(DeliveredMessage)
  HeartbeatAcked(Bytes)
  PeerShutdown
  Closed
  Aborted(String)
}

///|
/// Errors raised by association configuration, framing, or security checks.
#derive(Debug, Eq)
pub suberror AssocError {
  InvalidState(String)
  InvalidStream(UInt32)
  MessageTooLarge(Int32)
  PacketError(String)
  SecurityViolation(String)
  InvalidConfig(String)
}

///|
/// Endpoint configuration for a Sans-I/O SCTP association.
#derive(Debug, Eq)
pub(all) struct Config {
  local_port : UInt32
  remote_port : UInt32
  local_vtag : UInt32
  initial_tsn : UInt32
  num_outbound_streams : UInt32
  num_inbound_streams : UInt32
  a_rwnd : UInt32
  max_payload_size : Int32
  cookie_secret : Bytes
  cookie_lifetime_ms : UInt64
  rto_initial_ms : UInt64
  rto_max_ms : UInt64
  max_message_size : Int32
}

///|
/// Constructs a client configuration with sensible RFC 9260 defaults.
pub fn Config::default_client(
  local_port : UInt32,
  remote_port : UInt32,
  local_vtag : UInt32,
  initial_tsn : UInt32,
  num_outbound_streams~ : UInt32 = 16U,
  num_inbound_streams~ : UInt32 = 16U,
) -> Config {
  {
    local_port,
    remote_port,
    local_vtag,
    initial_tsn,
    num_outbound_streams,
    num_inbound_streams,
    a_rwnd: DEFAULT_A_RWND,
    max_payload_size: DEFAULT_MAX_PAYLOAD_SIZE,
    cookie_secret: b"",
    cookie_lifetime_ms: DEFAULT_COOKIE_LIFETIME_MS,
    rto_initial_ms: DEFAULT_RTO_INITIAL_MS,
    rto_max_ms: DEFAULT_RTO_MAX_MS,
    max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
  }
}

///|
/// Constructs a server configuration with sensible RFC 9260 defaults.
pub fn Config::default_server(
  local_port : UInt32,
  remote_port : UInt32,
  local_vtag : UInt32,
  initial_tsn : UInt32,
  cookie_secret : Bytes,
  num_outbound_streams~ : UInt32 = 16U,
  num_inbound_streams~ : UInt32 = 16U,
) -> Config {
  {
    local_port,
    remote_port,
    local_vtag,
    initial_tsn,
    num_outbound_streams,
    num_inbound_streams,
    a_rwnd: DEFAULT_A_RWND,
    max_payload_size: DEFAULT_MAX_PAYLOAD_SIZE,
    cookie_secret,
    cookie_lifetime_ms: DEFAULT_COOKIE_LIFETIME_MS,
    rto_initial_ms: DEFAULT_RTO_INITIAL_MS,
    rto_max_ms: DEFAULT_RTO_MAX_MS,
    max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
  }
}

///|
/// Runtime observability statistics for an SCTP association.
#derive(Debug, Eq)
pub(all) struct AssocStats {
  cwnd : Int32
  rto_ms : UInt64
  packets_sent : Int32
  packets_recv : Int32
  retransmissions : Int32
  forward_tsn_sent : Int32
  messages_delivered : Int32
}

///|
/// Validates configuration bounds and security invariants.
fn validate_config(cfg : Config, is_server : Bool) -> Unit raise AssocError {
  if cfg.local_port == 0U || cfg.local_port > 65535U {
    raise InvalidConfig("local_port must be in 1..=65535")
  }
  if cfg.remote_port == 0U || cfg.remote_port > 65535U {
    raise InvalidConfig("remote_port must be in 1..=65535")
  }
  if cfg.local_vtag == 0U {
    raise InvalidConfig("local_vtag must not be zero")
  }
  if cfg.num_outbound_streams == 0U || cfg.num_outbound_streams > 65535U {
    raise InvalidConfig("num_outbound_streams must be in 1..=65535")
  }
  if cfg.num_inbound_streams == 0U || cfg.num_inbound_streams > 65535U {
    raise InvalidConfig("num_inbound_streams must be in 1..=65535")
  }
  if cfg.a_rwnd < 1500U {
    raise InvalidConfig("a_rwnd must be >= 1500")
  }
  if cfg.max_payload_size < 16 || cfg.max_payload_size > 65000 {
    raise InvalidConfig("max_payload_size must be in 16..=65000")
  }
  if cfg.max_message_size < cfg.max_payload_size {
    raise InvalidConfig("max_message_size must be >= max_payload_size")
  }
  if cfg.rto_initial_ms == 0UL || cfg.rto_max_ms < cfg.rto_initial_ms {
    raise InvalidConfig("invalid RTO bounds")
  }
  if is_server {
    if cfg.cookie_secret.length() == 0 {
      raise InvalidConfig("server cookie_secret must not be empty")
    }
    if cfg.cookie_lifetime_ms == 0UL {
      raise InvalidConfig("server cookie_lifetime_ms must be > 0")
    }
  }
}

///|
fn min_u32(a : UInt32, b : UInt32) -> UInt32 {
  if a < b {
    a
  } else {
    b
  }
}

///|
fn max_int(a : Int32, b : Int32) -> Int32 {
  if a > b {
    a
  } else {
    b
  }
}

///|
fn min_int(a : Int32, b : Int32) -> Int32 {
  if a < b {
    a
  } else {
    b
  }
}

///|
fn packet_error_message(err : @packet.PacketError) -> String {
  match err {
    TooShort(n) => "packet too short: " + n.to_string()
    BadChecksum(_, _) => "CRC-32C checksum mismatch"
    InvalidChunkLength(n) => "invalid chunk length: " + n.to_string()
    TruncatedChunk => "truncated chunk"
    InvalidParameter(msg) => "invalid parameter: " + msg
    UnknownCriticalChunk(t) =>
      "unknown critical chunk: " + t.to_int().to_string()
    InvalidFlags(f) => "invalid flags: " + f.to_int().to_string()
    ProtocolViolation(msg) => "protocol violation: " + msg
  }
}

///|
fn cookie_error_message(err : @cookie.CookieError) -> String {
  match err {
    InvalidLength(n) => "invalid cookie length: " + n.to_string()
    InvalidMac => "invalid cookie HMAC"
    Expired(age) => "expired cookie, age_ms=" + age.to_string()
  }
}

///|
fn bytes_to_ascii_lossy(b : Bytes) -> String {
  let buf = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    if v >= 32 && v <= 126 {
      buf.write_char(Int32::unsafe_to_char(v))
    } else {
      buf.write_char('?')
    }
  }
  buf.to_string()
}
