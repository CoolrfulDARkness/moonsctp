///|
/// Sans-I/O RFC 9260 SCTP + RFC 3758 PR-SCTP Association State Machine.
/// All internal state and cryptographic secrets are strictly private.
pub struct Association {
  priv cfg : Config
  priv is_server : Bool
  priv mut assoc_state : AssocState
  priv mut peer_vtag : UInt32
  priv mut negotiated_out_streams : UInt32
  priv mut negotiated_in_streams : UInt32
  priv mut peer_forward_tsn : Bool
  priv mut send_q : SendQueue?
  priv mut recv_t : RecvTracker?
  priv outbound : Array[Bytes]
  priv consumed_cookies : Array[Bytes]
  priv mut saved_cookie : Bytes?
  priv mut ctrl_rto_ms : UInt64
  priv mut t1_deadline_ms : UInt64?
  priv mut t2_deadline_ms : UInt64?
  priv mut packets_sent : Int32
  priv mut packets_recv : Int32
  priv mut retransmissions : Int32
  priv mut forward_tsn_sent : Int32
  priv mut messages_delivered : Int32
}

///|
/// Creates a new client-side SCTP association in the `Closed` state.
pub fn Association::new_client(cfg : Config) -> Association raise AssocError {
  validate_config(cfg, false)
  {
    cfg,
    is_server: false,
    assoc_state: Closed,
    peer_vtag: 0U,
    negotiated_out_streams: cfg.num_outbound_streams,
    negotiated_in_streams: cfg.num_inbound_streams,
    peer_forward_tsn: false,
    send_q: None,
    recv_t: None,
    outbound: [],
    consumed_cookies: [],
    saved_cookie: None,
    ctrl_rto_ms: cfg.rto_initial_ms,
    t1_deadline_ms: None,
    t2_deadline_ms: None,
    packets_sent: 0,
    packets_recv: 0,
    retransmissions: 0,
    forward_tsn_sent: 0,
    messages_delivered: 0,
  }
}

///|
/// Creates a new server-side SCTP association in the `Closed` state.
pub fn Association::new_server(cfg : Config) -> Association raise AssocError {
  validate_config(cfg, true)
  {
    cfg,
    is_server: true,
    assoc_state: Closed,
    peer_vtag: 0U,
    negotiated_out_streams: cfg.num_outbound_streams,
    negotiated_in_streams: cfg.num_inbound_streams,
    peer_forward_tsn: false,
    send_q: None,
    recv_t: None,
    outbound: [],
    consumed_cookies: [],
    saved_cookie: None,
    ctrl_rto_ms: cfg.rto_initial_ms,
    t1_deadline_ms: None,
    t2_deadline_ms: None,
    packets_sent: 0,
    packets_recv: 0,
    retransmissions: 0,
    forward_tsn_sent: 0,
    messages_delivered: 0,
  }
}

///|
fn verify_wire_crc32c(raw : BytesView) -> Unit raise AssocError {
  if raw.length() < @packet.COMMON_HEADER_LEN {
    raise PacketError("packet too short: " + raw.length().to_string())
  }
  let wire_crc = raw[8].to_uint() |
    (raw[9].to_uint() << 8) |
    (raw[10].to_uint() << 16) |
    (raw[11].to_uint() << 24)
  let calc_crc = @crc32c.sctp_packet_checksum(raw)
  if wire_crc != calc_crc {
    raise SecurityViolation("CRC-32C checksum mismatch")
  }
}

///|
fn decode_verified_packet(raw : BytesView) -> @packet.Packet raise AssocError {
  verify_wire_crc32c(raw)
  @packet.decode_packet(raw) catch {
    @packet.BadChecksum(_, _) =>
      raise SecurityViolation("CRC-32C checksum mismatch")
    err => raise PacketError(packet_error_message(err))
  }
}

///|
fn encode_packet_checked(pkt : @packet.Packet) -> Bytes raise AssocError {
  @packet.encode_packet(pkt) catch {
    err => raise PacketError(packet_error_message(err))
  }
}

///|
fn Association::encode_and_queue(
  self : Association,
  vtag : UInt32,
  chunks : Array[@packet.Chunk],
) -> Unit raise AssocError {
  let bytes = encode_packet_checked({
    src_port: self.cfg.local_port,
    dst_port: self.cfg.remote_port,
    verification_tag: vtag,
    chunks,
  })
  self.outbound.push(bytes)
  self.packets_sent = self.packets_sent + 1
}

///|
fn Association::encode_and_queue_infallible(
  self : Association,
  vtag : UInt32,
  chunks : Array[@packet.Chunk],
) -> Unit {
  let encoded : Bytes? = Some(
    @packet.encode_packet({
      src_port: self.cfg.local_port,
      dst_port: self.cfg.remote_port,
      verification_tag: vtag,
      chunks,
    }),
  ) catch {
    _ => None
  }
  match encoded {
    Some(bytes) => {
      self.outbound.push(bytes)
      self.packets_sent = self.packets_sent + 1
    }
    None => ()
  }
}

///|
fn Association::make_init_packet(self : Association) -> @packet.Packet {
  {
    src_port: self.cfg.local_port,
    dst_port: self.cfg.remote_port,
    verification_tag: 0U,
    chunks: [
      @packet.Chunk::Init({
        initiate_tag: self.cfg.local_vtag,
        a_rwnd: self.cfg.a_rwnd,
        num_outbound_streams: self.cfg.num_outbound_streams,
        num_inbound_streams: self.cfg.num_inbound_streams,
        initial_tsn: self.cfg.initial_tsn,
        forward_tsn_supported: true,
      }),
    ],
  }
}

///|
/// Stateless SYN-flood resistant `INIT` responder (RFC 9260 Section 5.1.3).
/// Allocates zero per-client session state and signs a 64-byte HMAC-SHA256 cookie.
pub fn Association::process_stateless_init(
  cfg : Config,
  raw_pkt : BytesView,
  now_ms : UInt64,
) -> Bytes raise AssocError {
  validate_config(cfg, true)
  let pkt = decode_verified_packet(raw_pkt)
  if pkt.verification_tag != 0U {
    raise SecurityViolation("INIT packet must carry zero Verification Tag")
  }
  if pkt.chunks.length() != 1 {
    raise SecurityViolation("INIT chunk must not be bundled with other chunks")
  }
  let init = match pkt.chunks[0] {
    @packet.Chunk::Init(ic) => ic
    _ => raise SecurityViolation("expected INIT chunk")
  }
  if init.initiate_tag == 0U {
    raise SecurityViolation("INIT initiate_tag must not be zero")
  }
  if init.num_outbound_streams == 0U || init.num_inbound_streams == 0U {
    raise SecurityViolation("INIT stream counts must be non-zero")
  }
  if init.a_rwnd < 1500U {
    raise SecurityViolation("INIT a_rwnd below RFC 9260 minimum (1500)")
  }
  let out_streams = min_u32(cfg.num_outbound_streams, init.num_inbound_streams)
  let in_streams = min_u32(cfg.num_inbound_streams, init.num_outbound_streams)
  let cookie_payload : @cookie.CookiePayload = {
    local_vtag: cfg.local_vtag,
    peer_vtag: init.initiate_tag,
    local_tsn: cfg.initial_tsn,
    peer_tsn: init.initial_tsn,
    out_streams,
    in_streams,
    peer_arwnd: init.a_rwnd,
    created_ms: now_ms,
  }
  let state_cookie = @cookie.seal_cookie(cfg.cookie_secret, cookie_payload)
  encode_packet_checked({
    src_port: cfg.local_port,
    dst_port: pkt.src_port,
    verification_tag: init.initiate_tag,
    chunks: [
      @packet.Chunk::InitAck({
        initiate_tag: cfg.local_vtag,
        a_rwnd: cfg.a_rwnd,
        num_outbound_streams: cfg.num_outbound_streams,
        num_inbound_streams: cfg.num_inbound_streams,
        initial_tsn: cfg.initial_tsn,
        state_cookie,
        forward_tsn_supported: true,
      }),
    ],
  })
}

///|
/// Initiates the 4-way handshake by emitting an `INIT` packet and transitioning
/// `Closed -> CookieWait`.
pub fn Association::connect(
  self : Association,
  now_ms : UInt64,
) -> Array[Bytes] raise AssocError {
  if self.is_server {
    raise InvalidState("server association cannot initiate connect()")
  }
  if self.assoc_state != Closed {
    raise InvalidState("connect() requires Closed state")
  }
  let init_bytes = encode_packet_checked(self.make_init_packet())
  self.assoc_state = CookieWait
  self.ctrl_rto_ms = self.cfg.rto_initial_ms
  self.t1_deadline_ms = Some(now_ms + self.ctrl_rto_ms)
  self.packets_sent = self.packets_sent + 1
  [init_bytes]
}

///|
fn Association::is_cookie_consumed(self : Association, digest : Bytes) -> Bool {
  for i = 0; i < self.consumed_cookies.length(); i = i + 1 {
    if @cookie.ct_eq(self.consumed_cookies[i], digest) {
      return true
    }
  }
  false
}

///|
fn Association::flush_send_queue(self : Association, now_ms : UInt64) -> Unit {
  match self.send_q {
    Some(sq) => {
      let batch = sq.collect_outbound(now_ms)
      self.retransmissions = self.retransmissions + batch.retransmitted
      for i = 0; i < batch.chunks.length(); i = i + 1 {
        match batch.chunks[i] {
          @packet.Chunk::ForwardTsn(_) =>
            if self.peer_forward_tsn {
              self.forward_tsn_sent = self.forward_tsn_sent + 1
              self.encode_and_queue_infallible(self.peer_vtag, [batch.chunks[i]])
            }
          _ =>
            self.encode_and_queue_infallible(self.peer_vtag, [batch.chunks[i]])
        }
      }
    }
    None => ()
  }
}

///|
fn Association::check_shutdown_drain(
  self : Association,
  now_ms : UInt64,
) -> Unit {
  let empty = match self.send_q {
    Some(sq) => sq.is_empty()
    None => true
  }
  if !empty {
    return
  }
  match self.assoc_state {
    ShutdownPending => {
      let cum_tsn = match self.recv_t {
        Some(rt) => rt.cum_tsn
        None => 0U
      }
      self.encode_and_queue_infallible(self.peer_vtag, [
        @packet.Chunk::Shutdown(cum_tsn),
      ])
      self.assoc_state = ShutdownSent
      self.ctrl_rto_ms = self.cfg.rto_initial_ms
      self.t2_deadline_ms = Some(now_ms + self.ctrl_rto_ms)
    }
    ShutdownReceived => {
      self.encode_and_queue_infallible(self.peer_vtag, [
        @packet.Chunk::ShutdownAck,
      ])
      self.assoc_state = ShutdownAckSent
      self.ctrl_rto_ms = self.cfg.rto_initial_ms
      self.t2_deadline_ms = Some(now_ms + self.ctrl_rto_ms)
    }
    _ => ()
  }
}

///|
/// Processes an incoming wire SCTP packet, verifying CRC-32C, Verification Tag,
/// HMAC cookies, state transitions, multi-stream reassembly, SACK, and PR-SCTP.
pub fn Association::handle_packet(
  self : Association,
  raw : BytesView,
  now_ms : UInt64,
) -> Array[Event] raise AssocError {
  let pkt = decode_verified_packet(raw)
  if pkt.chunks.length() == 0 {
    raise PacketError("SCTP packet contains no chunks")
  }
  self.packets_recv = self.packets_recv + 1

  let events : Array[Event] = []
  let mut need_sack = false

  // Packet-level Verification Tag checks (RFC 9260 Section 8.5)
  let first = pkt.chunks[0]
  match first {
    @packet.Chunk::Init(_) => {
      if pkt.verification_tag != 0U {
        raise SecurityViolation("INIT must have zero Verification Tag")
      }
      if pkt.chunks.length() != 1 {
        raise SecurityViolation("INIT must not be bundled")
      }
      if !self.is_server {
        raise SecurityViolation("client does not accept INIT")
      }
      // Stateless response without mutating association state.
      let ack_bytes = Association::process_stateless_init(self.cfg, raw, now_ms)
      self.outbound.push(ack_bytes)
      self.packets_sent = self.packets_sent + 1
      return events
    }
    @packet.Chunk::Abort(t_bit, causes) => {
      let valid_vtag = if t_bit {
        self.peer_vtag != 0U && pkt.verification_tag == self.peer_vtag
      } else {
        pkt.verification_tag == self.cfg.local_vtag
      }
      if !valid_vtag {
        // RFC 9260 Section 8.5.1: silently ignore ABORT with mismatched VTag.
        return events
      }
      let reason = if causes.length() > 0 && causes[0].info.length() > 0 {
        bytes_to_ascii_lossy(causes[0].info)
      } else {
        "peer aborted"
      }
      self.assoc_state = Closed
      self.t1_deadline_ms = None
      self.t2_deadline_ms = None
      self.send_q = None
      self.recv_t = None
      events.push(Event::Aborted(reason))
      return events
    }
    @packet.Chunk::ShutdownComplete(t_bit) => {
      let valid_vtag = if t_bit {
        self.peer_vtag != 0U && pkt.verification_tag == self.peer_vtag
      } else {
        pkt.verification_tag == self.cfg.local_vtag
      }
      if !valid_vtag {
        raise SecurityViolation("SHUTDOWN_COMPLETE Verification Tag mismatch")
      }
    }
    _ =>
      if pkt.verification_tag == 0U ||
        pkt.verification_tag != self.cfg.local_vtag {
        raise SecurityViolation("Verification Tag mismatch")
      }
  }

  for i = 0; i < pkt.chunks.length(); i = i + 1 {
    match pkt.chunks[i] {
      @packet.Chunk::Init(_) =>
        raise SecurityViolation("bundled INIT is forbidden")
      @packet.Chunk::InitAck(ack) => {
        if pkt.chunks.length() != 1 {
          raise SecurityViolation("INIT_ACK must not be bundled")
        }
        if self.is_server || self.assoc_state != CookieWait {
          raise SecurityViolation("unexpected INIT_ACK in current state")
        }
        if ack.initiate_tag == 0U {
          raise SecurityViolation("INIT_ACK initiate_tag must not be zero")
        }
        if ack.num_outbound_streams == 0U || ack.num_inbound_streams == 0U {
          raise SecurityViolation("INIT_ACK stream counts must be non-zero")
        }
        if ack.a_rwnd < 1500U {
          raise SecurityViolation("INIT_ACK a_rwnd below minimum")
        }
        if ack.state_cookie.length() == 0 {
          raise SecurityViolation("INIT_ACK missing state cookie")
        }
        self.peer_vtag = ack.initiate_tag
        self.negotiated_out_streams = min_u32(
          self.cfg.num_outbound_streams,
          ack.num_inbound_streams,
        )
        self.negotiated_in_streams = min_u32(
          self.cfg.num_inbound_streams,
          ack.num_outbound_streams,
        )
        self.peer_forward_tsn = ack.forward_tsn_supported
        self.send_q = Some(
          SendQueue::new(
            self.cfg.initial_tsn,
            self.negotiated_out_streams,
            self.cfg.max_payload_size,
            self.cfg.max_message_size,
            ack.a_rwnd,
            self.cfg.rto_initial_ms,
            self.cfg.rto_max_ms,
          ),
        )
        self.recv_t = Some(
          RecvTracker::new(
            ack.initial_tsn,
            self.negotiated_in_streams,
            self.cfg.max_message_size,
            self.cfg.a_rwnd,
          ),
        )
        self.saved_cookie = Some(ack.state_cookie)
        self.encode_and_queue(self.peer_vtag, [
          @packet.Chunk::CookieEcho(ack.state_cookie),
        ])
        self.assoc_state = CookieEchoed
        self.ctrl_rto_ms = self.cfg.rto_initial_ms
        self.t1_deadline_ms = Some(now_ms + self.ctrl_rto_ms)
      }
      @packet.Chunk::CookieEcho(cookie_bytes) => {
        if !self.is_server {
          raise SecurityViolation("client does not accept COOKIE_ECHO")
        }
        let payload = @cookie.open_cookie(
          self.cfg.cookie_secret,
          cookie_bytes,
          now_ms,
          self.cfg.cookie_lifetime_ms,
        ) catch {
          err => raise SecurityViolation(cookie_error_message(err))
        }
        if payload.local_vtag != self.cfg.local_vtag {
          raise SecurityViolation("cookie local_vtag mismatch")
        }
        if payload.peer_vtag == 0U ||
          payload.out_streams == 0U ||
          payload.in_streams == 0U {
          raise SecurityViolation("malformed cookie payload")
        }
        let digest = @cookie.sha256(cookie_bytes)
        if self.is_cookie_consumed(digest) {
          raise SecurityViolation("replayed state cookie rejected")
        }
        self.consumed_cookies.push(digest)

        self.peer_vtag = payload.peer_vtag
        self.negotiated_out_streams = min_u32(
          self.cfg.num_outbound_streams,
          payload.out_streams,
        )
        self.negotiated_in_streams = min_u32(
          self.cfg.num_inbound_streams,
          payload.in_streams,
        )
        self.peer_forward_tsn = true
        self.send_q = Some(
          SendQueue::new(
            payload.local_tsn,
            self.negotiated_out_streams,
            self.cfg.max_payload_size,
            self.cfg.max_message_size,
            payload.peer_arwnd,
            self.cfg.rto_initial_ms,
            self.cfg.rto_max_ms,
          ),
        )
        self.recv_t = Some(
          RecvTracker::new(
            payload.peer_tsn,
            self.negotiated_in_streams,
            self.cfg.max_message_size,
            self.cfg.a_rwnd,
          ),
        )
        self.encode_and_queue(self.peer_vtag, [@packet.Chunk::CookieAck])
        self.assoc_state = Established
        events.push(Event::Connected)
      }
      @packet.Chunk::CookieAck => {
        if self.is_server || self.assoc_state != CookieEchoed {
          raise SecurityViolation("unexpected COOKIE_ACK in current state")
        }
        self.assoc_state = Established
        self.saved_cookie = None
        self.t1_deadline_ms = None
        events.push(Event::Connected)
      }
      @packet.Chunk::Data(dc) => {
        let can_recv_data = match self.assoc_state {
          Established | ShutdownPending | ShutdownSent => true
          _ => false
        }
        if !can_recv_data {
          raise SecurityViolation("DATA chunk rejected before Established")
        }
        match self.recv_t {
          Some(rt) => {
            let msgs = rt.on_data(dc)
            for k = 0; k < msgs.length(); k = k + 1 {
              self.messages_delivered = self.messages_delivered + 1
              events.push(Event::Message(msgs[k]))
            }
            need_sack = true
          }
          None => raise InvalidState("receive tracker uninitialized")
        }
      }
      @packet.Chunk::Sack(sack) => {
        let can_recv_sack = match self.assoc_state {
          Established | ShutdownPending | ShutdownSent | ShutdownReceived =>
            true
          _ => false
        }
        if !can_recv_sack {
          raise SecurityViolation("SACK chunk rejected in current state")
        }
        match self.send_q {
          Some(sq) => sq.on_sack(sack, now_ms)
          None => ()
        }
      }
      @packet.Chunk::ForwardTsn(ft) => {
        let can_recv_ft = match self.assoc_state {
          Established | ShutdownPending | ShutdownSent => true
          _ => false
        }
        if !can_recv_ft {
          raise SecurityViolation("FORWARD_TSN rejected in current state")
        }
        match self.recv_t {
          Some(rt) => {
            let msgs = rt.on_forward_tsn(ft)
            for k = 0; k < msgs.length(); k = k + 1 {
              self.messages_delivered = self.messages_delivered + 1
              events.push(Event::Message(msgs[k]))
            }
            need_sack = true
          }
          None => raise InvalidState("receive tracker uninitialized")
        }
      }
      @packet.Chunk::Heartbeat(info) => {
        if self.assoc_state == Closed || self.peer_vtag == 0U {
          raise SecurityViolation("HEARTBEAT rejected before handshake")
        }
        self.encode_and_queue(self.peer_vtag, [
          @packet.Chunk::HeartbeatAck(info),
        ])
      }
      @packet.Chunk::HeartbeatAck(info) => {
        if self.assoc_state == Closed || self.peer_vtag == 0U {
          raise SecurityViolation("HEARTBEAT_ACK rejected before handshake")
        }
        events.push(Event::HeartbeatAcked(info))
      }
      @packet.Chunk::Shutdown(peer_cum_tsn) =>
        match self.assoc_state {
          Established | ShutdownPending => {
            match self.send_q {
              Some(sq) => sq.ack_up_to(peer_cum_tsn)
              None => ()
            }
            events.push(Event::PeerShutdown)
            self.assoc_state = ShutdownReceived
            self.check_shutdown_drain(now_ms)
          }
          ShutdownSent => {
            match self.send_q {
              Some(sq) => sq.ack_up_to(peer_cum_tsn)
              None => ()
            }
            events.push(Event::PeerShutdown)
            self.encode_and_queue(self.peer_vtag, [@packet.Chunk::ShutdownAck])
            self.assoc_state = ShutdownAckSent
            self.t2_deadline_ms = Some(now_ms + self.ctrl_rto_ms)
          }
          ShutdownReceived => {
            match self.send_q {
              Some(sq) => sq.ack_up_to(peer_cum_tsn)
              None => ()
            }
            self.check_shutdown_drain(now_ms)
          }
          ShutdownAckSent =>
            self.encode_and_queue(self.peer_vtag, [@packet.Chunk::ShutdownAck])
          _ => raise SecurityViolation("SHUTDOWN rejected before Established")
        }
      @packet.Chunk::ShutdownAck =>
        match self.assoc_state {
          ShutdownSent | ShutdownAckSent => {
            self.encode_and_queue(self.peer_vtag, [
              @packet.Chunk::ShutdownComplete(false),
            ])
            self.assoc_state = Closed
            self.t1_deadline_ms = None
            self.t2_deadline_ms = None
            events.push(Event::Closed)
          }
          _ =>
            raise SecurityViolation("unexpected SHUTDOWN_ACK in current state")
        }
      @packet.Chunk::ShutdownComplete(_) => {
        if self.assoc_state != ShutdownAckSent {
          raise SecurityViolation(
            "unexpected SHUTDOWN_COMPLETE in current state",
          )
        }
        self.assoc_state = Closed
        self.t1_deadline_ms = None
        self.t2_deadline_ms = None
        events.push(Event::Closed)
      }
      @packet.Chunk::Abort(_, causes) => {
        let reason = if causes.length() > 0 && causes[0].info.length() > 0 {
          bytes_to_ascii_lossy(causes[0].info)
        } else {
          "peer aborted"
        }
        self.assoc_state = Closed
        self.t1_deadline_ms = None
        self.t2_deadline_ms = None
        events.push(Event::Aborted(reason))
        return events
      }
      @packet.Chunk::Error(_) => ()
    }
  }

  if need_sack {
    match self.recv_t {
      Some(rt) => {
        let sack = rt.build_sack()
        self.encode_and_queue(self.peer_vtag, [@packet.Chunk::Sack(sack)])
      }
      None => ()
    }
  }

  match self.assoc_state {
    Established | ShutdownPending | ShutdownReceived => {
      self.flush_send_queue(now_ms)
      self.check_shutdown_drain(now_ms)
    }
    _ => ()
  }

  events
}

///|
/// Enqueues a user message on the specified stream, automatically fragmenting
/// by `max_payload_size` with B/E flags and transmitting eligible chunks.
pub fn Association::send(
  self : Association,
  payload : Bytes,
  opts : SendOptions,
  now_ms : UInt64,
) -> Unit raise AssocError {
  if self.assoc_state != Established {
    raise InvalidState("send() requires Established state")
  }
  match self.send_q {
    Some(sq) => {
      sq.enqueue_message(payload, opts, now_ms)
      self.flush_send_queue(now_ms)
    }
    None => raise InvalidState("send queue uninitialized")
  }
}

///|
/// Sends an RFC 9260 `HEARTBEAT` chunk carrying caller-provided opaque info.
pub fn Association::send_heartbeat(
  self : Association,
  info : Bytes,
  _now_ms : UInt64,
) -> Unit raise AssocError {
  if self.assoc_state != Established {
    raise InvalidState("send_heartbeat() requires Established state")
  }
  self.encode_and_queue(self.peer_vtag, [@packet.Chunk::Heartbeat(info)])
}

///|
/// Initiates a graceful RFC 9260 3-way shutdown (`SHUTDOWN` -> `SHUTDOWN_ACK` ->
/// `SHUTDOWN_COMPLETE`), draining any queued outbound data first.
pub fn Association::shutdown(
  self : Association,
  now_ms : UInt64,
) -> Unit raise AssocError {
  if self.assoc_state != Established {
    raise InvalidState("shutdown() requires Established state")
  }
  self.assoc_state = ShutdownPending
  self.check_shutdown_drain(now_ms)
}

///|
/// Immediately aborts the association by queueing an `ABORT` chunk and
/// transitioning to `Closed`.
pub fn Association::abort(self : Association, reason : Bytes) -> Unit {
  if self.assoc_state == Closed {
    return
  }
  let (vtag, t_bit) = if self.peer_vtag != 0U {
    (self.peer_vtag, false)
  } else {
    (self.cfg.local_vtag, true)
  }
  let causes : Array[@packet.ErrorCause] = if reason.length() > 0 {
    [{ code: 0x000CU, info: reason, }]
  } else {
    []
  }
  self.encode_and_queue_infallible(vtag, [@packet.Chunk::Abort(t_bit, causes)])
  self.assoc_state = Closed
  self.t1_deadline_ms = None
  self.t2_deadline_ms = None
  self.send_q = None
  self.recv_t = None
}

///|
/// Advances protocol timers: T1-init/T1-cookie, T3-rtx timeout with exponential
/// RTO backoff, PR-SCTP timed/max-retransmit abandonment + FORWARD_TSN, and
/// T2-shutdown retransmissions.
pub fn Association::tick(self : Association, now_ms : UInt64) -> Array[Event] {
  let events : Array[Event] = []
  match self.assoc_state {
    CookieWait =>
      match self.t1_deadline_ms {
        Some(deadline) =>
          if now_ms >= deadline {
            let next_rto = self.ctrl_rto_ms * 2UL
            self.ctrl_rto_ms = if next_rto > self.cfg.rto_max_ms {
              self.cfg.rto_max_ms
            } else {
              next_rto
            }
            self.t1_deadline_ms = Some(now_ms + self.ctrl_rto_ms)
            self.retransmissions = self.retransmissions + 1
            let pkt = self.make_init_packet()
            self.encode_and_queue_infallible(pkt.verification_tag, pkt.chunks)
          }
        None => ()
      }
    CookieEchoed =>
      match self.t1_deadline_ms {
        Some(deadline) =>
          if now_ms >= deadline {
            let next_rto = self.ctrl_rto_ms * 2UL
            self.ctrl_rto_ms = if next_rto > self.cfg.rto_max_ms {
              self.cfg.rto_max_ms
            } else {
              next_rto
            }
            self.t1_deadline_ms = Some(now_ms + self.ctrl_rto_ms)
            match self.saved_cookie {
              Some(ck) => {
                self.retransmissions = self.retransmissions + 1
                self.encode_and_queue_infallible(self.peer_vtag, [
                  @packet.Chunk::CookieEcho(ck),
                ])
              }
              None => ()
            }
          }
        None => ()
      }
    Established | ShutdownPending | ShutdownReceived => {
      match self.send_q {
        Some(sq) => {
          sq.check_timed_abandonments(now_ms)
          match sq.t3_deadline_ms {
            Some(deadline) => if now_ms >= deadline { sq.on_t3_timeout(now_ms) }
            None => ()
          }
        }
        None => ()
      }
      self.flush_send_queue(now_ms)
      self.check_shutdown_drain(now_ms)
    }
    ShutdownSent =>
      match self.t2_deadline_ms {
        Some(deadline) =>
          if now_ms >= deadline {
            let next_rto = self.ctrl_rto_ms * 2UL
            self.ctrl_rto_ms = if next_rto > self.cfg.rto_max_ms {
              self.cfg.rto_max_ms
            } else {
              next_rto
            }
            self.t2_deadline_ms = Some(now_ms + self.ctrl_rto_ms)
            self.retransmissions = self.retransmissions + 1
            let cum_tsn = match self.recv_t {
              Some(rt) => rt.cum_tsn
              None => 0U
            }
            self.encode_and_queue_infallible(self.peer_vtag, [
              @packet.Chunk::Shutdown(cum_tsn),
            ])
          }
        None => ()
      }
    ShutdownAckSent =>
      match self.t2_deadline_ms {
        Some(deadline) =>
          if now_ms >= deadline {
            let next_rto = self.ctrl_rto_ms * 2UL
            self.ctrl_rto_ms = if next_rto > self.cfg.rto_max_ms {
              self.cfg.rto_max_ms
            } else {
              next_rto
            }
            self.t2_deadline_ms = Some(now_ms + self.ctrl_rto_ms)
            self.retransmissions = self.retransmissions + 1
            self.encode_and_queue_infallible(self.peer_vtag, [
              @packet.Chunk::ShutdownAck,
            ])
          }
        None => ()
      }
    Closed => ()
  }
  events
}

///|
/// Drains and returns all pending outbound wire SCTP packets.
pub fn Association::poll_outbound(self : Association) -> Array[Bytes] {
  let out : Array[Bytes] = Array(capacity=self.outbound.length())
  for i = 0; i < self.outbound.length(); i = i + 1 {
    out.push(self.outbound[i])
  }
  self.outbound.clear()
  out
}

///|
/// Returns the current RFC 9260 association state.
pub fn Association::state(self : Association) -> AssocState {
  self.assoc_state
}

///|
/// Returns a snapshot of congestion, timing, and traffic statistics.
pub fn Association::stats(self : Association) -> AssocStats {
  let (cwnd, rto_ms) = match self.send_q {
    Some(sq) => (sq.cwnd, sq.rto_ms)
    None => (0, self.ctrl_rto_ms)
  }
  {
    cwnd,
    rto_ms,
    packets_sent: self.packets_sent,
    packets_recv: self.packets_recv,
    retransmissions: self.retransmissions,
    forward_tsn_sent: self.forward_tsn_sent,
    messages_delivered: self.messages_delivered,
  }
}
