///|
fn u32_hex(v : UInt32) -> String {
  let hex = "0123456789ABCDEF"
  let buf = StringBuilder()
  buf.write_string("0x")
  for shift = 28; shift >= 0; shift = shift - 4 {
    let nibble = ((v >> shift) & 0xFU).reinterpret_as_int()
    buf.write_char(hex[nibble].to_int().unsafe_to_char())
  }
  buf.to_string()
}

///|
fn flip_bit(b : Bytes, idx : Int32) -> Bytes {
  let arr : FixedArray[Byte] = FixedArray::make(b.length(), b'\x00')
  for i = 0; i < b.length(); i = i + 1 {
    arr[i] = if i == idx { (b[i].to_int() ^ 0x01).to_byte() } else { b[i] }
  }
  Bytes::from_array(arr)
}

///|
fn make_payload(tag : Int32, len : Int32) -> Bytes {
  let arr : FixedArray[Byte] = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    arr[i] = ((tag * 29 + i * 13 + 5) & 0xFF).to_byte()
  }
  Bytes::from_array(arr)
}

///|
priv struct SimPkt {
  deliver_at_ms : UInt64
  to_server : Bool
  raw : Bytes
}

///|
priv struct CliChaosNet {
  mut rng : UInt32
  loss_pct : Int32
  dup_pct : Int32
  queue : Array[SimPkt]
  mut sent : Int32
  mut dropped : Int32
  mut duped : Int32
}

///|
fn CliChaosNet::new(
  seed : UInt32,
  loss_pct : Int32,
  dup_pct : Int32,
) -> CliChaosNet {
  { rng: seed, loss_pct, dup_pct, queue: [], sent: 0, dropped: 0, duped: 0, }
}

///|
fn CliChaosNet::next_u32(self : CliChaosNet) -> UInt32 {
  let mut x = self.rng
  x = x ^ (x << 13)
  x = x ^ (x >> 17)
  x = x ^ (x << 5)
  self.rng = x
  x
}

///|
fn CliChaosNet::push_all(
  self : CliChaosNet,
  pkts : Array[Bytes],
  to_server : Bool,
  now_ms : UInt64,
) -> Unit {
  for i = 0; i < pkts.length(); i = i + 1 {
    self.sent = self.sent + 1
    let r = (self.next_u32() % 100U).reinterpret_as_int()
    if r < self.loss_pct {
      self.dropped = self.dropped + 1
      continue
    }
    let jitter = self.next_u32().to_uint64() % 55UL
    self.queue.push({
      deliver_at_ms: now_ms + 10UL + jitter,
      to_server,
      raw: pkts[i],
    })
    let dr = (self.next_u32() % 100U).reinterpret_as_int()
    if dr < self.dup_pct {
      self.duped = self.duped + 1
      let dj = self.next_u32().to_uint64() % 55UL
      self.queue.push({
        deliver_at_ms: now_ms + 10UL + dj,
        to_server,
        raw: pkts[i],
      })
    }
  }
}

///|
fn run_demo() -> Unit raise {
  println("==================================================================")
  println("  MoonSCTP: Pure MoonBit Sans-I/O RFC 9260 SCTP + RFC 3758 PR-SCTP")
  println("==================================================================")

  // [1/5] Cryptographic & RFC 9260/4231/1982 Self-Check
  println(
    "\n[1/5] RFC 9260 Appendix B CRC-32C + RFC 4231 HMAC Cookie + RFC 1982 TSN Wrap",
  )
  let crc_check = @crc32c.crc32c(b"123456789")
  let crc_zeros = @sctp.crc32c(Bytes::make(32, b'\x00'))
  if crc_check != 0xE3069283U || crc_zeros != 0x8A9136AAU {
    abort("CRC-32C self-check failed")
  }
  let secret = b"moonsctp-demo-hmac-secret-32byte!"
  let sample_cookie : @cookie.CookiePayload = {
    local_vtag: 0xAABBCCDDU,
    peer_vtag: 0x11223344U,
    local_tsn: 0xFFFFFFFCU,
    peer_tsn: 0xFFFFFFFEU,
    out_streams: 4U,
    in_streams: 4U,
    peer_arwnd: 65536U,
    created_ms: 1000UL,
  }
  let cookie_wire = @sctp.seal_cookie(secret, sample_cookie)
  let opened = @sctp.open_cookie(secret, cookie_wire, 2000UL, 60000UL)
  let wrap_ok = @packet.tsn_lt(0xFFFFFFFFU, 0x00000000U) &&
    @packet.tsn_diff(0x00000002U, 0xFFFFFFFEU) == 4
  if opened != sample_cookie || !wrap_ok {
    abort("Cookie or RFC 1982 wrap self-check failed")
  }
  println(
    "  PASS: CRC32C(\"123456789\")=" +
    u32_hex(crc_check) +
    ", CRC32C(0x00*32)=" +
    u32_hex(crc_zeros),
  )
  println(
    "  PASS: 64B HMAC-SHA256 Cookie verified (" +
    cookie_wire.length().to_string() +
    "B), RFC 1982 TSN wrap (0xFFFFFFFF < 0x00000000) OK",
  )

  // [2/5] Stateless Anti-SYN-Flood 4-Way Cookie Handshake + Heartbeat
  println(
    "\n[2/5] Stateless 4-Way Cookie Handshake (Anti-SYN-Flood) + HEARTBEAT",
  )
  let c_cfg = @sctp.client_config(
    5000U,
    5001U,
    0x11223344U,
    1000U,
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )
  let s_cfg = @sctp.server_config(
    5001U,
    5000U,
    0xAABBCCDDU,
    2000U,
    secret,
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )
  let client = @sctp.new_client(c_cfg)
  let init_pkts = client.connect(0UL)
  let init_ack = @sctp.process_stateless_init(s_cfg, init_pkts[0][:], 5UL)
  let _ = client.handle_packet(init_ack[:], 10UL)
  let ce_pkts = client.poll_outbound()
  // Server allocates Association memory ONLY after valid COOKIE_ECHO!
  let server = @sctp.new_server(s_cfg)
  let _ = server.handle_packet(ce_pkts[0][:], 15UL)
  let ca_pkts = server.poll_outbound()
  let _ = client.handle_packet(ca_pkts[0][:], 20UL)

  client.send_heartbeat(b"live-probe-2026", 30UL)
  let hb = client.poll_outbound()
  let _ = server.handle_packet(hb[0][:], 35UL)
  let hb_ack = server.poll_outbound()
  let hb_evs = client.handle_packet(hb_ack[0][:], 40UL)
  if hb_evs != [@assoc.Event::HeartbeatAcked(b"live-probe-2026")] {
    abort("Heartbeat roundtrip failed")
  }
  println(
    "  PASS: INIT(" +
    init_pkts[0].length().to_string() +
    "B) -> Stateless INIT_ACK(" +
    init_ack.length().to_string() +
    "B) -> COOKIE_ECHO(" +
    ce_pkts[0].length().to_string() +
    "B) -> COOKIE_ACK -> Established",
  )
  println("  PASS: HEARTBEAT / HEARTBEAT_ACK roundtrip verified")

  // [3/5] Multi-Stream HOL-Blocking Elimination Proof
  println("\n[3/5] Multi-Stream HOL-Blocking Elimination Live Comparison")
  client.send(b"stream0-blocked-msg", @sctp.reliable_opts(0U, ppid=1U), 100UL)
  let _dropped_s0 = client.poll_outbound()
  client.send(b"stream1-fast-1", @sctp.reliable_opts(1U, ppid=2U), 105UL)
  client.send(b"stream1-fast-2", @sctp.reliable_opts(1U, ppid=2U), 110UL)
  client.send(b"stream1-fast-3", @sctp.reliable_opts(1U, ppid=2U), 115UL)
  let s1_pkts = client.poll_outbound()
  let mut s1_immediate = 0
  for i = 0; i < s1_pkts.length(); i = i + 1 {
    let evs = server.handle_packet(s1_pkts[i][:], 120UL + i.to_uint64())
    for j = 0; j < evs.length(); j = j + 1 {
      match evs[j] {
        @assoc.Event::Message(m) =>
          if m.stream_id == 1U {
            s1_immediate = s1_immediate + 1
          }
        _ => ()
      }
    }
  }
  let s_sacks = server.poll_outbound()
  for i = 0; i < s_sacks.length(); i = i + 1 {
    let _ = client.handle_packet(s_sacks[i][:], 140UL + i.to_uint64())
  }
  let rtx = client.poll_outbound()
  let mut s0_recovered = 0
  for i = 0; i < rtx.length(); i = i + 1 {
    let evs = server.handle_packet(rtx[i][:], 160UL + i.to_uint64())
    for j = 0; j < evs.length(); j = j + 1 {
      match evs[j] {
        @assoc.Event::Message(m) =>
          if m.stream_id == 0U {
            s0_recovered = s0_recovered + 1
          }
        _ => ()
      }
    }
  }
  let flush_sacks = server.poll_outbound()
  for i = 0; i < flush_sacks.length(); i = i + 1 {
    let _ = client.handle_packet(flush_sacks[i][:], 170UL)
  }
  if s1_immediate != 3 || s0_recovered != 1 {
    abort("HOL-blocking demo failed")
  }
  println(
    "  PASS: Stream 0 packet #1 dropped -> Stream 1 delivered " +
    s1_immediate.to_string() +
    "/3 messages IMMEDIATELY (0ms cross-stream HOL stall!)",
  )
  println(
    "  PASS: 3-SACK fast retransmit recovered Stream 0 (" +
    s0_recovered.to_string() +
    "/1 delivered, retransmissions=" +
    client.stats().retransmissions.to_string() +
    ")",
  )

  // [4/5] 15% Loss + Reordering + Duplication Chaos Simulation & PR-SCTP FORWARD_TSN
  println(
    "\n[4/5] 15% Loss + Reorder + Dup Chaos Simulation & RFC 3758 PR-SCTP Skip",
  )
  let c2 = @sctp.new_client(c_cfg)
  let s2 = @sctp.new_server(s_cfg)
  let _ = @sctp.run_handshake_loop(c2, s2, 0UL)
  let net = CliChaosNet::new(0x13579BDFU, 15, 10)
  let expected : Array[Array[Bytes]] = [[], [], [], []]
  let total_msgs = 20
  let mut now_ms = 200UL
  for i = 0; i < total_msgs; i = i + 1 {
    let sid = i % 4
    let sz = if i % 4 == 0 { 3200 + i * 23 } else { 350 + i * 31 }
    let p = make_payload(i + 1, sz)
    expected[sid].push(p)
    c2.send(
      p,
      @sctp.reliable_opts(
        sid.reinterpret_as_uint(),
        ppid=i.reinterpret_as_uint(),
      ),
      now_ms,
    )
    net.push_all(c2.poll_outbound(), true, now_ms)
  }
  let delivered : Array[@assoc.DeliveredMessage] = []
  let mut steps = 0
  while delivered.length() < total_msgs && steps < 4000 {
    now_ms = now_ms + 25UL
    steps = steps + 1
    let due : Array[SimPkt] = []
    let keep : Array[SimPkt] = []
    for i = 0; i < net.queue.length(); i = i + 1 {
      if net.queue[i].deliver_at_ms <= now_ms {
        due.push(net.queue[i])
      } else {
        keep.push(net.queue[i])
      }
    }
    net.queue.clear()
    for i = 0; i < keep.length(); i = i + 1 {
      net.queue.push(keep[i])
    }
    for i = 0; i < due.length(); i = i + 1 {
      if due[i].to_server {
        let evs = s2.handle_packet(due[i].raw[:], now_ms)
        for j = 0; j < evs.length(); j = j + 1 {
          match evs[j] {
            @assoc.Event::Message(m) => delivered.push(m)
            _ => ()
          }
        }
        net.push_all(s2.poll_outbound(), false, now_ms)
      } else {
        let _ = c2.handle_packet(due[i].raw[:], now_ms)
        net.push_all(c2.poll_outbound(), true, now_ms)
      }
    }
    let _ = c2.tick(now_ms)
    net.push_all(c2.poll_outbound(), true, now_ms)
    let _ = s2.tick(now_ms)
    net.push_all(s2.poll_outbound(), false, now_ms)
  }
  if delivered.length() != total_msgs {
    abort("Chaos simulation did not converge")
  }
  println(
    "  PASS: Chaos Link (sent=" +
    net.sent.to_string() +
    ", dropped=" +
    net.dropped.to_string() +
    ", duped=" +
    net.duped.to_string() +
    ", rtx=" +
    c2.stats().retransmissions.to_string() +
    ") -> 20/20 multi-fragment messages 100% lossless!",
  )

  // PR-SCTP MaxRetransmits(1) skip drill
  let c3 = @sctp.new_client(c_cfg)
  let s3 = @sctp.new_server(s_cfg)
  let _ = @sctp.run_handshake_loop(c3, s3, 0UL)
  c3.send(b"skip-me-frame", @sctp.partial_retransmit_opts(0U, 1), 100UL)
  let _drop1 = c3.poll_outbound()
  c3.send(b"keep-me-keyframe", @sctp.reliable_opts(0U), 120UL)
  let keep_pkt = c3.poll_outbound()
  let _ = s3.handle_packet(keep_pkt[0][:], 130UL)
  let sk = s3.poll_outbound()
  for i = 0; i < sk.length(); i = i + 1 {
    let _ = c3.handle_packet(sk[i][:], 140UL)
  }
  let _ = c3.tick(1200UL)
  let _drop2 = c3.poll_outbound()
  let _ = c3.tick(3500UL)
  let ftsn_pkts = c3.poll_outbound()
  let mut unblocked = false
  for i = 0; i < ftsn_pkts.length(); i = i + 1 {
    let evs = s3.handle_packet(ftsn_pkts[i][:], 3520UL)
    for j = 0; j < evs.length(); j = j + 1 {
      match evs[j] {
        @assoc.Event::Message(m) =>
          if m.payload == b"keep-me-keyframe" {
            unblocked = true
          }
        _ => ()
      }
    }
  }
  if !unblocked || c3.stats().forward_tsn_sent == 0 {
    abort("PR-SCTP FORWARD_TSN skip demo failed")
  }
  println(
    "  PASS: RFC 3758 PR-SCTP MaxRetransmits(1) emitted FORWARD_TSN (count=" +
    c3.stats().forward_tsn_sent.to_string() +
    ") and immediately unblocked reliable follow-up",
  )

  // [5/5] Live Adversarial Security Drills
  println("\n[5/5] Live Adversarial Security Drills")
  // 5a. Single-bit CRC-32C tamper
  client.send(b"integrity-test", @sctp.reliable_opts(0U), 500UL)
  let good_pkt = client.poll_outbound()[0]
  let bad_crc_pkt = flip_bit(good_pkt, good_pkt.length() - 1)
  let mut crc_blocked = false
  try {
    let _ = server.handle_packet(bad_crc_pkt[:], 510UL)
  } catch {
    @assoc.SecurityViolation(_) => crc_blocked = true
    _ => ()
  }
  // 5b. Single-bit tampered HMAC Cookie
  let bad_cookie = flip_bit(cookie_wire, 12)
  let bad_ce = @sctp.encode_packet({
    src_port: c_cfg.local_port,
    dst_port: s_cfg.local_port,
    verification_tag: s_cfg.local_vtag,
    chunks: [@packet.Chunk::CookieEcho(bad_cookie)],
  })
  let fresh_srv = @sctp.new_server(s_cfg)
  let mut cookie_blocked = false
  try {
    let _ = fresh_srv.handle_packet(bad_ce[:], 520UL)
  } catch {
    @assoc.SecurityViolation(_) => cookie_blocked = true
    _ => ()
  }
  // 5c. Forged ABORT with wrong Verification Tag silently ignored
  let forged_abort = @sctp.encode_packet({
    src_port: c_cfg.local_port,
    dst_port: s_cfg.local_port,
    verification_tag: 0xBAD0BEEFU,
    chunks: [@packet.Chunk::Abort(false, [{ code: 12U, info: b"spoof", }])],
  })
  let abort_evs = server.handle_packet(forged_abort[:], 530UL)
  let abort_ignored = abort_evs.length() == 0 &&
    server.state() == @assoc.AssocState::Established

  if !crc_blocked || !cookie_blocked || !abort_ignored {
    abort("Adversarial security drill failed")
  }
  println("  PASS: Single-bit CRC-32C tamper -> rejected (SecurityViolation)")
  println(
    "  PASS: Single-bit HMAC Cookie tamper -> rejected (SecurityViolation)",
  )
  println(
    "  PASS: Forged ABORT (wrong VTag) -> silently ignored (state stays Established)",
  )
  println("\nAll 5 stages completed cleanly!")
}

///|
fn main {
  run_demo() catch {
    err => abort("MoonSCTP CLI demo failed: " + err.to_string())
  }
}
