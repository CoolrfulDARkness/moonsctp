///|
fn flip_byte_at(b : Bytes, idx : Int32) -> Bytes {
  let out : FixedArray[Byte] = FixedArray::make(b.length(), b'\x00')
  for i = 0; i < b.length(); i = i + 1 {
    out[i] = if i == idx { (b[i].to_int() ^ 0x01).to_byte() } else { b[i] }
  }
  Bytes::from_array(out)
}

///|
fn adv_configs() -> (@association.Config, @association.Config) {
  let secret = b"adversarial-server-hmac-secret-32"
  let client_cfg = @association.Config::default_client(
    4000U,
    4001U,
    0x12345678U,
    1000U,
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )
  let server_cfg = @association.Config::default_server(
    4001U,
    4000U,
    0x87654321U,
    2000U,
    secret,
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )
  (client_cfg, server_cfg)
}

///|
fn adv_establish() -> (
  @association.Association,
  @association.Association,
  @association.Config,
  @association.Config,
) raise @association.AssocError {
  let (c_cfg, s_cfg) = adv_configs()
  let client = @association.Association::new_client(c_cfg)
  let init_pkts = client.connect(0UL)
  let init_ack = @association.Association::process_stateless_init(
    s_cfg,
    init_pkts[0][:],
    10UL,
  )
  let _ = client.handle_packet(init_ack[:], 20UL)
  let ce = client.poll_outbound()
  let server = @association.Association::new_server(s_cfg)
  let _ = server.handle_packet(ce[0][:], 30UL)
  let ca = server.poll_outbound()
  let _ = client.handle_packet(ca[0][:], 40UL)
  (client, server, c_cfg, s_cfg)
}

///|
fn encode_raw(pkt : @packet.Packet) -> Bytes {
  @packet.encode_packet(pkt) catch {
    _ => abort("unexpected encode failure in test")
  }
}

///|
test "adv 01: corrupted CRC-32C single bit flip rejected with SecurityViolation" {
  let (client, server, _, _) = adv_establish()
  client.send(
    b"protected-payload",
    @association.SendOptions::reliable(0U),
    100UL,
  )
  let pkts = client.poll_outbound()
  let tampered = flip_byte_at(pkts[0], pkts[0].length() - 1)
  let mut caught = false
  try {
    let _ = server.handle_packet(tampered[:], 110UL)
  } catch {
    @association.SecurityViolation(_) => caught = true
    _ => ()
  }
  assert_true(caught)
}

///|
test "adv 02: spoofed non-zero Verification Tag on DATA rejected" {
  let (_, server, c_cfg, s_cfg) = adv_establish()
  let forged = encode_raw({
    src_port: c_cfg.local_port,
    dst_port: s_cfg.local_port,
    verification_tag: 0xDEAD0001U,
    chunks: [
      @packet.Chunk::Data({
        tsn: 1000U,
        stream_id: 0U,
        stream_seq: 0U,
        ppid: 0U,
        unordered: false,
        beginning: true,
        ending: true,
        payload: b"spoofed",
      }),
    ],
  })
  let mut caught = false
  try {
    let _ = server.handle_packet(forged[:], 100UL)
  } catch {
    @association.SecurityViolation(_) => caught = true
    _ => ()
  }
  assert_true(caught)
}

///|
test "adv 03: zero Verification Tag on DATA rejected" {
  let (_, server, c_cfg, s_cfg) = adv_establish()
  let forged = encode_raw({
    src_port: c_cfg.local_port,
    dst_port: s_cfg.local_port,
    verification_tag: 0U,
    chunks: [
      @packet.Chunk::Data({
        tsn: 1000U,
        stream_id: 0U,
        stream_seq: 0U,
        ppid: 0U,
        unordered: false,
        beginning: true,
        ending: true,
        payload: b"zero-vtag-data",
      }),
    ],
  })
  let mut caught = false
  try {
    let _ = server.handle_packet(forged[:], 100UL)
  } catch {
    @association.SecurityViolation(_) => caught = true
    _ => ()
  }
  assert_true(caught)
}

///|
test "adv 04: zero Verification Tag on SACK rejected" {
  let (client, _, c_cfg, s_cfg) = adv_establish()
  let forged = encode_raw({
    src_port: s_cfg.local_port,
    dst_port: c_cfg.local_port,
    verification_tag: 0U,
    chunks: [
      @packet.Chunk::Sack({
        cum_tsn_ack: 1000U,
        a_rwnd: 65536U,
        gap_blocks: [],
        dup_tsns: [],
      }),
    ],
  })
  let mut caught = false
  try {
    let _ = client.handle_packet(forged[:], 100UL)
  } catch {
    @association.SecurityViolation(_) => caught = true
    _ => ()
  }
  assert_true(caught)
}

///|
test "adv 05: zero Verification Tag on SHUTDOWN rejected" {
  let (_, server, c_cfg, s_cfg) = adv_establish()
  let forged = encode_raw({
    src_port: c_cfg.local_port,
    dst_port: s_cfg.local_port,
    verification_tag: 0U,
    chunks: [@packet.Chunk::Shutdown(1999U)],
  })
  let mut caught = false
  try {
    let _ = server.handle_packet(forged[:], 100UL)
  } catch {
    @association.SecurityViolation(_) => caught = true
    _ => ()
  }
  assert_true(caught)
}

///|
test "adv 06: single-bit tampered HMAC State Cookie rejected" {
  let (c_cfg, s_cfg) = adv_configs()
  let client = @association.Association::new_client(c_cfg)
  let init_pkts = client.connect(0UL)
  let init_ack = @association.Association::process_stateless_init(
    s_cfg,
    init_pkts[0][:],
    10UL,
  )
  let ack_pkt = @packet.decode_packet(init_ack[:]) catch {
    _ => abort("decode init_ack failed")
  }
  let valid_cookie = match ack_pkt.chunks[0] {
    @packet.Chunk::InitAck(ia) => ia.state_cookie
    _ => abort("expected InitAck")
  }
  let bad_cookie = flip_byte_at(valid_cookie, 10)
  let ce_forged = encode_raw({
    src_port: c_cfg.local_port,
    dst_port: s_cfg.local_port,
    verification_tag: s_cfg.local_vtag,
    chunks: [@packet.Chunk::CookieEcho(bad_cookie)],
  })
  let server = @association.Association::new_server(s_cfg)
  let mut caught = false
  try {
    let _ = server.handle_packet(ce_forged[:], 20UL)
  } catch {
    @association.SecurityViolation(_) => caught = true
    _ => ()
  }
  assert_true(caught)
  assert_eq(server.state(), @association.AssocState::Closed)
}

///|
test "adv 07: expired State Cookie rejected" {
  let (c_cfg, s_cfg) = adv_configs()
  let client = @association.Association::new_client(c_cfg)
  let init_pkts = client.connect(100UL)
  let init_ack = @association.Association::process_stateless_init(
    s_cfg,
    init_pkts[0][:],
    100UL,
  )
  let _ = client.handle_packet(init_ack[:], 110UL)
  let ce = client.poll_outbound()

  let server = @association.Association::new_server(s_cfg)
  let mut caught = false
  try {
    let _ = server.handle_packet(
      ce[0][:],
      100UL + s_cfg.cookie_lifetime_ms + 1UL,
    )
  } catch {
    @association.SecurityViolation(_) => caught = true
    _ => ()
  }
  assert_true(caught)
  assert_eq(server.state(), @association.AssocState::Closed)
}

///|
test "adv 08: cookie signed with wrong server secret rejected" {
  let (c_cfg, s_cfg) = adv_configs()
  let rogue_cfg = @association.Config::default_server(
    s_cfg.local_port,
    s_cfg.remote_port,
    s_cfg.local_vtag,
    s_cfg.initial_tsn,
    b"wrong-attacker-secret-key-000000!",
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )
  let client = @association.Association::new_client(c_cfg)
  let init_pkts = client.connect(0UL)
  let rogue_ack = @association.Association::process_stateless_init(
    rogue_cfg,
    init_pkts[0][:],
    10UL,
  )
  let _ = client.handle_packet(rogue_ack[:], 20UL)
  let ce = client.poll_outbound()

  let real_server = @association.Association::new_server(s_cfg)
  let mut caught = false
  try {
    let _ = real_server.handle_packet(ce[0][:], 30UL)
  } catch {
    @association.SecurityViolation(_) => caught = true
    _ => ()
  }
  assert_true(caught)
}

///|
test "adv 09: replayed valid State Cookie rejected" {
  let (c_cfg, s_cfg) = adv_configs()
  let client = @association.Association::new_client(c_cfg)
  let init_pkts = client.connect(0UL)
  let init_ack = @association.Association::process_stateless_init(
    s_cfg,
    init_pkts[0][:],
    10UL,
  )
  let _ = client.handle_packet(init_ack[:], 20UL)
  let ce = client.poll_outbound()

  let server = @association.Association::new_server(s_cfg)
  let ev1 = server.handle_packet(ce[0][:], 30UL)
  assert_eq(ev1, [@association.Event::Connected])

  // Replay the exact same COOKIE_ECHO
  let mut caught = false
  try {
    let _ = server.handle_packet(ce[0][:], 40UL)
  } catch {
    @association.SecurityViolation(_) => caught = true
    _ => ()
  }
  assert_true(caught)
}

///|
test "adv 10: stateless SYN flood defense handles 100 forged INITs with zero session allocation" {
  let (_, s_cfg) = adv_configs()
  for i = 0; i < 100; i = i + 1 {
    let forged_init = encode_raw({
      src_port: (10000 + i).reinterpret_as_uint(),
      dst_port: s_cfg.local_port,
      verification_tag: 0U,
      chunks: [
        @packet.Chunk::Init({
          initiate_tag: (0x50000000 + i + 1).reinterpret_as_uint(),
          a_rwnd: 65536U,
          num_outbound_streams: 4U,
          num_inbound_streams: 4U,
          initial_tsn: (i * 100).reinterpret_as_uint(),
          forward_tsn_supported: true,
        }),
      ],
    })
    let ack_bytes = @association.Association::process_stateless_init(
      s_cfg,
      forged_init[:],
      i.to_uint64(),
    )
    let ack = @packet.decode_packet(ack_bytes[:]) catch {
      _ => abort("stateless init_ack decode failed")
    }
    assert_eq(ack.verification_tag, (0x50000000 + i + 1).reinterpret_as_uint())
    match ack.chunks[0] {
      @packet.Chunk::InitAck(ia) =>
        assert_eq(ia.state_cookie.length(), @cookie.COOKIE_WIRE_LEN)
      _ => abort("expected InitAck")
    }
  }
}

///|
test "adv 11: INIT with zero initiate_tag rejected" {
  let (_, s_cfg) = adv_configs()
  let bad_init = encode_raw({
    src_port: 4000U,
    dst_port: s_cfg.local_port,
    verification_tag: 0U,
    chunks: [
      @packet.Chunk::Init({
        initiate_tag: 0U,
        a_rwnd: 65536U,
        num_outbound_streams: 4U,
        num_inbound_streams: 4U,
        initial_tsn: 1U,
        forward_tsn_supported: true,
      }),
    ],
  })
  let mut caught = false
  try {
    let _ = @association.Association::process_stateless_init(
      s_cfg,
      bad_init[:],
      0UL,
    )
  } catch {
    @association.SecurityViolation(_) | @association.PacketError(_) =>
      caught = true
    _ => ()
  }
  assert_true(caught)
}

///|
test "adv 12: INIT with zero stream counts rejected" {
  let (_, s_cfg) = adv_configs()
  let bad_init = encode_raw({
    src_port: 4000U,
    dst_port: s_cfg.local_port,
    verification_tag: 0U,
    chunks: [
      @packet.Chunk::Init({
        initiate_tag: 0x11112222U,
        a_rwnd: 65536U,
        num_outbound_streams: 0U,
        num_inbound_streams: 4U,
        initial_tsn: 1U,
        forward_tsn_supported: true,
      }),
    ],
  })
  let mut caught = false
  try {
    let _ = @association.Association::process_stateless_init(
      s_cfg,
      bad_init[:],
      0UL,
    )
  } catch {
    @association.SecurityViolation(_) | @association.PacketError(_) =>
      caught = true
    _ => ()
  }
  assert_true(caught)
}

///|
test "adv 13: INIT with non-zero Verification Tag rejected" {
  let (_, s_cfg) = adv_configs()
  let bad_init = encode_raw({
    src_port: 4000U,
    dst_port: s_cfg.local_port,
    verification_tag: 0x12345678U,
    chunks: [
      @packet.Chunk::Init({
        initiate_tag: 0x11112222U,
        a_rwnd: 65536U,
        num_outbound_streams: 4U,
        num_inbound_streams: 4U,
        initial_tsn: 1U,
        forward_tsn_supported: true,
      }),
    ],
  })
  let mut caught = false
  try {
    let _ = @association.Association::process_stateless_init(
      s_cfg,
      bad_init[:],
      0UL,
    )
  } catch {
    @association.SecurityViolation(_) => caught = true
    _ => ()
  }
  assert_true(caught)
}

///|
test "adv 14: premature DATA injected before handshake rejected" {
  let (c_cfg, s_cfg) = adv_configs()
  let server = @association.Association::new_server(s_cfg)
  let early_data = encode_raw({
    src_port: c_cfg.local_port,
    dst_port: s_cfg.local_port,
    verification_tag: s_cfg.local_vtag,
    chunks: [
      @packet.Chunk::Data({
        tsn: 1000U,
        stream_id: 0U,
        stream_seq: 0U,
        ppid: 0U,
        unordered: false,
        beginning: true,
        ending: true,
        payload: b"early-data",
      }),
    ],
  })
  let mut caught = false
  try {
    let _ = server.handle_packet(early_data[:], 10UL)
  } catch {
    @association.SecurityViolation(_) => caught = true
    _ => ()
  }
  assert_true(caught)
}

///|
test "adv 15: premature COOKIE_ACK injected in CookieWait rejected" {
  let (c_cfg, s_cfg) = adv_configs()
  let client = @association.Association::new_client(c_cfg)
  let _ = client.connect(0UL)
  assert_eq(client.state(), @association.AssocState::CookieWait)
  let early_ca = encode_raw({
    src_port: s_cfg.local_port,
    dst_port: c_cfg.local_port,
    verification_tag: c_cfg.local_vtag,
    chunks: [@packet.Chunk::CookieAck],
  })
  let mut caught = false
  try {
    let _ = client.handle_packet(early_ca[:], 10UL)
  } catch {
    @association.SecurityViolation(_) => caught = true
    _ => ()
  }
  assert_true(caught)
  assert_eq(client.state(), @association.AssocState::CookieWait)
}

///|
test "adv 16: premature SHUTDOWN injected before Established rejected" {
  let (c_cfg, s_cfg) = adv_configs()
  let client = @association.Association::new_client(c_cfg)
  let _ = client.connect(0UL)
  let early_sd = encode_raw({
    src_port: s_cfg.local_port,
    dst_port: c_cfg.local_port,
    verification_tag: c_cfg.local_vtag,
    chunks: [@packet.Chunk::Shutdown(0U)],
  })
  let mut caught = false
  try {
    let _ = client.handle_packet(early_sd[:], 10UL)
  } catch {
    @association.SecurityViolation(_) => caught = true
    _ => ()
  }
  assert_true(caught)
  assert_eq(client.state(), @association.AssocState::CookieWait)
}

///|
test "adv 17: forged ABORT with wrong Verification Tag silently ignored" {
  let (client, server, c_cfg, s_cfg) = adv_establish()
  let forged_abort = encode_raw({
    src_port: c_cfg.local_port,
    dst_port: s_cfg.local_port,
    verification_tag: 0xBAD0F00DU,
    chunks: [@packet.Chunk::Abort(false, [{ code: 12U, info: b"hijack", }])],
  })
  let evs = server.handle_packet(forged_abort[:], 100UL)
  assert_eq(evs.length(), 0)
  assert_eq(server.state(), @association.AssocState::Established)

  // Verify association still functions normally after ignored spoofed ABORT
  client.send(b"still-alive", @association.SendOptions::reliable(0U), 110UL)
  let pkts = client.poll_outbound()
  let ev2 = server.handle_packet(pkts[0][:], 120UL)
  assert_eq(ev2.length(), 1)
}

///|
test "adv 18: valid ABORT with matching Verification Tag closes association" {
  let (client, server, _, _) = adv_establish()
  client.abort(b"fatal-app-error")
  assert_eq(client.state(), @association.AssocState::Closed)
  let abort_pkts = client.poll_outbound()
  assert_eq(abort_pkts.length(), 1)

  let evs = server.handle_packet(abort_pkts[0][:], 100UL)
  assert_eq(evs, [@association.Event::Aborted("fatal-app-error")])
  assert_eq(server.state(), @association.AssocState::Closed)
}

///|
test "adv 19: anti-OOM max_message_size enforced on both send and fragmented receive" {
  let (c_cfg, s_cfg) = adv_configs()
  let small_c_cfg : @association.Config = {
    ..c_cfg,
    max_payload_size: 256,
    max_message_size: 512,
  }
  let small_s_cfg : @association.Config = {
    ..s_cfg,
    max_payload_size: 256,
    max_message_size: 512,
  }
  let client = @association.Association::new_client(small_c_cfg)
  let init_pkts = client.connect(0UL)
  let init_ack = @association.Association::process_stateless_init(
    small_s_cfg,
    init_pkts[0][:],
    10UL,
  )
  let _ = client.handle_packet(init_ack[:], 20UL)
  let ce = client.poll_outbound()
  let server = @association.Association::new_server(small_s_cfg)
  let _ = server.handle_packet(ce[0][:], 30UL)
  let ca = server.poll_outbound()
  let _ = client.handle_packet(ca[0][:], 40UL)

  // 1. Oversized send rejected with MessageTooLarge
  let oversized_send = Bytes::make(513, b'\x41')
  let mut send_caught = false
  client.send(oversized_send, @association.SendOptions::reliable(0U), 100UL) catch {
    @association.MessageTooLarge(513) => send_caught = true
    _ => ()
  }
  assert_true(send_caught)

  // 2. Fragmented reassembly OOM attack (3 x 200B = 600B > 512B) rejected on receive!
  let frag_payload = Bytes::make(200, b'\x42')
  let p1 = encode_raw({
    src_port: small_c_cfg.local_port,
    dst_port: small_s_cfg.local_port,
    verification_tag: small_s_cfg.local_vtag,
    chunks: [
      @packet.Chunk::Data({
        tsn: 1000U,
        stream_id: 0U,
        stream_seq: 0U,
        ppid: 0U,
        unordered: false,
        beginning: true,
        ending: false,
        payload: frag_payload,
      }),
    ],
  })
  let p2 = encode_raw({
    src_port: small_c_cfg.local_port,
    dst_port: small_s_cfg.local_port,
    verification_tag: small_s_cfg.local_vtag,
    chunks: [
      @packet.Chunk::Data({
        tsn: 1001U,
        stream_id: 0U,
        stream_seq: 0U,
        ppid: 0U,
        unordered: false,
        beginning: false,
        ending: false,
        payload: frag_payload,
      }),
    ],
  })
  let p3 = encode_raw({
    src_port: small_c_cfg.local_port,
    dst_port: small_s_cfg.local_port,
    verification_tag: small_s_cfg.local_vtag,
    chunks: [
      @packet.Chunk::Data({
        tsn: 1002U,
        stream_id: 0U,
        stream_seq: 0U,
        ppid: 0U,
        unordered: false,
        beginning: false,
        ending: true,
        payload: frag_payload,
      }),
    ],
  })
  let _ = server.handle_packet(p1[:], 110UL)
  let _ = server.handle_packet(p2[:], 120UL)
  let mut recv_oom_caught = false
  try {
    let _ = server.handle_packet(p3[:], 130UL)
  } catch {
    @association.MessageTooLarge(600) => recv_oom_caught = true
    _ => ()
  }
  assert_true(recv_oom_caught)
}

///|
test "adv 20: unknown critical chunk type rejected with PacketError" {
  let (_, server, c_cfg, s_cfg) = adv_establish()
  // Hand-craft packet with chunk type 0x20 (top 2 bits = 00 -> stop/critical) and valid CRC-32C
  let buf : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  buf[0] = ((c_cfg.local_port >> 8) & 0xFFU).to_byte()
  buf[1] = (c_cfg.local_port & 0xFFU).to_byte()
  buf[2] = ((s_cfg.local_port >> 8) & 0xFFU).to_byte()
  buf[3] = (s_cfg.local_port & 0xFFU).to_byte()
  buf[4] = ((s_cfg.local_vtag >> 24) & 0xFFU).to_byte()
  buf[5] = ((s_cfg.local_vtag >> 16) & 0xFFU).to_byte()
  buf[6] = ((s_cfg.local_vtag >> 8) & 0xFFU).to_byte()
  buf[7] = (s_cfg.local_vtag & 0xFFU).to_byte()
  buf[12] = b'\x20'
  buf[13] = b'\x00'
  buf[14] = b'\x00'
  buf[15] = b'\x04'
  let pre = Bytes::from_array(buf)
  let crc = @crc32c.sctp_packet_checksum(pre[:])
  buf[8] = (crc & 0xFFU).to_byte()
  buf[9] = ((crc >> 8) & 0xFFU).to_byte()
  buf[10] = ((crc >> 16) & 0xFFU).to_byte()
  buf[11] = ((crc >> 24) & 0xFFU).to_byte()
  let wire = Bytes::from_array(buf)

  let mut caught = false
  try {
    let _ = server.handle_packet(wire[:], 100UL)
  } catch {
    @association.PacketError(_) => caught = true
    _ => ()
  }
  assert_true(caught)
}

///|
test "adv 21: out-of-range Stream ID rejected on both send and receive" {
  let (client, server, c_cfg, s_cfg) = adv_establish()
  let mut send_err = false
  client.send(b"bad-stream", @association.SendOptions::reliable(4U), 100UL) catch {
    @association.InvalidStream(4U) => send_err = true
    _ => ()
  }
  assert_true(send_err)

  let bad_rx = encode_raw({
    src_port: c_cfg.local_port,
    dst_port: s_cfg.local_port,
    verification_tag: s_cfg.local_vtag,
    chunks: [
      @packet.Chunk::Data({
        tsn: 1000U,
        stream_id: 99U,
        stream_seq: 0U,
        ppid: 0U,
        unordered: false,
        beginning: true,
        ending: true,
        payload: b"oob-stream",
      }),
    ],
  })
  let mut rx_err = false
  try {
    let _ = server.handle_packet(bad_rx[:], 110UL)
  } catch {
    @association.InvalidStream(99U) => rx_err = true
    _ => ()
  }
  assert_true(rx_err)
}

///|
test "adv 22: duplicate TSN reported in SACK dup_tsns and never delivered twice" {
  let (client, server, _, _) = adv_establish()
  client.send(b"deliver-once", @association.SendOptions::reliable(0U), 100UL)
  let pkts = client.poll_outbound()

  let ev1 = server.handle_packet(pkts[0][:], 110UL)
  assert_eq(ev1.length(), 1)
  let _ = server.poll_outbound()

  // Replay exact same DATA packet
  let ev2 = server.handle_packet(pkts[0][:], 120UL)
  assert_eq(ev2.length(), 0)
  let sacks = server.poll_outbound()
  assert_eq(sacks.length(), 1)
  let sack_pkt = @packet.decode_packet(sacks[0][:]) catch {
    _ => abort("decode sack failed")
  }
  match sack_pkt.chunks[0] {
    @packet.Chunk::Sack(sk) => assert_eq(sk.dup_tsns, [1000U])
    _ => abort("expected SACK chunk")
  }
}

///|
test "adv 23: send rejected after ShutdownSent and Closed states" {
  let (client, _, _, _) = adv_establish()
  client.shutdown(100UL)
  assert_eq(client.state(), @association.AssocState::ShutdownSent)
  let mut sd_err = false
  client.send(b"after-shutdown", @association.SendOptions::reliable(0U), 110UL) catch {
    @association.InvalidState(_) => sd_err = true
    _ => ()
  }
  assert_true(sd_err)

  client.abort(b"close-now")
  assert_eq(client.state(), @association.AssocState::Closed)
  let mut closed_err = false
  client.send(b"after-closed", @association.SendOptions::reliable(0U), 120UL) catch {
    @association.InvalidState(_) => closed_err = true
    _ => ()
  }
  assert_true(closed_err)
}

///|
test "adv 24: truncated packet and malformed chunk length DoS rejected" {
  let (_, server, c_cfg, s_cfg) = adv_establish()

  // 1. Truncated header (< 12 bytes)
  let mut trunc_caught = false
  try {
    let _ = server.handle_packet(b"\x01\x02\x03\x04\x05"[:], 100UL)
  } catch {
    @association.PacketError(_) => trunc_caught = true
    _ => ()
  }
  assert_true(trunc_caught)

  // 2. Malformed chunk length = 2 (< 4) with valid CRC-32C
  let buf : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  buf[0] = ((c_cfg.local_port >> 8) & 0xFFU).to_byte()
  buf[1] = (c_cfg.local_port & 0xFFU).to_byte()
  buf[2] = ((s_cfg.local_port >> 8) & 0xFFU).to_byte()
  buf[3] = (s_cfg.local_port & 0xFFU).to_byte()
  buf[4] = ((s_cfg.local_vtag >> 24) & 0xFFU).to_byte()
  buf[5] = ((s_cfg.local_vtag >> 16) & 0xFFU).to_byte()
  buf[6] = ((s_cfg.local_vtag >> 8) & 0xFFU).to_byte()
  buf[7] = (s_cfg.local_vtag & 0xFFU).to_byte()
  buf[12] = b'\x00'
  buf[13] = b'\x00'
  buf[14] = b'\x00'
  buf[15] = b'\x02' // illegal length < 4
  let pre = Bytes::from_array(buf)
  let crc = @crc32c.sctp_packet_checksum(pre[:])
  buf[8] = (crc & 0xFFU).to_byte()
  buf[9] = ((crc >> 8) & 0xFFU).to_byte()
  buf[10] = ((crc >> 16) & 0xFFU).to_byte()
  buf[11] = ((crc >> 24) & 0xFFU).to_byte()
  let bad_len_pkt = Bytes::from_array(buf)

  let mut len_caught = false
  try {
    let _ = server.handle_packet(bad_len_pkt[:], 110UL)
  } catch {
    @association.PacketError(_) => len_caught = true
    _ => ()
  }
  assert_true(len_caught)
}

///|
test "adv 25: invalid Config parameters rejected with InvalidConfig" {
  let (c_cfg, s_cfg) = adv_configs()

  let mut e1 = false
  try {
    let _ = @association.Association::new_client({ ..c_cfg, local_vtag: 0U, })
  } catch {
    @association.InvalidConfig(_) => e1 = true
    _ => ()
  }
  assert_true(e1)

  let mut e2 = false
  try {
    let _ = @association.Association::new_client({
      ..c_cfg,
      num_outbound_streams: 0U,
    })
  } catch {
    @association.InvalidConfig(_) => e2 = true
    _ => ()
  }
  assert_true(e2)

  let mut e3 = false
  try {
    let _ = @association.Association::new_server({
      ..s_cfg,
      cookie_secret: b"",
    })
  } catch {
    @association.InvalidConfig(_) => e3 = true
    _ => ()
  }
  assert_true(e3)

  let mut e4 = false
  try {
    let _ = @association.Association::new_client({
      ..c_cfg,
      max_payload_size: 8,
    })
  } catch {
    @association.InvalidConfig(_) => e4 = true
    _ => ()
  }
  assert_true(e4)
}
