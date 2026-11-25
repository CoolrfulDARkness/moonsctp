///|
fn make_payload(len : Int32) -> Bytes {
  let buf = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    buf[i] = ((i * 131 + 17) & 0xFF).to_byte()
  }
  Bytes::from_array(buf)
}

///|
fn establish_pair() -> (@assoc.Association, @assoc.Association) {
  let secret = b"bench-sctp-cookie-secret-32bytes"
  let cli_cfg = @assoc.Config::default_client(
    5000U,
    5001U,
    0x11223344U,
    1000U,
    num_outbound_streams=16U,
    num_inbound_streams=16U,
  )
  let srv_cfg = @assoc.Config::default_server(
    5001U,
    5000U,
    0x55667788U,
    2000U,
    secret,
    num_outbound_streams=16U,
    num_inbound_streams=16U,
  )
  let cli = try! @assoc.Association::new_client(cli_cfg)
  let srv = try! @assoc.Association::new_server(srv_cfg)
  let init_pkts = try! cli.connect(1000UL)
  let init_ack = try! @assoc.Association::process_stateless_init(
    srv_cfg,
    init_pkts[0][:],
    1005UL,
  )
  ignore(try! cli.handle_packet(init_ack[:], 1010UL))
  let ce_pkts = cli.poll_outbound()
  ignore(try! srv.handle_packet(ce_pkts[0][:], 1015UL))
  let ca_pkts = srv.poll_outbound()
  ignore(try! cli.handle_packet(ca_pkts[0][:], 1020UL))
  (cli, srv)
}

///|
fn pump_all(
  cli : @assoc.Association,
  srv : @assoc.Association,
  now_ms : UInt64,
) -> Int32 {
  let mut delivered = 0
  let mut t = now_ms
  for round = 0; round < 32; round = round + 1 {
    let out_c = cli.poll_outbound()
    if out_c.length() == 0 {
      break
    }
    for i = 0; i < out_c.length(); i = i + 1 {
      let evs = try! srv.handle_packet(out_c[i][:], t)
      for j = 0; j < evs.length(); j = j + 1 {
        match evs[j] {
          @assoc.Event::Message(_) => delivered = delivered + 1
          _ => ()
        }
      }
    }
    let mut out_s = srv.poll_outbound()
    if out_s.length() == 0 {
      t = t + 250UL
      ignore(srv.tick(t))
      out_s = srv.poll_outbound()
    }
    for i = 0; i < out_s.length(); i = i + 1 {
      ignore(try! cli.handle_packet(out_s[i][:], t))
    }
  }
  delivered
}

///|
test "bench suite sanity" {
  assert_eq(bench_suite_name(), "CoolrfulDARkness/moonsctp")
  let (cli, srv) = establish_pair()
  assert_eq(cli.state(), @assoc.AssocState::Established)
  assert_eq(srv.state(), @assoc.AssocState::Established)
  try! cli.send(make_payload(8192), @assoc.SendOptions::reliable(0U), 2000UL)
  assert_eq(pump_all(cli, srv, 2000UL), 1)
  let msg = make_payload(256)
  let mut total = 0
  let mut now = 5000UL
  for round = 0; round < 4; round = round + 1 {
    for sid = 0; sid < 4; sid = sid + 1 {
      try! cli.send(
        msg,
        @assoc.SendOptions::reliable(sid.reinterpret_as_uint()),
        now,
      )
    }
    total = total + pump_all(cli, srv, now)
    now = now + 1000UL
  }
  assert_eq(total, 16)
}

///|
test "1. Castagnoli CRC-32C 1KB" (b : @bench.T) {
  let data = make_payload(1024)
  b.bench(fn() { b.keep(@crc32c.crc32c(data)) })
}

///|
test "2. Castagnoli CRC-32C 16KB" (b : @bench.T) {
  let data = make_payload(16384)
  b.bench(fn() { b.keep(@crc32c.crc32c(data)) })
}

///|
test "3. HMAC-SHA256 Cookie seal" (b : @bench.T) {
  let secret = b"bench-sctp-cookie-secret-32bytes"
  let payload : @cookie.CookiePayload = {
    local_vtag: 0x55667788U,
    peer_vtag: 0x11223344U,
    local_tsn: 2000U,
    peer_tsn: 1000U,
    out_streams: 16U,
    in_streams: 16U,
    peer_arwnd: 131072U,
    created_ms: 1780272000000UL,
  }
  b.bench(fn() { b.keep(@cookie.seal_cookie(secret, payload)) })
}

///|
test "4. HMAC-SHA256 Cookie open" (b : @bench.T) {
  let secret = b"bench-sctp-cookie-secret-32bytes"
  let payload : @cookie.CookiePayload = {
    local_vtag: 0x55667788U,
    peer_vtag: 0x11223344U,
    local_tsn: 2000U,
    peer_tsn: 1000U,
    out_streams: 16U,
    in_streams: 16U,
    peer_arwnd: 131072U,
    created_ms: 1780272000000UL,
  }
  let cookie_bytes = @cookie.seal_cookie(secret, payload)
  b.bench(fn() {
    b.keep(
      try! @cookie.open_cookie(secret, cookie_bytes, 1780272001000UL, 60000UL),
    )
  })
}

///|
test "5. Packet encode_packet (1KB DATA)" (b : @bench.T) {
  let pkt : @packet.Packet = {
    src_port: 5000U,
    dst_port: 5001U,
    verification_tag: 0x55667788U,
    chunks: [
      @packet.Chunk::Data({
        tsn: 1000U,
        stream_id: 0U,
        stream_seq: 0U,
        ppid: 53U,
        unordered: false,
        beginning: true,
        ending: true,
        payload: make_payload(1024),
      }),
    ],
  }
  b.bench(fn() { b.keep(try! @packet.encode_packet(pkt)) })
}

///|
test "6. Packet decode_packet (1KB DATA + CRC-32C)" (b : @bench.T) {
  let pkt : @packet.Packet = {
    src_port: 5000U,
    dst_port: 5001U,
    verification_tag: 0x55667788U,
    chunks: [
      @packet.Chunk::Data({
        tsn: 1000U,
        stream_id: 0U,
        stream_seq: 0U,
        ppid: 53U,
        unordered: false,
        beginning: true,
        ending: true,
        payload: make_payload(1024),
      }),
    ],
  }
  let wire = try! @packet.encode_packet(pkt)
  b.bench(fn() { b.keep(try! @packet.decode_packet(wire[:])) })
}

///|
test "7. Multi-chunk bundle encode+decode (DATA+SACK+HEARTBEAT)" (b : @bench.T) {
  let pkt : @packet.Packet = {
    src_port: 5000U,
    dst_port: 5001U,
    verification_tag: 0x55667788U,
    chunks: [
      @packet.Chunk::Data({
        tsn: 1042U,
        stream_id: 2U,
        stream_seq: 7U,
        ppid: 51U,
        unordered: false,
        beginning: true,
        ending: true,
        payload: make_payload(513),
      }),
      @packet.Chunk::Sack({
        cum_tsn_ack: 1040U,
        a_rwnd: 65536U,
        gap_blocks: [{ start: 2U, end: 4U, }],
        dup_tsns: [1039U],
      }),
      @packet.Chunk::Heartbeat(b"hb-bench-17bytes!"),
    ],
  }
  b.bench(fn() {
    let wire = try! @packet.encode_packet(pkt)
    b.keep(try! @packet.decode_packet(wire[:]))
  })
}

///|
test "8. Stateless process_stateless_init" (b : @bench.T) {
  let secret = b"bench-sctp-cookie-secret-32bytes"
  let cli_cfg = @assoc.Config::default_client(5000U, 5001U, 0x11223344U, 1000U)
  let srv_cfg = @assoc.Config::default_server(
    5001U, 5000U, 0x55667788U, 2000U, secret,
  )
  let cli = try! @assoc.Association::new_client(cli_cfg)
  let init_wire = (try! cli.connect(1000UL))[0]
  b.bench(fn() {
    b.keep(
      try! @assoc.Association::process_stateless_init(
        srv_cfg,
        init_wire[:],
        1005UL,
      ),
    )
  })
}

///|
test "9. Full 4-Way Cookie handshake end-to-end" (b : @bench.T) {
  let secret = b"bench-sctp-cookie-secret-32bytes"
  let cli_cfg = @assoc.Config::default_client(5000U, 5001U, 0x11223344U, 1000U)
  let srv_cfg = @assoc.Config::default_server(
    5001U, 5000U, 0x55667788U, 2000U, secret,
  )
  b.bench(fn() {
    let cli = try! @assoc.Association::new_client(cli_cfg)
    let srv = try! @assoc.Association::new_server(srv_cfg)
    let init_pkts = try! cli.connect(1000UL)
    let init_ack = try! @assoc.Association::process_stateless_init(
      srv_cfg,
      init_pkts[0][:],
      1005UL,
    )
    ignore(try! cli.handle_packet(init_ack[:], 1010UL))
    let ce = cli.poll_outbound()
    ignore(try! srv.handle_packet(ce[0][:], 1015UL))
    let ca = srv.poll_outbound()
    b.keep(try! cli.handle_packet(ca[0][:], 1020UL))
  })
}

///|
test "10. Single 1KB DATA send + handle_packet + SACK" (b : @bench.T) {
  let (cli, srv) = establish_pair()
  let msg = make_payload(1024)
  let opts = @assoc.SendOptions::reliable(0U)
  let mut now = 2000UL
  b.bench(fn() {
    try! cli.send(msg, opts, now)
    b.keep(pump_all(cli, srv, now))
    now = now + 1000UL
  })
}

///|
test "11. Multi-fragment 8KB message (7 frags) reassembly + delivery" (
  b : @bench.T,
) {
  let (cli, srv) = establish_pair()
  let msg = make_payload(8192)
  let opts = @assoc.SendOptions::reliable(0U)
  let mut now = 2000UL
  b.bench(fn() {
    try! cli.send(msg, opts, now)
    b.keep(pump_all(cli, srv, now))
    now = now + 1000UL
  })
}

///|
test "12. 4 concurrent streams x 4 messages (16 msgs) multi-stream delivery" (
  b : @bench.T,
) {
  let (cli, srv) = establish_pair()
  let msg = make_payload(256)
  let mut now = 2000UL
  b.bench(fn() {
    for round = 0; round < 4; round = round + 1 {
      for sid = 0; sid < 4; sid = sid + 1 {
        try! cli.send(
          msg,
          @assoc.SendOptions::reliable(sid.reinterpret_as_uint()),
          now,
        )
      }
      ignore(pump_all(cli, srv, now))
      now = now + 1000UL
    }
    b.keep(now)
  })
}
