///|
test "facade 1: Castagnoli CRC-32C and packet roundtrip" {
  assert_eq(@moonsctp.crc32c(b"123456789"), 0xE3069283U)
  let pkt : @packet.Packet = {
    src_port: 5000U,
    dst_port: 5001U,
    verification_tag: 0x11223344U,
    chunks: [
      @packet.Chunk::Data({
        tsn: 42U,
        stream_id: 1U,
        stream_seq: 0U,
        ppid: 7U,
        unordered: false,
        beginning: true,
        ending: true,
        payload: b"moonsctp-facade",
      }),
    ],
  }
  let wire = @moonsctp.encode_packet(pkt)
  let decoded = @moonsctp.decode_packet(wire[:])
  assert_eq(decoded, pkt)
}

///|
test "facade 2: run_handshake_loop drives 4-way cookie handshake and bidirectional delivery" {
  let c_cfg = @moonsctp.client_config(
    6000U,
    6001U,
    0x10203040U,
    100U,
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )
  let s_cfg = @moonsctp.server_config(
    6001U,
    6000U,
    0x50607080U,
    200U,
    b"facade-secret-key-0123456789abcdef",
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )
  let client = @moonsctp.new_client(c_cfg)
  let server = @moonsctp.new_server(s_cfg)
  let (c2s, s2c) = @moonsctp.run_handshake_loop(client, server, 1000UL)
  assert_eq(c2s, 2)
  assert_eq(s2c, 2)
  assert_eq(client.state(), @association.AssocState::Established)
  assert_eq(server.state(), @association.AssocState::Established)

  client.send(b"ping", @moonsctp.reliable_opts(0U, ppid=1U), 1100UL)
  let c_pkts = client.poll_outbound()
  let s_evs = server.handle_packet(c_pkts[0][:], 1110UL)
  assert_eq(s_evs, [
    @association.Event::Message({
      stream_id: 0U,
      ppid: 1U,
      unordered: false,
      payload: b"ping",
    }),
  ])

  server.send(b"pong", @moonsctp.unordered_opts(2U, ppid=2U), 1120UL)
  let s_pkts = server.poll_outbound()
  // s_pkts contains SACK + DATA
  let mut got_pong = false
  for i = 0; i < s_pkts.length(); i = i + 1 {
    let evs = client.handle_packet(s_pkts[i][:], 1130UL)
    for j = 0; j < evs.length(); j = j + 1 {
      match evs[j] {
        @association.Event::Message(m) => {
          assert_eq(m.payload, b"pong")
          assert_eq(m.unordered, true)
          got_pong = true
        }
        _ => ()
      }
    }
  }
  assert_true(got_pong)
}

///|
test "facade 3: stateless INIT + PR-SCTP option builders" {
  let c_cfg = @moonsctp.client_config(7000U, 7001U, 0xCAFEBABEU, 500U)
  let s_cfg = @moonsctp.server_config(
    7001U, 7000U, 0xFEEDFACEU, 600U, b"stateless-cookie-secret-key-32b!",
  )
  let client = @moonsctp.new_client(c_cfg)
  let init_pkts = client.connect(0UL)
  let init_ack = @moonsctp.process_stateless_init(s_cfg, init_pkts[0][:], 10UL)
  let _ = client.handle_packet(init_ack[:], 20UL)
  let ce = client.poll_outbound()
  let server = @moonsctp.new_server(s_cfg)
  let _ = server.handle_packet(ce[0][:], 30UL)
  let ca = server.poll_outbound()
  let _ = client.handle_packet(ca[0][:], 40UL)

  let rtx_opts = @moonsctp.partial_retransmit_opts(1U, 2, ppid=10U)
  assert_eq(
    rtx_opts.reliability,
    @association.ReliabilityPolicy::MaxRetransmits(2),
  )
  let timed_opts = @moonsctp.partial_timed_opts(
    2U,
    500UL,
    ppid=20U,
    unordered=true,
  )
  assert_eq(
    timed_opts.reliability,
    @association.ReliabilityPolicy::TimedMs(500UL),
  )
  assert_eq(timed_opts.unordered, true)

  client.send(b"pr-sctp-payload", rtx_opts, 100UL)
  let out = client.poll_outbound()
  let evs = server.handle_packet(out[0][:], 110UL)
  assert_eq(evs.length(), 1)
}

///|
test "facade 4: cookie seal/open and graceful 3-way shutdown" {
  let secret = b"root-cookie-test-secret-key-32by"
  let payload : @cookie.CookiePayload = {
    local_vtag: 1U,
    peer_vtag: 2U,
    local_tsn: 3U,
    peer_tsn: 4U,
    out_streams: 8U,
    in_streams: 8U,
    peer_arwnd: 65536U,
    created_ms: 500UL,
  }
  let cookie_wire = @moonsctp.seal_cookie(secret, payload)
  let opened = @moonsctp.open_cookie(secret, cookie_wire, 1500UL, 60000UL)
  assert_eq(opened, payload)

  let client = @moonsctp.new_client(
    @moonsctp.client_config(8000U, 8001U, 0x11111111U, 1U),
  )
  let server = @moonsctp.new_server(
    @moonsctp.server_config(8001U, 8000U, 0x22222222U, 2U, secret),
  )
  let _ = @moonsctp.run_handshake_loop(client, server, 0UL)

  client.shutdown(100UL)
  let sd = client.poll_outbound()
  let _ = server.handle_packet(sd[0][:], 110UL)
  let sd_ack = server.poll_outbound()
  let _ = client.handle_packet(sd_ack[0][:], 120UL)
  let sd_comp = client.poll_outbound()
  let _ = server.handle_packet(sd_comp[0][:], 130UL)
  assert_eq(client.state(), @association.AssocState::Closed)
  assert_eq(server.state(), @association.AssocState::Closed)
}
