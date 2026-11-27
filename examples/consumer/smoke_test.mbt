///|
test "consumer 1: Castagnoli CRC-32C and stateless HMAC-SHA256 Cookie roundtrip" {
  assert_eq(@sctp.crc32c(b"123456789"), 0xE3069283U)
  assert_eq(@sctp.crc32c(Bytes::make(32, b'\x00')), 0x8A9136AAU)

  let secret = b"consumer-smoke-cookie-secret-32b!"
  let payload : @cookie.CookiePayload = {
    local_vtag: 0xAABBCCDDU,
    peer_vtag: 0x11223344U,
    local_tsn: 0xFFFFFFFEU,
    peer_tsn: 0x00000010U,
    out_streams: 4U,
    in_streams: 4U,
    peer_arwnd: 65536U,
    created_ms: 1000UL,
  }
  let wire = @sctp.seal_cookie(secret, payload)
  assert_eq(wire.length(), @cookie.COOKIE_WIRE_LEN)
  let opened = @sctp.open_cookie(secret, wire, 2000UL, 60000UL)
  assert_eq(opened, payload)
}

///|
test "consumer 2: stateless 4-way Cookie handshake and multi-stream send/recv" {
  let secret = b"consumer-handshake-hmac-key-32by!"
  let c_cfg = @sctp.client_config(
    5000U,
    5001U,
    0x12345678U,
    1000U,
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )
  let s_cfg = @sctp.server_config(
    5001U,
    5000U,
    0x87654321U,
    2000U,
    secret,
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )

  // Stateless INIT -> INIT_ACK before allocating server Association
  let client = @sctp.new_client(c_cfg)
  let init_pkts = client.connect(0UL)
  assert_eq(init_pkts.length(), 1)
  let init_ack = @sctp.process_stateless_init(s_cfg, init_pkts[0][:], 5UL)
  let _ = client.handle_packet(init_ack[:], 10UL)
  let ce_pkts = client.poll_outbound()
  assert_eq(ce_pkts.length(), 1)

  let server = @sctp.new_server(s_cfg)
  let s_conn = server.handle_packet(ce_pkts[0][:], 15UL)
  assert_eq(s_conn, [@assoc.Event::Connected])
  let ca_pkts = server.poll_outbound()
  let c_conn = client.handle_packet(ca_pkts[0][:], 20UL)
  assert_eq(c_conn, [@assoc.Event::Connected])

  // Stream 0 packet dropped -> Stream 1 & Stream 2 still deliver immediately (zero HOL blocking)
  client.send(b"stream0-lost", @sctp.reliable_opts(0U, ppid=10U), 100UL)
  let _dropped = client.poll_outbound()

  client.send(b"stream1-hello", @sctp.reliable_opts(1U, ppid=11U), 110UL)
  client.send(b"stream2-unordered", @sctp.unordered_opts(2U, ppid=12U), 120UL)
  let pkts = client.poll_outbound()
  assert_eq(pkts.length(), 2)

  let ev1 = server.handle_packet(pkts[0][:], 130UL)
  let ev2 = server.handle_packet(pkts[1][:], 135UL)
  assert_eq(ev1, [
    @assoc.Event::Message({
      stream_id: 1U,
      ppid: 11U,
      unordered: false,
      payload: b"stream1-hello",
    }),
  ])
  assert_eq(ev2, [
    @assoc.Event::Message({
      stream_id: 2U,
      ppid: 12U,
      unordered: true,
      payload: b"stream2-unordered",
    }),
  ])
}
