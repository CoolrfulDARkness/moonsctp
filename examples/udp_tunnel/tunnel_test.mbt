///|
async test "udp tunnel 1: full RFC 6951 lifecycle over real 127.0.0.1 UDP" {
  let report = @moonsctp_udp_tunnel_example.run_full_rfc6951_udp_tunnel()
  assert_true(report.server_addr is [.. "127.0.0.1:", ..])
  assert_true(report.client_addr is [.. "127.0.0.1:", ..])
  assert_eq(report.stateless_init_acks, 1)
  assert_true(report.udp_datagrams_c2s >= 10)
  assert_true(report.udp_datagrams_s2c >= 10)
  assert_eq(report.simulated_drops, 2)
  assert_eq(report.stream1_delivered_before_s0_rtx, 2)
  assert_eq(report.stream2_unordered_delivered_before_s0_rtx, 2)
  assert_true(report.fast_retransmissions >= 1)
  assert_true(report.forward_tsn_sent >= 1)
  assert_true(report.prsctp_skipped_absent)
  assert_true(report.prsctp_followup_unblocked)
  assert_eq(report.server_delivered.length(), 6)
  assert_eq(report.client_delivered.length(), 1)
  assert_eq(report.client_delivered[0].stream_id, 1U)
  assert_eq(report.client_delivered[0].payload, b"server-udp-reply-stream1")
  assert_true(report.heartbeat_acked)
  assert_eq(report.heartbeat_payload, b"rfc6951-udp-keepalive-probe")
  assert_true(report.client_closed_gracefully)
  assert_true(report.server_closed_gracefully)
}

///|
async test "udp tunnel 2: stateless anti-SYN-flood and tampered cookie rejected over UDP" {
  let report = @moonsctp_udp_tunnel_example.run_stateless_cookie_security_udp_drill()
  assert_eq(report.stateless_init_acks, 1)
  assert_true(report.tampered_cookie_rejected)
  assert_eq(report.assoc_allocated_before_valid_cookie, false)
  assert_true(report.valid_handshake_established)
}

///|
async test "udp tunnel 3: PR-SCTP TimedMs TTL abandonment emits FORWARD_TSN over UDP" {
  let report = @moonsctp_udp_tunnel_example.run_timed_prsctp_udp_drill()
  assert_true(report.forward_tsn_sent >= 1)
  assert_true(report.expired_msg_absent)
  assert_true(report.followup_delivered)
  assert_true(report.udp_datagrams_c2s >= 4)
  assert_true(report.udp_datagrams_s2c >= 4)
}

///|
async test "udp tunnel 4: multi-fragment 4KB bidirectional exchange over real UDP" {
  let report = @moonsctp_udp_tunnel_example.run_fragmented_bidirectional_udp_drill()
  assert_eq(report.server_received_len, 4096)
  assert_eq(report.client_received_len, 3840)
  assert_true(report.server_payload_match)
  assert_true(report.client_payload_match)
  assert_true(report.udp_datagrams_c2s >= 7)
  assert_true(report.udp_datagrams_s2c >= 7)
}
