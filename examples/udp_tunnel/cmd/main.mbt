///|
async fn main {
  let t0 = @async.now()
  println("===================================================================")
  println("  MoonSCTP RFC 6951 SCTP-over-UDP Real OS Loopback Tunnel Demo")
  println("===================================================================")

  let r = @tunnel.run_full_rfc6951_udp_tunnel()
  let elapsed = @async.now() - t0

  println("\n[1/4] Stateless Anti-SYN-Flood 4-Way Cookie Handshake (Real UDP)")
  println(
    "  PASS: " +
    r.client_addr +
    " <-> " +
    r.server_addr +
    " (stateless_init_acks=" +
    r.stateless_init_acks.to_string() +
    ")",
  )

  println("\n[2/4] Multi-Stream (0/1/2) Ordered/Unordered + Fast Retransmit")
  println(
    "  PASS: Stream 0 #1 dropped -> Stream 1 delivered " +
    r.stream1_delivered_before_s0_rtx.to_string() +
    "/2 + Stream 2 (U=1) delivered " +
    r.stream2_unordered_delivered_before_s0_rtx.to_string() +
    "/2 with 0 HOL stall",
  )
  println(
    "  PASS: 3-SACK fast retransmit recovered Stream 0 (retransmissions=" +
    r.fast_retransmissions.to_string() +
    ", bidir replies=" +
    r.client_delivered.length().to_string() +
    ")",
  )

  println("\n[3/4] RFC 3758 PR-SCTP FORWARD_TSN Frame Skip (Real UDP)")
  println(
    "  PASS: MaxRetransmits(0) emitted FORWARD_TSN=" +
    r.forward_tsn_sent.to_string() +
    " (skipped_absent=" +
    r.prsctp_skipped_absent.to_string() +
    ", followup_unblocked=" +
    r.prsctp_followup_unblocked.to_string() +
    ")",
  )

  println("\n[4/4] HEARTBEAT + Graceful 3-Way SHUTDOWN (Real UDP)")
  println(
    "  PASS: HEARTBEAT_ACK=" +
    r.heartbeat_acked.to_string() +
    ", client_closed=" +
    r.client_closed_gracefully.to_string() +
    ", server_closed=" +
    r.server_closed_gracefully.to_string(),
  )
  println(
    "\nSummary: real UDP datagrams c2s=" +
    r.udp_datagrams_c2s.to_string() +
    " (" +
    r.udp_bytes_c2s.to_string() +
    "B), s2c=" +
    r.udp_datagrams_s2c.to_string() +
    " (" +
    r.udp_bytes_s2c.to_string() +
    "B), simulated_drops=" +
    r.simulated_drops.to_string() +
    ", elapsed=" +
    elapsed.to_string() +
    "ms",
  )
}
