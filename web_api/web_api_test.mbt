///|
test "web_api: run_hol_comparison clean, reorder-only, and lossy networks" {
  let clean = @web_api.run_hol_comparison(0, false, 8)
  assert_true(clean.contains("\"ok\":true"))
  assert_true(clean.contains("\"packets_dropped\":0"))
  assert_true(clean.contains("\"sctp_hol_stall_ms\":0"))
  assert_true(clean.contains("\"single_stream_hol_stall_ms\":0"))
  assert_true(clean.contains("\"messages_delivered\":8"))

  let reorder_only = @web_api.run_hol_comparison(0, true, 12)
  assert_true(reorder_only.contains("\"ok\":true"))
  assert_true(reorder_only.contains("\"packets_dropped\":0"))
  assert_true(reorder_only.contains("\"sctp_hol_stall_ms\":0"))
  assert_true(!reorder_only.contains("\"single_stream_hol_stall_ms\":0,"))
  assert_true(reorder_only.contains("\"messages_delivered\":12"))

  let chaos = @web_api.run_hol_comparison(15, true, 16)
  assert_true(chaos.contains("\"ok\":true"))
  assert_true(chaos.contains("\"loss_percent\":15"))
  assert_true(chaos.contains("\"reorder_enabled\":true"))
  assert_true(chaos.contains("\"sctp_hol_stall_ms\":0"))
  assert_true(chaos.contains("\"messages_delivered\":16"))
  assert_true(!chaos.contains("\"single_stream_hol_stall_ms\":0,"))
  assert_true(!chaos.contains("\"packets_dropped\":0,"))
  assert_true(chaos.contains("\"stream_events\":["))

  let heavy = @web_api.run_hol_comparison(30, true, 24)
  assert_true(heavy.contains("\"ok\":true"))
  assert_true(heavy.contains("\"sctp_hol_stall_ms\":0"))
  assert_true(heavy.contains("\"messages_delivered\":24"))
}

///|
test "web_api: run_prsctp_demo covers reliable, max_retransmits, timed_ms, zero-drop, and invalid policy" {
  let rel = @web_api.run_prsctp_demo("reliable", 1, 2)
  assert_true(rel.contains("\"ok\":true"))
  assert_true(rel.contains("\"policy\":\"reliable\""))
  assert_true(rel.contains("\"forward_tsn_emitted\":false"))
  assert_true(rel.contains("\"abandoned_chunks\":0"))
  assert_true(rel.contains("\"followup_delivered\":true"))
  assert_true(rel.contains("\"retransmissions\":2"))

  let max_r = @web_api.run_prsctp_demo("max_retransmits", 1, 2)
  assert_true(max_r.contains("\"ok\":true"))
  assert_true(max_r.contains("\"policy\":\"max_retransmits\""))
  assert_true(max_r.contains("\"forward_tsn_emitted\":true"))
  assert_true(max_r.contains("\"abandoned_chunks\":1"))
  assert_true(max_r.contains("\"followup_delivered\":true"))

  let max_r0 = @web_api.run_prsctp_demo("max_retransmits", 0, 1)
  assert_true(max_r0.contains("\"ok\":true"))
  assert_true(max_r0.contains("\"forward_tsn_emitted\":true"))
  assert_true(max_r0.contains("\"retransmissions\":0"))
  assert_true(max_r0.contains("\"followup_delivered\":true"))

  let no_drop = @web_api.run_prsctp_demo("max_retransmits", 1, 0)
  assert_true(no_drop.contains("\"ok\":true"))
  assert_true(no_drop.contains("\"forward_tsn_emitted\":false"))
  assert_true(no_drop.contains("\"abandoned_chunks\":0"))
  assert_true(no_drop.contains("\"followup_delivered\":true"))

  let timed = @web_api.run_prsctp_demo("timed_ms", 1, 2)
  assert_true(timed.contains("\"ok\":true"))
  assert_true(timed.contains("\"policy\":\"timed_ms\""))
  assert_true(timed.contains("\"forward_tsn_emitted\":true"))
  assert_true(timed.contains("\"abandoned_chunks\":1"))
  assert_true(timed.contains("\"followup_delivered\":true"))

  let bad = @web_api.run_prsctp_demo("unknown_policy", 1, 1)
  assert_true(bad.contains("\"ok\":false"))
}

///|
test "web_api: run_security_drill covers all 6 modes and invalid mode" {
  let none_res = @web_api.run_security_drill("none")
  assert_true(none_res.contains("\"ok\":true"))
  assert_true(none_res.contains("\"attack_mode\":\"none\""))
  assert_true(none_res.contains("\"attack_blocked\":false"))
  assert_true(none_res.contains("\"association_state\":\"Established\""))

  let crc_res = @web_api.run_security_drill("crc32c_tamper")
  assert_true(crc_res.contains("\"ok\":true"))
  assert_true(crc_res.contains("\"attack_blocked\":true"))
  assert_true(crc_res.contains("\"association_state\":\"Established\""))

  let ck_res = @web_api.run_security_drill("cookie_tamper")
  assert_true(ck_res.contains("\"ok\":true"))
  assert_true(ck_res.contains("\"attack_blocked\":true"))
  assert_true(ck_res.contains("\"association_state\":\"Closed\""))

  let hijack_res = @web_api.run_security_drill("cookie_hijack_established")
  assert_true(hijack_res.contains("\"ok\":true"))
  assert_true(hijack_res.contains("\"attack_blocked\":true"))
  assert_true(hijack_res.contains("\"association_state\":\"Established\""))

  let sack_res = @web_api.run_security_drill("future_sack")
  assert_true(sack_res.contains("\"ok\":true"))
  assert_true(sack_res.contains("\"attack_blocked\":true"))
  assert_true(sack_res.contains("\"association_state\":\"Established\""))

  let abort_res = @web_api.run_security_drill("forged_abort")
  assert_true(abort_res.contains("\"ok\":true"))
  assert_true(abort_res.contains("\"attack_blocked\":true"))
  assert_true(abort_res.contains("\"association_state\":\"Established\""))

  let bad_res = @web_api.run_security_drill("does_not_exist")
  assert_true(bad_res.contains("\"ok\":false"))
}
