import assert from "node:assert/strict";
import {
  run_hol_comparison,
  run_prsctp_demo,
  run_security_drill,
} from "../../_build/js/release/build/web_api/web_api.js";

function parseJson(label, raw) {
  assert.equal(typeof raw, "string", `${label}: expected JSON string`);
  return JSON.parse(raw);
}

console.log("=== MoonSCTP Web Demo JS ESM Smoke Suite ===");

// ---------------------------------------------------------------------------
// Lab 1: Multi-Stream HOL-Blocking Elimination Comparison
// ---------------------------------------------------------------------------
{
  const clean = parseJson("hol-clean", run_hol_comparison(0, false, 12));
  assert.equal(clean.ok, true);
  assert.equal(clean.loss_percent, 0);
  assert.equal(clean.reorder_enabled, false);
  assert.equal(clean.packets_dropped, 0);
  assert.equal(clean.sctp_hol_stall_ms, 0);
  assert.equal(clean.single_stream_hol_stall_ms, 0);
  assert.equal(clean.messages_delivered, 12);
  assert.equal(clean.stream_events.length, 12);

  const reorderOnly = parseJson("hol-reorder", run_hol_comparison(0, true, 12));
  assert.equal(reorderOnly.ok, true);
  assert.equal(reorderOnly.packets_dropped, 0);
  assert.equal(reorderOnly.sctp_hol_stall_ms, 0);
  assert.ok(
    reorderOnly.single_stream_hol_stall_ms > 0,
    "expected single-stream HOL stall under reordering"
  );
  assert.equal(reorderOnly.messages_delivered, 12);

  const chaos = parseJson("hol-chaos-15", run_hol_comparison(15, true, 16));
  assert.equal(chaos.ok, true);
  assert.equal(chaos.loss_percent, 15);
  assert.equal(chaos.reorder_enabled, true);
  assert.ok(chaos.packets_sent > 16);
  assert.ok(chaos.packets_dropped > 0);
  assert.ok(chaos.retransmissions > 0);
  assert.equal(chaos.sctp_hol_stall_ms, 0);
  assert.ok(
    chaos.single_stream_hol_stall_ms > 0,
    `expected positive single-stream HOL stall, got ${chaos.single_stream_hol_stall_ms}`
  );
  assert.ok(
    chaos.sctp_other_streams_latency_ms < chaos.sctp_stream0_latency_ms,
    "expected unaffected SCTP streams to beat lossy stream 0"
  );
  assert.equal(chaos.messages_delivered, 16);
  assert.equal(chaos.stream_events.length, 16);

  const heavy = parseJson("hol-chaos-30", run_hol_comparison(30, true, 24));
  assert.equal(heavy.ok, true);
  assert.equal(heavy.sctp_hol_stall_ms, 0);
  assert.ok(heavy.single_stream_hol_stall_ms > 0);
  assert.equal(heavy.messages_delivered, 24);

  console.log(
    `[PASS] Lab 1 (HOL Comparison): 15% loss+reorder -> SCTP stall=${chaos.sctp_hol_stall_ms}ms vs Single-Stream stall=${chaos.single_stream_hol_stall_ms}ms (other=${chaos.sctp_other_streams_latency_ms}ms, s0=${chaos.sctp_stream0_latency_ms}ms)`
  );
}

// ---------------------------------------------------------------------------
// Lab 2: RFC 3758 PR-SCTP FORWARD_TSN Unblock
// ---------------------------------------------------------------------------
{
  const rel = parseJson("prsctp-reliable", run_prsctp_demo("reliable", 1, 2));
  assert.equal(rel.ok, true);
  assert.equal(rel.policy, "reliable");
  assert.equal(rel.forward_tsn_emitted, false);
  assert.equal(rel.abandoned_chunks, 0);
  assert.equal(rel.followup_delivered, true);
  assert.equal(rel.retransmissions, 2);
  assert.ok(Array.isArray(rel.events) && rel.events.length >= 4);

  const maxRtx = parseJson(
    "prsctp-max-rtx",
    run_prsctp_demo("max_retransmits", 1, 2)
  );
  assert.equal(maxRtx.ok, true);
  assert.equal(maxRtx.policy, "max_retransmits");
  assert.equal(maxRtx.forward_tsn_emitted, true);
  assert.equal(maxRtx.abandoned_chunks, 1);
  assert.equal(maxRtx.followup_delivered, true);
  assert.equal(maxRtx.retransmissions, 1);
  assert.ok(maxRtx.events.some((ev) => ev.kind === "forward_tsn"));

  const maxRtx0 = parseJson(
    "prsctp-max-rtx-0",
    run_prsctp_demo("max_retransmits", 0, 1)
  );
  assert.equal(maxRtx0.ok, true);
  assert.equal(maxRtx0.forward_tsn_emitted, true);
  assert.equal(maxRtx0.abandoned_chunks, 1);
  assert.equal(maxRtx0.retransmissions, 0);
  assert.equal(maxRtx0.followup_delivered, true);

  const timed = parseJson("prsctp-timed", run_prsctp_demo("timed_ms", 1, 2));
  assert.equal(timed.ok, true);
  assert.equal(timed.policy, "timed_ms");
  assert.equal(timed.forward_tsn_emitted, true);
  assert.equal(timed.abandoned_chunks, 1);
  assert.equal(timed.followup_delivered, true);
  assert.ok(timed.unblock_time_ms < 500, "timed_ms should unblock well before 1s RTO");

  const invalid = parseJson("prsctp-invalid", run_prsctp_demo("bogus", 1, 1));
  assert.equal(invalid.ok, false);

  console.log(
    `[PASS] Lab 2 (PR-SCTP): reliable unblock=${rel.unblock_time_ms}ms | max_retransmits FORWARD_TSN=${maxRtx.forward_tsn_emitted} | timed_ms unblock=${timed.unblock_time_ms}ms`
  );
}

// ---------------------------------------------------------------------------
// Lab 3: Stateless 4-Way Cookie & 6-Mode Red-Team Security Drills
// ---------------------------------------------------------------------------
{
  const cases = [
    { mode: "none", blocked: false, state: "Established" },
    { mode: "crc32c_tamper", blocked: true, state: "Established" },
    { mode: "cookie_tamper", blocked: true, state: "Closed" },
    { mode: "cookie_hijack_established", blocked: true, state: "Established" },
    { mode: "future_sack", blocked: true, state: "Established" },
    { mode: "forged_abort", blocked: true, state: "Established" },
  ];

  for (const tc of cases) {
    const res = parseJson(`sec-${tc.mode}`, run_security_drill(tc.mode));
    assert.equal(res.ok, true, `mode=${tc.mode}`);
    assert.equal(res.attack_mode, tc.mode);
    assert.equal(res.attack_blocked, tc.blocked, `mode=${tc.mode} blocked mismatch`);
    assert.equal(
      res.association_state,
      tc.state,
      `mode=${tc.mode} state mismatch`
    );
    assert.ok(res.handshake_bytes > 100, `mode=${tc.mode} handshake_bytes`);
    assert.ok(res.verdict.length > 10, `mode=${tc.mode} verdict`);
    assert.ok(res.wire_hex_preview.length > 20, `mode=${tc.mode} hex`);
  }

  const invalid = parseJson("sec-invalid", run_security_drill("nonexistent"));
  assert.equal(invalid.ok, false);

  console.log(
    `[PASS] Lab 3 (Red-Team Security Drills): all 6/6 modes + invalid guard verified`
  );
}

console.log("=== ALL WEB DEMO SMOKE CHECKS PASSED ===");
