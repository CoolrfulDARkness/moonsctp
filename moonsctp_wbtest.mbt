///|
test "wb: send option helpers preserve defaults and PR-SCTP policies" {
  let r = reliable_opts(3U)
  assert_eq(r.stream_id, 3U)
  assert_eq(r.ppid, 0U)
  assert_eq(r.unordered, false)
  assert_eq(r.reliability, @association.ReliabilityPolicy::Reliable)

  let u = unordered_opts(2U, ppid=55U)
  assert_eq(u.unordered, true)
  assert_eq(u.ppid, 55U)

  let pr = partial_retransmit_opts(1U, 3)
  assert_eq(pr.reliability, @association.ReliabilityPolicy::MaxRetransmits(3))

  let pt = partial_timed_opts(0U, 250UL)
  assert_eq(pt.reliability, @association.ReliabilityPolicy::TimedMs(250UL))
}
