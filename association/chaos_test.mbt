///|
priv struct ScheduledPacket {
  deliver_at_ms : UInt64
  to_server : Bool
  raw : Bytes
}

///|
/// Deterministic network chaos simulator supporting configurable packet loss,
/// random reordering via jitter, and packet duplication.
priv struct ChaosLink {
  mut rng : UInt32
  loss_pct : Int32
  dup_pct : Int32
  base_delay_ms : UInt64
  max_jitter_ms : UInt64
  queue : Array[ScheduledPacket]
  mut total_sent : Int32
  mut dropped : Int32
  mut duplicated : Int32
}

///|
fn ChaosLink::new(
  seed : UInt32,
  loss_pct : Int32,
  dup_pct : Int32,
  base_delay_ms : UInt64,
  max_jitter_ms : UInt64,
) -> ChaosLink {
  {
    rng: if seed == 0U {
      0x9E3779B9U
    } else {
      seed
    },
    loss_pct,
    dup_pct,
    base_delay_ms,
    max_jitter_ms,
    queue: [],
    total_sent: 0,
    dropped: 0,
    duplicated: 0,
  }
}

///|
fn ChaosLink::next_u32(self : ChaosLink) -> UInt32 {
  let mut x = self.rng
  x = x ^ (x << 13)
  x = x ^ (x >> 17)
  x = x ^ (x << 5)
  self.rng = x
  x
}

///|
fn ChaosLink::enqueue(
  self : ChaosLink,
  raw : Bytes,
  to_server : Bool,
  now_ms : UInt64,
) -> Unit {
  self.total_sent = self.total_sent + 1
  let roll = (self.next_u32() % 100U).reinterpret_as_int()
  if roll < self.loss_pct {
    self.dropped = self.dropped + 1
    return
  }
  let jitter = if self.max_jitter_ms == 0UL {
    0UL
  } else {
    self.next_u32().to_uint64() % (self.max_jitter_ms + 1UL)
  }
  self.queue.push({
    deliver_at_ms: now_ms + self.base_delay_ms + jitter,
    to_server,
    raw,
  })
  let dup_roll = (self.next_u32() % 100U).reinterpret_as_int()
  if dup_roll < self.dup_pct {
    self.duplicated = self.duplicated + 1
    let dup_jitter = if self.max_jitter_ms == 0UL {
      5UL
    } else {
      self.next_u32().to_uint64() % (self.max_jitter_ms + 1UL)
    }
    self.queue.push({
      deliver_at_ms: now_ms + self.base_delay_ms + dup_jitter,
      to_server,
      raw,
    })
  }
}

///|
fn ChaosLink::enqueue_all(
  self : ChaosLink,
  pkts : Array[Bytes],
  to_server : Bool,
  now_ms : UInt64,
) -> Unit {
  for i = 0; i < pkts.length(); i = i + 1 {
    self.enqueue(pkts[i], to_server, now_ms)
  }
}

///|
fn ChaosLink::deliver_due(
  self : ChaosLink,
  now_ms : UInt64,
  client : @association.Association,
  server : @association.Association,
  client_msgs : Array[@association.DeliveredMessage],
  server_msgs : Array[@association.DeliveredMessage],
) -> Unit raise @association.AssocError {
  let due : Array[ScheduledPacket] = []
  let later : Array[ScheduledPacket] = []
  for i = 0; i < self.queue.length(); i = i + 1 {
    if self.queue[i].deliver_at_ms <= now_ms {
      due.push(self.queue[i])
    } else {
      later.push(self.queue[i])
    }
  }
  self.queue.clear()
  for i = 0; i < later.length(); i = i + 1 {
    self.queue.push(later[i])
  }
  for i = 0; i < due.length(); i = i + 1 {
    let sp = due[i]
    if sp.to_server {
      let evs = server.handle_packet(sp.raw[:], now_ms)
      for j = 0; j < evs.length(); j = j + 1 {
        match evs[j] {
          @association.Event::Message(m) => server_msgs.push(m)
          _ => ()
        }
      }
      self.enqueue_all(server.poll_outbound(), false, now_ms)
    } else {
      let evs = client.handle_packet(sp.raw[:], now_ms)
      for j = 0; j < evs.length(); j = j + 1 {
        match evs[j] {
          @association.Event::Message(m) => client_msgs.push(m)
          _ => ()
        }
      }
      self.enqueue_all(client.poll_outbound(), true, now_ms)
    }
  }
}

///|
fn make_pattern_payload(tag : Int32, len : Int32) -> Bytes {
  let buf : FixedArray[Byte] = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    buf[i] = ((tag * 31 + i * 17 + 7) & 0xFF).to_byte()
  }
  Bytes::from_array(buf)
}

///|
fn establish_pair(
  client_tsn : UInt32,
  server_tsn : UInt32,
  num_streams : UInt32,
  now_ms : UInt64,
) -> (@association.Association, @association.Association) raise {
  let secret = b"moonsctp-test-secret-key-32bytes!"
  let client_cfg = @association.Config::default_client(
    5000U,
    5001U,
    0x11223344U,
    client_tsn,
    num_outbound_streams=num_streams,
    num_inbound_streams=num_streams,
  )
  let server_cfg = @association.Config::default_server(
    5001U,
    5000U,
    0xAABBCCDDU,
    server_tsn,
    secret,
    num_outbound_streams=num_streams,
    num_inbound_streams=num_streams,
  )
  let client = @association.Association::new_client(client_cfg)
  let init_pkts = client.connect(now_ms)
  assert_eq(init_pkts.length(), 1)
  assert_eq(client.state(), @association.AssocState::CookieWait)

  // Stateless server INIT handling (zero session allocation!)
  let init_ack = @association.Association::process_stateless_init(
    server_cfg,
    init_pkts[0][:],
    now_ms + 5UL,
  )

  let _ = client.handle_packet(init_ack[:], now_ms + 10UL)
  assert_eq(client.state(), @association.AssocState::CookieEchoed)
  let cookie_echo_pkts = client.poll_outbound()
  assert_eq(cookie_echo_pkts.length(), 1)

  // Server allocates session ONLY after receiving COOKIE_ECHO
  let server = @association.Association::new_server(server_cfg)
  let server_evs = server.handle_packet(cookie_echo_pkts[0][:], now_ms + 15UL)
  assert_eq(server_evs, [@association.Event::Connected])
  assert_eq(server.state(), @association.AssocState::Established)
  let cookie_ack_pkts = server.poll_outbound()
  assert_eq(cookie_ack_pkts.length(), 1)

  let client_evs = client.handle_packet(cookie_ack_pkts[0][:], now_ms + 20UL)
  assert_eq(client_evs, [@association.Event::Connected])
  assert_eq(client.state(), @association.AssocState::Established)

  (client, server)
}

///|
test "chaos 1: 4-way stateless cookie handshake, bidirectional messaging, heartbeat, and 3-way shutdown" {
  let (client, server) = establish_pair(1000U, 2000U, 8U, 100UL)

  // Bidirectional messaging (ordered + unordered)
  client.send(
    b"hello-from-client",
    @association.SendOptions::reliable(0U, ppid=42U),
    200UL,
  )
  server.send(
    b"hello-from-server",
    @association.SendOptions::unordered(3U, ppid=99U),
    200UL,
  )
  let c_out = client.poll_outbound()
  let s_out = server.poll_outbound()
  assert_eq(c_out.length(), 1)
  assert_eq(s_out.length(), 1)

  let s_ev = server.handle_packet(c_out[0][:], 210UL)
  assert_eq(s_ev, [
    @association.Event::Message({
      stream_id: 0U,
      ppid: 42U,
      unordered: false,
      payload: b"hello-from-client",
    }),
  ])
  let c_ev = client.handle_packet(s_out[0][:], 210UL)
  assert_eq(c_ev, [
    @association.Event::Message({
      stream_id: 3U,
      ppid: 99U,
      unordered: true,
      payload: b"hello-from-server",
    }),
  ])

  // Deliver SACKs so both send queues drain
  let s_sacks = server.poll_outbound()
  let c_sacks = client.poll_outbound()
  for i = 0; i < s_sacks.length(); i = i + 1 {
    let _ = client.handle_packet(s_sacks[i][:], 220UL)
  }
  for i = 0; i < c_sacks.length(); i = i + 1 {
    let _ = server.handle_packet(c_sacks[i][:], 220UL)
  }

  // Heartbeat roundtrip
  client.send_heartbeat(b"hb-nonce-77", 230UL)
  let hb_pkts = client.poll_outbound()
  assert_eq(hb_pkts.length(), 1)
  let _ = server.handle_packet(hb_pkts[0][:], 240UL)
  let hb_ack_pkts = server.poll_outbound()
  assert_eq(hb_ack_pkts.length(), 1)
  let hb_ev = client.handle_packet(hb_ack_pkts[0][:], 250UL)
  assert_eq(hb_ev, [@association.Event::HeartbeatAcked(b"hb-nonce-77")])

  // Graceful 3-way shutdown: SHUTDOWN -> SHUTDOWN_ACK -> SHUTDOWN_COMPLETE
  client.shutdown(300UL)
  assert_eq(client.state(), @association.AssocState::ShutdownSent)
  let sd_pkts = client.poll_outbound()
  assert_eq(sd_pkts.length(), 1)

  let s_sd_ev = server.handle_packet(sd_pkts[0][:], 310UL)
  assert_eq(s_sd_ev, [@association.Event::PeerShutdown])
  assert_eq(server.state(), @association.AssocState::ShutdownAckSent)
  let sd_ack_pkts = server.poll_outbound()
  assert_eq(sd_ack_pkts.length(), 1)

  let c_sd_ev = client.handle_packet(sd_ack_pkts[0][:], 320UL)
  assert_eq(c_sd_ev, [@association.Event::Closed])
  assert_eq(client.state(), @association.AssocState::Closed)
  let sd_comp_pkts = client.poll_outbound()
  assert_eq(sd_comp_pkts.length(), 1)

  let s_comp_ev = server.handle_packet(sd_comp_pkts[0][:], 330UL)
  assert_eq(s_comp_ev, [@association.Event::Closed])
  assert_eq(server.state(), @association.AssocState::Closed)
}

///|
test "chaos 2: HOL-blocking elimination proof across independent streams" {
  let (client, server) = establish_pair(5000U, 6000U, 4U, 0UL)

  // Send Stream 0 message and deliberately DROP its packet!
  client.send(
    b"stream0-lost-msg",
    @association.SendOptions::reliable(0U, ppid=10U),
    100UL,
  )
  let dropped_s0 = client.poll_outbound()
  assert_eq(dropped_s0.length(), 1)

  // Send 3 messages on Stream 1 and deliver all 3 immediately
  client.send(
    b"stream1-msg-1",
    @association.SendOptions::reliable(1U, ppid=11U),
    110UL,
  )
  client.send(
    b"stream1-msg-2",
    @association.SendOptions::reliable(1U, ppid=11U),
    115UL,
  )
  client.send(
    b"stream1-msg-3",
    @association.SendOptions::reliable(1U, ppid=11U),
    120UL,
  )
  let s1_pkts = client.poll_outbound()
  assert_eq(s1_pkts.length(), 3)

  let delivered_now : Array[@association.DeliveredMessage] = []
  for i = 0; i < s1_pkts.length(); i = i + 1 {
    let evs = server.handle_packet(s1_pkts[i][:], 130UL + i.to_uint64())
    for j = 0; j < evs.length(); j = j + 1 {
      match evs[j] {
        @association.Event::Message(m) => delivered_now.push(m)
        _ => ()
      }
    }
  }

  // Proof of zero cross-stream HOL blocking: all 3 Stream 1 messages delivered
  // IMMEDIATELY even though Stream 0's earlier TSN is still missing!
  assert_eq(delivered_now.length(), 3)
  assert_eq(delivered_now[0].stream_id, 1U)
  assert_eq(delivered_now[0].payload, b"stream1-msg-1")
  assert_eq(delivered_now[1].payload, b"stream1-msg-2")
  assert_eq(delivered_now[2].payload, b"stream1-msg-3")

  // Feed Server's 3 gap SACKs back to Client -> triggers RFC 9260 3-missing-report
  // fast retransmit of Stream 0's dropped packet!
  let sacks = server.poll_outbound()
  assert_eq(sacks.length(), 3)
  for i = 0; i < sacks.length(); i = i + 1 {
    let _ = client.handle_packet(sacks[i][:], 150UL + i.to_uint64())
  }
  let rtx_pkts = client.poll_outbound()
  assert_true(rtx_pkts.length() >= 1)
  assert_true(client.stats().retransmissions >= 1)

  // Deliver retransmitted Stream 0 packet -> Stream 0 now completes cleanly!
  let s0_delivered : Array[@association.DeliveredMessage] = []
  for i = 0; i < rtx_pkts.length(); i = i + 1 {
    let evs = server.handle_packet(rtx_pkts[i][:], 170UL + i.to_uint64())
    for j = 0; j < evs.length(); j = j + 1 {
      match evs[j] {
        @association.Event::Message(m) => s0_delivered.push(m)
        _ => ()
      }
    }
  }
  assert_eq(s0_delivered.length(), 1)
  assert_eq(s0_delivered[0].stream_id, 0U)
  assert_eq(s0_delivered[0].payload, b"stream0-lost-msg")
}

///|
test "chaos 3: 15% loss + random reordering + duplication across 4 streams and 30 multi-fragment messages" {
  let (client, server) = establish_pair(10000U, 20000U, 4U, 0UL)
  let link = ChaosLink::new(0xC0FFEE42U, 15, 12, 10UL, 60UL)

  let expected_per_stream : Array[Array[Bytes]] = [[], [], [], []]
  let total_messages = 30
  let mut now_ms = 100UL

  // Enqueue 30 messages across 4 streams, including large >3KB multi-fragment messages
  for i = 0; i < total_messages; i = i + 1 {
    let sid = i % 4
    let len = if i % 3 == 0 { 3600 + i * 37 } else { 400 + i * 53 }
    let payload = make_pattern_payload(i + 1, len)
    expected_per_stream[sid].push(payload)
    client.send(
      payload,
      @association.SendOptions::reliable(
        sid.reinterpret_as_uint(),
        ppid=i.reinterpret_as_uint(),
      ),
      now_ms,
    )
    link.enqueue_all(client.poll_outbound(), true, now_ms)
  }

  let client_msgs : Array[@association.DeliveredMessage] = []
  let server_msgs : Array[@association.DeliveredMessage] = []

  // Drive simulation up to 120 seconds in 25ms ticks
  let mut steps = 0
  while server_msgs.length() < total_messages && steps < 4800 {
    now_ms = now_ms + 25UL
    steps = steps + 1
    link.deliver_due(now_ms, client, server, client_msgs, server_msgs)
    let _ = client.tick(now_ms)
    link.enqueue_all(client.poll_outbound(), true, now_ms)
    let _ = server.tick(now_ms)
    link.enqueue_all(server.poll_outbound(), false, now_ms)
  }

  // Verify chaos actually exercised drops, duplications, and retransmissions
  assert_true(link.dropped > 0)
  assert_true(link.duplicated > 0)
  assert_true(client.stats().retransmissions > 0)

  // Verify 100% lossless byte-exact ordered delivery on every single stream
  assert_eq(server_msgs.length(), total_messages)
  let got_per_stream : Array[Array[Bytes]] = [[], [], [], []]
  for i = 0; i < server_msgs.length(); i = i + 1 {
    let m = server_msgs[i]
    got_per_stream[m.stream_id.reinterpret_as_int()].push(m.payload)
  }
  for sid = 0; sid < 4; sid = sid + 1 {
    assert_eq(got_per_stream[sid].length(), expected_per_stream[sid].length())
    for k = 0; k < expected_per_stream[sid].length(); k = k + 1 {
      assert_eq(got_per_stream[sid][k], expected_per_stream[sid][k])
    }
  }
}

///|
test "chaos 4: RFC 3758 PR-SCTP MaxRetransmits(1) and TimedMs skipping with FORWARD_TSN" {
  let (client, server) = establish_pair(30000U, 40000U, 4U, 0UL)

  // Part A: MaxRetransmits(1) on Stream 0
  // Transmission #1 (initial) -> deliberately DROPPED
  client.send(
    b"ephemeral-video-frame",
    {
      stream_id: 0U,
      ppid: 1U,
      unordered: false,
      reliability: @association.ReliabilityPolicy::MaxRetransmits(1),
    },
    100UL,
  )
  let tx1 = client.poll_outbound()
  assert_eq(tx1.length(), 1)

  // Follow-up reliable message on the SAME Stream 0 -> delivered to server
  client.send(
    b"reliable-keyframe",
    @association.SendOptions::reliable(0U, ppid=2U),
    120UL,
  )
  let reliable_pkt = client.poll_outbound()
  assert_eq(reliable_pkt.length(), 1)
  let ev_before_skip = server.handle_packet(reliable_pkt[0][:], 130UL)
  // Blocked behind the dropped SSN 0 on Stream 0!
  assert_eq(ev_before_skip.length(), 0)
  let sack1 = server.poll_outbound()
  for i = 0; i < sack1.length(); i = i + 1 {
    let _ = client.handle_packet(sack1[i][:], 140UL)
  }

  // First T3-rtx timeout -> retransmit #1 (transmission #2) -> deliberately DROPPED
  let _ = client.tick(1200UL)
  let tx2 = client.poll_outbound()
  assert_eq(tx2.length(), 1)
  assert_eq(client.stats().forward_tsn_sent, 0)

  // Second T3-rtx timeout -> MaxRetransmits(1) exhausted -> abandon & emit FORWARD_TSN!
  let _ = client.tick(3500UL)
  let ftsn_pkts = client.poll_outbound()
  assert_true(ftsn_pkts.length() >= 1)
  assert_true(client.stats().forward_tsn_sent >= 1)

  // Deliver FORWARD_TSN to server -> immediately unblocks and delivers "reliable-keyframe"!
  let unblocked : Array[@association.DeliveredMessage] = []
  for i = 0; i < ftsn_pkts.length(); i = i + 1 {
    let evs = server.handle_packet(ftsn_pkts[i][:], 3520UL)
    for j = 0; j < evs.length(); j = j + 1 {
      match evs[j] {
        @association.Event::Message(m) => unblocked.push(m)
        _ => ()
      }
    }
  }
  assert_eq(unblocked.length(), 1)
  assert_eq(unblocked[0].stream_id, 0U)
  assert_eq(unblocked[0].payload, b"reliable-keyframe")

  // Drain server SACK back to client
  let sack_after = server.poll_outbound()
  for i = 0; i < sack_after.length(); i = i + 1 {
    let _ = client.handle_packet(sack_after[i][:], 3540UL)
  }

  // Part B: TimedMs(150UL) on Stream 1
  client.send(
    b"timed-out-telemetry",
    {
      stream_id: 1U,
      ppid: 3U,
      unordered: false,
      reliability: @association.ReliabilityPolicy::TimedMs(150UL),
    },
    4000UL,
  )
  let _dropped_timed = client.poll_outbound()
  client.send(
    b"fresh-telemetry",
    @association.SendOptions::reliable(1U, ppid=4U),
    4010UL,
  )
  let fresh_pkt = client.poll_outbound()
  let ev_blocked_s1 = server.handle_packet(fresh_pkt[0][:], 4020UL)
  assert_eq(ev_blocked_s1.length(), 0)
  let s1_sacks = server.poll_outbound()
  for i = 0; i < s1_sacks.length(); i = i + 1 {
    let _ = client.handle_packet(s1_sacks[i][:], 4030UL)
  }

  // Advance clock past 150ms TTL -> client expires msg and emits FORWARD_TSN!
  let prev_ftsn = client.stats().forward_tsn_sent
  let _ = client.tick(4200UL)
  assert_true(client.stats().forward_tsn_sent > prev_ftsn)
  let timed_ftsn_pkts = client.poll_outbound()
  let unblocked_s1 : Array[@association.DeliveredMessage] = []
  for i = 0; i < timed_ftsn_pkts.length(); i = i + 1 {
    let evs = server.handle_packet(timed_ftsn_pkts[i][:], 4220UL)
    for j = 0; j < evs.length(); j = j + 1 {
      match evs[j] {
        @association.Event::Message(m) => unblocked_s1.push(m)
        _ => ()
      }
    }
  }
  assert_eq(unblocked_s1.length(), 1)
  assert_eq(unblocked_s1[0].stream_id, 1U)
  assert_eq(unblocked_s1[0].payload, b"fresh-telemetry")
}

///|
test "chaos 5: RFC 1982 32-bit TSN wraparound across 0xFFFFFFFF -> 0x00000000 with packet loss" {
  let (client, server) = establish_pair(0xFFFFFFFCU, 0xFFFFFFFEU, 4U, 0UL)
  let link = ChaosLink::new(0xDEADBEEFU, 20, 10, 10UL, 40UL)

  let expected : Array[Bytes] = []
  let total = 12
  let mut now_ms = 100UL
  for i = 0; i < total; i = i + 1 {
    let payload = make_pattern_payload(100 + i, 180 + i * 25)
    expected.push(payload)
    client.send(
      payload,
      @association.SendOptions::reliable(0U, ppid=i.reinterpret_as_uint()),
      now_ms,
    )
    link.enqueue_all(client.poll_outbound(), true, now_ms)
  }

  let client_msgs : Array[@association.DeliveredMessage] = []
  let server_msgs : Array[@association.DeliveredMessage] = []
  let mut steps = 0
  while server_msgs.length() < total && steps < 3000 {
    now_ms = now_ms + 25UL
    steps = steps + 1
    link.deliver_due(now_ms, client, server, client_msgs, server_msgs)
    let _ = client.tick(now_ms)
    link.enqueue_all(client.poll_outbound(), true, now_ms)
    let _ = server.tick(now_ms)
    link.enqueue_all(server.poll_outbound(), false, now_ms)
  }

  assert_true(link.dropped > 0)
  assert_true(client.stats().retransmissions > 0)
  assert_eq(server_msgs.length(), total)
  for i = 0; i < total; i = i + 1 {
    assert_eq(server_msgs[i].payload, expected[i])
  }
}
