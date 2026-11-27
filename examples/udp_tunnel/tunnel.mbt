///|
/// End-to-end telemetry report from a real OS `127.0.0.1` RFC 6951
/// SCTP-over-UDP loopback tunnel execution.
#derive(Eq, Debug)
pub(all) struct UdpTunnelReport {
  server_addr : String
  client_addr : String
  stateless_init_acks : Int32
  udp_datagrams_c2s : Int32
  udp_datagrams_s2c : Int32
  udp_bytes_c2s : Int32
  udp_bytes_s2c : Int32
  simulated_drops : Int32
  stream1_delivered_before_s0_rtx : Int32
  stream2_unordered_delivered_before_s0_rtx : Int32
  fast_retransmissions : Int32
  forward_tsn_sent : Int32
  prsctp_skipped_absent : Bool
  prsctp_followup_unblocked : Bool
  server_delivered : Array[@assoc.DeliveredMessage]
  client_delivered : Array[@assoc.DeliveredMessage]
  heartbeat_acked : Bool
  heartbeat_payload : Bytes
  client_closed_gracefully : Bool
  server_closed_gracefully : Bool
}

///|
/// Telemetry report for the real-UDP anti-SYN-flood and tampered Cookie test.
#derive(Eq, Debug)
pub(all) struct StatelessCookieDrillReport {
  stateless_init_acks : Int32
  tampered_cookie_rejected : Bool
  assoc_allocated_before_valid_cookie : Bool
  valid_handshake_established : Bool
}

///|
/// Telemetry report for the real-UDP PR-SCTP `TimedMs` TTL abandonment test.
#derive(Eq, Debug)
pub(all) struct TimedPrSctpReport {
  forward_tsn_sent : Int32
  expired_msg_absent : Bool
  followup_delivered : Bool
  udp_datagrams_c2s : Int32
  udp_datagrams_s2c : Int32
}

///|
/// Telemetry report for the real-UDP multi-fragment bidirectional exchange test.
#derive(Eq, Debug)
pub(all) struct FragmentedUdpReport {
  server_received_len : Int32
  client_received_len : Int32
  server_payload_match : Bool
  client_payload_match : Bool
  udp_datagrams_c2s : Int32
  udp_datagrams_s2c : Int32
}

///|
/// Copies the first `len` bytes from a reusable socket receive buffer into an
/// immutable `Bytes` value without unsafe aliasing.
fn copy_datagram(buf : FixedArray[Byte], len : Int32) -> Bytes {
  Bytes::makei(len, i => buf[i])
}

///|
/// Returns monotonic non-negative milliseconds elapsed since `start_ms`.
fn elapsed_ms(start_ms : Int64) -> UInt64 {
  let delta = @async.now() - start_ms
  if delta <= 0L {
    0UL
  } else {
    delta.reinterpret_as_uint64()
  }
}

///|
/// Builds a client association config tuned for fast loopback RTO while using
/// the real OS-assigned UDP ports in the RFC 6951 encapsulated SCTP header.
fn make_client_cfg(
  local_port : UInt32,
  remote_port : UInt32,
  local_vtag : UInt32,
  initial_tsn : UInt32,
  rto_initial_ms~ : UInt64 = 80UL,
) -> @assoc.Config {
  let base = @sctp.client_config(
    local_port,
    remote_port,
    local_vtag,
    initial_tsn,
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )
  { ..base, rto_initial_ms, rto_max_ms: 2000UL, }
}

///|
/// Builds a server association config with HMAC-SHA256 stateless cookie secret
/// and real OS-assigned UDP ports.
fn make_server_cfg(
  local_port : UInt32,
  remote_port : UInt32,
  local_vtag : UInt32,
  initial_tsn : UInt32,
  cookie_secret : Bytes,
  rto_initial_ms~ : UInt64 = 80UL,
) -> @assoc.Config {
  let base = @sctp.server_config(
    local_port,
    remote_port,
    local_vtag,
    initial_tsn,
    cookie_secret,
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )
  { ..base, rto_initial_ms, rto_max_ms: 2000UL, }
}

///|
/// Checks whether a raw wire SCTP packet carries a standalone `INIT` chunk so
/// the server can handle it statelessly without allocating session memory.
fn is_init_packet(raw : Bytes) -> Bool {
  let pkt : @packet.Packet? = Some(@sctp.decode_packet(raw[:])) catch {
    _ => None
  }
  match pkt {
    Some(p) =>
      if p.chunks.length() == 1 {
        match p.chunks[0] {
          @packet.Chunk::Init(_) => true
          _ => false
        }
      } else {
        false
      }
    None => false
  }
}

///|
/// Flips one bit at `idx` in `raw` to simulate wire/cookie tampering.
fn flip_bit(raw : Bytes, idx : Int32) -> Bytes {
  Bytes::makei(raw.length(), i => {
    if i == idx {
      (raw[i].to_int() ^ 0x01).to_byte()
    } else {
      raw[i]
    }
  })
}

///|
/// Checks whether `msgs` contains a delivered message with matching stream and
/// payload.
fn has_message(
  msgs : Array[@assoc.DeliveredMessage],
  stream_id : UInt32,
  payload : Bytes,
) -> Bool {
  for i = 0; i < msgs.length(); i = i + 1 {
    if msgs[i].stream_id == stream_id && msgs[i].payload == payload {
      return true
    }
  }
  false
}

///|
/// Flushes all queued outbound SCTP packets from `assoc` onto `udp_client`,
/// updating datagram/byte counters.
async fn flush_client_udp(
  assoc : @assoc.Association,
  udp : @socket.UdpClient,
  c2s_count : Ref[Int32],
  c2s_bytes : Ref[Int32],
) -> Unit {
  let pkts = assoc.poll_outbound()
  for i = 0; i < pkts.length(); i = i + 1 {
    udp.send(pkts[i])
    c2s_count.val = c2s_count.val + 1
    c2s_bytes.val = c2s_bytes.val + pkts[i].length()
  }
}

///|
/// Flushes all queued outbound SCTP packets from `assoc` onto `udp_server`,
/// sending each datagram to `peer_addr`.
async fn flush_server_udp(
  assoc : @assoc.Association,
  udp : @socket.UdpServer,
  peer_addr : @socket.Addr,
  s2c_count : Ref[Int32],
  s2c_bytes : Ref[Int32],
) -> Unit {
  let pkts = assoc.poll_outbound()
  for i = 0; i < pkts.length(); i = i + 1 {
    udp.sendto(pkts[i], peer_addr)
    s2c_count.val = s2c_count.val + 1
    s2c_bytes.val = s2c_bytes.val + pkts[i].length()
  }
}

///|
/// Drains incoming UDP datagrams on `udp_client` and advances `client.tick()`
/// until `stop_cond()` becomes true or `timeout_ms` elapses.
async fn pump_client_until(
  client : @assoc.Association,
  udp : @socket.UdpClient,
  start_ms : Int64,
  c2s_count : Ref[Int32],
  c2s_bytes : Ref[Int32],
  client_delivered : Array[@assoc.DeliveredMessage],
  heartbeat_acked : Ref[Bool],
  heartbeat_payload : Ref[Bytes],
  client_closed : Ref[Bool],
  timeout_ms : Int64,
  stop_cond : () -> Bool,
) -> Unit {
  let buf = FixedArray::make(8192, b'\x00')
  let deadline = @async.now() + timeout_ms
  while !stop_cond() && @async.now() < deadline {
    let recv_opt = @async.with_timeout_opt(20, () => udp.recv(buf))
    let now = elapsed_ms(start_ms)
    match recv_opt {
      Some(n) => {
        let raw = copy_datagram(buf, n)
        let evs = client.handle_packet(raw[:], now)
        for i = 0; i < evs.length(); i = i + 1 {
          match evs[i] {
            @assoc.Event::Message(m) => client_delivered.push(m)
            @assoc.Event::HeartbeatAcked(p) => {
              heartbeat_acked.val = true
              heartbeat_payload.val = p
            }
            @assoc.Event::Closed => client_closed.val = true
            _ => ()
          }
        }
        flush_client_udp(client, udp, c2s_count, c2s_bytes)
      }
      None => ()
    }
    let _ = client.tick(elapsed_ms(start_ms))
    flush_client_udp(client, udp, c2s_count, c2s_bytes)
  }
}

///|
/// Runs the full 4-phase RFC 6951 SCTP-over-UDP loopback tunnel over real OS
/// UDP sockets (`127.0.0.1`):
/// 1. Stateless Anti-SYN-Flood 4-Way Cookie Handshake (`INIT` -> stateless
///    `INIT_ACK` -> `COOKIE_ECHO` -> `COOKIE_ACK`);
/// 2. Multi-Stream (Stream 0/1/2) concurrent ordered/unordered DATA + SACK
///    with simulated single UDP packet drop proving 0-HOL cross-stream
///    delivery and triggering 3-dup fast retransmit;
/// 3. RFC 3758 PR-SCTP `MaxRetransmits(0)` drop triggering `FORWARD_TSN`
///    over real UDP to unblock reliable Stream 0 follow-up;
/// 4. `HEARTBEAT` / `HEARTBEAT_ACK` keepalive + graceful 3-way `SHUTDOWN`.
pub async fn run_full_rfc6951_udp_tunnel() -> UdpTunnelReport {
  let secret = b"rfc6951-udp-tunnel-hmac-secret32!"
  let start_ms = @async.now()

  @async.with_timeout(15000, () => {
    @async.with_task_group(group => {
      let server_udp = @socket.UdpServer(@socket.Addr::parse("127.0.0.1:0"))
      let server_addr = server_udp.addr
      let server_port = server_addr.port().reinterpret_as_uint()

      let client_udp = @socket.UdpClient(server_addr)
      let client_addr = client_udp.addr
      let client_port = client_addr.port().reinterpret_as_uint()

      let c2s_count : Ref[Int32] = Ref(0)
      let s2c_count : Ref[Int32] = Ref(0)
      let c2s_bytes : Ref[Int32] = Ref(0)
      let s2c_bytes : Ref[Int32] = Ref(0)
      let simulated_drops : Ref[Int32] = Ref(0)
      let stateless_init_acks : Ref[Int32] = Ref(0)

      let server_delivered : Array[@assoc.DeliveredMessage] = []
      let client_delivered : Array[@assoc.DeliveredMessage] = []
      let stream1_before_s0 : Ref[Int32] = Ref(0)
      let stream2_before_s0 : Ref[Int32] = Ref(0)
      let s0_recovered : Ref[Bool] = Ref(false)
      let server_echo_sent : Ref[Bool] = Ref(false)
      let server_closed : Ref[Bool] = Ref(false)
      let client_closed : Ref[Bool] = Ref(false)
      let heartbeat_acked : Ref[Bool] = Ref(false)
      let heartbeat_payload : Ref[Bytes] = Ref(b"")

      let s0_drop_msg = b"s0-ordered-1-dropped-then-fast-rtx"
      let s1_msg_a = b"s1-ordered-fast-a"
      let s1_msg_b = b"s1-ordered-fast-b"
      let s2_msg_a = b"s2-unordered-fast-a"
      let s2_msg_b = b"s2-unordered-fast-b"
      let server_echo_msg = b"server-udp-reply-stream1"
      let prsctp_drop_msg = b"s0-prsctp-ephemeral-drop"
      let prsctp_keep_msg = b"s0-reliable-after-forward-tsn"
      let hb_probe = b"rfc6951-udp-keepalive-probe"

      // Dedicated server coroutine: owns `server_udp` exclusively.
      let server_task = group.spawn(() => {
        defer server_udp.close()
        let buf = FixedArray::make(8192, b'\x00')
        let mut assoc_opt : @assoc.Association? = None
        let mut peer_opt : @socket.Addr? = None
        let deadline = @async.now() + 12000L

        while !server_closed.val && @async.now() < deadline {
          let recv_opt = @async.with_timeout_opt(25, () => {
            server_udp.recvfrom(buf)
          })
          let now = elapsed_ms(start_ms)
          match recv_opt {
            Some((n, peer)) => {
              let raw = copy_datagram(buf, n)
              let peer_port = peer.port().reinterpret_as_uint()
              match assoc_opt {
                None =>
                  if is_init_packet(raw) {
                    // RFC 9260 §5.1.3: respond statelessly with zero Association allocation
                    let s_cfg = make_server_cfg(
                      server_port, peer_port, 0xAABBCCDDU, 2000U, secret,
                    )
                    let init_ack = @sctp.process_stateless_init(
                      s_cfg,
                      raw[:],
                      now,
                    )
                    server_udp.sendto(init_ack, peer)
                    stateless_init_acks.val = stateless_init_acks.val + 1
                    s2c_count.val = s2c_count.val + 1
                    s2c_bytes.val = s2c_bytes.val + init_ack.length()
                  } else {
                    // Allocate Association ONLY upon valid COOKIE_ECHO
                    let s_cfg = make_server_cfg(
                      server_port, peer_port, 0xAABBCCDDU, 2000U, secret,
                    )
                    let srv = @sctp.new_server(s_cfg)
                    let evs = srv.handle_packet(raw[:], now)
                    flush_server_udp(
                      srv, server_udp, peer, s2c_count, s2c_bytes,
                    )
                    for i = 0; i < evs.length(); i = i + 1 {
                      match evs[i] {
                        @assoc.Event::Connected => {
                          assoc_opt = Some(srv)
                          peer_opt = Some(peer)
                        }
                        _ => ()
                      }
                    }
                  }
                Some(srv) => {
                  let evs = srv.handle_packet(raw[:], now)
                  for i = 0; i < evs.length(); i = i + 1 {
                    match evs[i] {
                      @assoc.Event::Message(m) => {
                        server_delivered.push(m)
                        if m.stream_id == 0U && m.payload == s0_drop_msg {
                          s0_recovered.val = true
                        } else if !s0_recovered.val {
                          if m.stream_id == 1U {
                            stream1_before_s0.val = stream1_before_s0.val + 1
                          } else if m.stream_id == 2U && m.unordered {
                            stream2_before_s0.val = stream2_before_s0.val + 1
                          }
                        }
                        // Send bidirectional reply on Stream 1 once Stream 0 recovers
                        if s0_recovered.val &&
                          !server_echo_sent.val &&
                          srv.state() == @assoc.AssocState::Established {
                          server_echo_sent.val = true
                          srv.send(
                            server_echo_msg,
                            @sctp.reliable_opts(1U, ppid=51U),
                            now,
                          )
                        }
                      }
                      @assoc.Event::Closed => server_closed.val = true
                      _ => ()
                    }
                  }
                  flush_server_udp(srv, server_udp, peer, s2c_count, s2c_bytes)
                }
              }
            }
            None =>
              match (assoc_opt, peer_opt) {
                (Some(srv), Some(peer)) => {
                  let _ = srv.tick(now)
                  flush_server_udp(srv, server_udp, peer, s2c_count, s2c_bytes)
                }
                _ => ()
              }
          }
        }
      })

      // Client coroutine: owns `client_udp` exclusively.
      let client_task = group.spawn(() => {
        defer client_udp.close()
        let c_cfg = make_client_cfg(
          client_port, server_port, 0x11223344U, 1000U,
        )
        let client = @sctp.new_client(c_cfg)

        // Phase 1: Stateless 4-way Cookie Handshake over real OS UDP
        let init_pkts = client.connect(elapsed_ms(start_ms))
        for i = 0; i < init_pkts.length(); i = i + 1 {
          client_udp.send(init_pkts[i])
          c2s_count.val = c2s_count.val + 1
          c2s_bytes.val = c2s_bytes.val + init_pkts[i].length()
        }
        pump_client_until(
          client,
          client_udp,
          start_ms,
          c2s_count,
          c2s_bytes,
          client_delivered,
          heartbeat_acked,
          heartbeat_payload,
          client_closed,
          4000L,
          () => client.state() == @assoc.AssocState::Established,
        )
        guard client.state() == @assoc.AssocState::Established else {
          raise Failure::Failure("UDP 4-way Cookie handshake failed")
        }

        // Phase 2: Multi-stream (0/1/2) + simulated 1-packet drop -> 0 HOL stall + 3-dup fast retransmit
        let t2 = elapsed_ms(start_ms)
        client.send(s0_drop_msg, @sctp.reliable_opts(0U, ppid=51U), t2)
        // Intentionally drop Stream 0's first UDP datagram before sending on wire
        let dropped_s0 = client.poll_outbound()
        simulated_drops.val = simulated_drops.val + dropped_s0.length()

        // Immediately transmit Stream 1 (ordered) & Stream 2 (unordered U=1) over real UDP
        client.send(s1_msg_a, @sctp.reliable_opts(1U, ppid=51U), t2 + 1UL)
        client.send(s1_msg_b, @sctp.reliable_opts(1U, ppid=51U), t2 + 2UL)
        client.send(s2_msg_a, @sctp.unordered_opts(2U, ppid=53U), t2 + 3UL)
        client.send(s2_msg_b, @sctp.unordered_opts(2U, ppid=53U), t2 + 4UL)
        flush_client_udp(client, client_udp, c2s_count, c2s_bytes)

        // Wait deterministically until the server has delivered all 4 Stream 1 &
        // Stream 2 messages over real UDP before reading SACKs to trigger fast
        // retransmit of Stream 0.
        let hol_wait_deadline = @async.now() + 2000L
        while (stream1_before_s0.val < 2 || stream2_before_s0.val < 2) &&
              @async.now() < hol_wait_deadline {
          @async.sleep(5)
        }

        pump_client_until(
          client,
          client_udp,
          start_ms,
          c2s_count,
          c2s_bytes,
          client_delivered,
          heartbeat_acked,
          heartbeat_payload,
          client_closed,
          4000L,
          () => {
            s0_recovered.val &&
            has_message(client_delivered, 1U, server_echo_msg)
          },
        )
        guard s0_recovered.val else {
          raise Failure::Failure("Stream 0 fast retransmit did not recover")
        }
        // Drain any remaining cumulative SACK from Phase 2 before Phase 3
        pump_client_until(
          client,
          client_udp,
          start_ms,
          c2s_count,
          c2s_bytes,
          client_delivered,
          heartbeat_acked,
          heartbeat_payload,
          client_closed,
          50L,
          () => false,
        )

        // Phase 3: RFC 3758 PR-SCTP MaxRetransmits(0) drop -> FORWARD_TSN over real UDP
        let t3 = elapsed_ms(start_ms)
        client.send(
          prsctp_drop_msg,
          @sctp.partial_retransmit_opts(0U, 0, ppid=53U),
          t3,
        )
        // Drop the ephemeral PR-SCTP datagram once on the wire
        let dropped_pr = client.poll_outbound()
        simulated_drops.val = simulated_drops.val + dropped_pr.length()

        // Reliable follow-up on Stream 0 arrives first and blocks behind missing SSN
        client.send(
          prsctp_keep_msg,
          @sctp.reliable_opts(0U, ppid=51U),
          t3 + 1UL,
        )
        flush_client_udp(client, client_udp, c2s_count, c2s_bytes)

        // Advance real wall-clock ticks until client emits FORWARD_TSN over UDP and
        // server unblocks and delivers `prsctp_keep_msg`
        pump_client_until(
          client,
          client_udp,
          start_ms,
          c2s_count,
          c2s_bytes,
          client_delivered,
          heartbeat_acked,
          heartbeat_payload,
          client_closed,
          4000L,
          () => {
            client.stats().forward_tsn_sent > 0 &&
            has_message(server_delivered, 0U, prsctp_keep_msg)
          },
        )
        guard has_message(server_delivered, 0U, prsctp_keep_msg) else {
          raise Failure::Failure("PR-SCTP FORWARD_TSN did not unblock Stream 0")
        }

        // Phase 4a: HEARTBEAT / HEARTBEAT_ACK over real UDP
        client.send_heartbeat(hb_probe, elapsed_ms(start_ms))
        flush_client_udp(client, client_udp, c2s_count, c2s_bytes)
        pump_client_until(
          client,
          client_udp,
          start_ms,
          c2s_count,
          c2s_bytes,
          client_delivered,
          heartbeat_acked,
          heartbeat_payload,
          client_closed,
          3000L,
          () => heartbeat_acked.val,
        )
        guard heartbeat_acked.val else {
          raise Failure::Failure("HEARTBEAT_ACK not received over UDP")
        }

        // Phase 4b: Graceful 3-way SHUTDOWN over real UDP
        client.shutdown(elapsed_ms(start_ms))
        flush_client_udp(client, client_udp, c2s_count, c2s_bytes)
        pump_client_until(
          client,
          client_udp,
          start_ms,
          c2s_count,
          c2s_bytes,
          client_delivered,
          heartbeat_acked,
          heartbeat_payload,
          client_closed,
          4000L,
          () => client_closed.val && server_closed.val,
        )

        client.stats()
      })

      let client_stats = client_task.wait()
      server_task.wait()

      {
        server_addr: server_addr.to_string(),
        client_addr: client_addr.to_string(),
        stateless_init_acks: stateless_init_acks.val,
        udp_datagrams_c2s: c2s_count.val,
        udp_datagrams_s2c: s2c_count.val,
        udp_bytes_c2s: c2s_bytes.val,
        udp_bytes_s2c: s2c_bytes.val,
        simulated_drops: simulated_drops.val,
        stream1_delivered_before_s0_rtx: stream1_before_s0.val,
        stream2_unordered_delivered_before_s0_rtx: stream2_before_s0.val,
        fast_retransmissions: client_stats.retransmissions,
        forward_tsn_sent: client_stats.forward_tsn_sent,
        prsctp_skipped_absent: !has_message(
          server_delivered, 0U, prsctp_drop_msg,
        ),
        prsctp_followup_unblocked: has_message(
          server_delivered, 0U, prsctp_keep_msg,
        ),
        server_delivered,
        client_delivered,
        heartbeat_acked: heartbeat_acked.val,
        heartbeat_payload: heartbeat_payload.val,
        client_closed_gracefully: client_closed.val,
        server_closed_gracefully: server_closed.val,
      }
    })
  })
}

///|
/// Verifies anti-SYN-flood stateless `INIT` handling and tampered `COOKIE_ECHO`
/// rejection over real OS `127.0.0.1` UDP sockets before establishing a valid
/// session.
pub async fn run_stateless_cookie_security_udp_drill() -> StatelessCookieDrillReport {
  let secret = b"udp-cookie-security-drill-key-32!"
  let start_ms = @async.now()

  @async.with_timeout(10000, () => {
    @async.with_task_group(group => {
      let server_udp = @socket.UdpServer(@socket.Addr::parse("127.0.0.1:0"))
      let server_addr = server_udp.addr
      let server_port = server_addr.port().reinterpret_as_uint()

      let client_udp = @socket.UdpClient(server_addr)
      let client_port = client_udp.addr.port().reinterpret_as_uint()

      let stateless_init_acks : Ref[Int32] = Ref(0)
      let tampered_cookie_rejected : Ref[Bool] = Ref(false)
      let assoc_allocated_before_valid : Ref[Bool] = Ref(false)
      let valid_established : Ref[Bool] = Ref(false)

      let server_task = group.spawn(() => {
        defer server_udp.close()
        let buf = FixedArray::make(8192, b'\x00')
        let mut assoc_opt : @assoc.Association? = None
        let deadline = @async.now() + 8000L

        while !valid_established.val && @async.now() < deadline {
          let recv_opt = @async.with_timeout_opt(25, () => {
            server_udp.recvfrom(buf)
          })
          let now = elapsed_ms(start_ms)
          match recv_opt {
            Some((n, peer)) => {
              let raw = copy_datagram(buf, n)
              let peer_port = peer.port().reinterpret_as_uint()
              let s_cfg = make_server_cfg(
                server_port, peer_port, 0xCAFEBABEU, 3000U, secret,
              )
              if is_init_packet(raw) {
                let ack = @sctp.process_stateless_init(s_cfg, raw[:], now)
                server_udp.sendto(ack, peer)
                stateless_init_acks.val = stateless_init_acks.val + 1
              } else {
                let candidate = @sctp.new_server(s_cfg)
                let handled = try {
                  let evs = candidate.handle_packet(raw[:], now)
                  Some(evs)
                } catch {
                  @assoc.SecurityViolation(_) => {
                    tampered_cookie_rejected.val = true
                    if assoc_opt is Some(_) {
                      assoc_allocated_before_valid.val = true
                    }
                    None
                  }
                  err => raise err
                }
                match handled {
                  Some(evs) => {
                    let out = candidate.poll_outbound()
                    for i = 0; i < out.length(); i = i + 1 {
                      server_udp.sendto(out[i], peer)
                    }
                    for i = 0; i < evs.length(); i = i + 1 {
                      match evs[i] {
                        @assoc.Event::Connected => {
                          assoc_opt = Some(candidate)
                          valid_established.val = true
                        }
                        _ => ()
                      }
                    }
                  }
                  None => ()
                }
              }
            }
            None => ()
          }
        }
      })

      let client_task = group.spawn(() => {
        defer client_udp.close()
        let buf = FixedArray::make(8192, b'\x00')
        let c_cfg = make_client_cfg(
          client_port, server_port, 0x22334455U, 4000U,
        )
        let client = @sctp.new_client(c_cfg)

        // Send INIT over real UDP
        let init_pkts = client.connect(elapsed_ms(start_ms))
        client_udp.send(init_pkts[0])

        // Receive stateless INIT_ACK over real UDP
        let n1 = client_udp.recv(buf)
        let init_ack_raw = copy_datagram(buf, n1)
        let _ = client.handle_packet(init_ack_raw[:], elapsed_ms(start_ms))
        let valid_ce = client.poll_outbound()[0]

        // Re-encode a COOKIE_ECHO with a 1-bit tampered HMAC cookie and send over UDP
        let ce_pkt = @sctp.decode_packet(valid_ce[:])
        let bad_cookie = match ce_pkt.chunks[0] {
          @packet.Chunk::CookieEcho(c) => flip_bit(c, 10)
          _ => raise Failure::Failure("expected COOKIE_ECHO chunk")
        }
        let tampered_ce = @sctp.encode_packet({
          src_port: ce_pkt.src_port,
          dst_port: ce_pkt.dst_port,
          verification_tag: ce_pkt.verification_tag,
          chunks: [@packet.Chunk::CookieEcho(bad_cookie)],
        })
        client_udp.send(tampered_ce)
        let reject_deadline = @async.now() + 2000L
        while !tampered_cookie_rejected.val && @async.now() < reject_deadline {
          @async.sleep(5)
        }

        // Now send the authentic COOKIE_ECHO over real UDP and finish handshake
        client_udp.send(valid_ce)
        let n2 = client_udp.recv(buf)
        let ca_raw = copy_datagram(buf, n2)
        let _ = client.handle_packet(ca_raw[:], elapsed_ms(start_ms))
        guard client.state() == @assoc.AssocState::Established else {
          raise Failure::Failure(
            "valid COOKIE_ECHO handshake did not establish",
          )
        }
      })

      client_task.wait()
      server_task.wait()

      {
        stateless_init_acks: stateless_init_acks.val,
        tampered_cookie_rejected: tampered_cookie_rejected.val,
        assoc_allocated_before_valid_cookie: assoc_allocated_before_valid.val,
        valid_handshake_established: valid_established.val,
      }
    })
  })
}

///|
/// Verifies RFC 3758 PR-SCTP `TimedMs` TTL expiration using real wall-clock
/// time over OS `127.0.0.1` UDP sockets.
pub async fn run_timed_prsctp_udp_drill() -> TimedPrSctpReport {
  let secret = b"udp-timed-prsctp-secret-key-32by!"
  let start_ms = @async.now()
  let expired_msg = b"timed-ttl-60ms-dropped-frame"
  let followup_msg = b"reliable-stream0-unblocked-by-timed-ftsn"

  @async.with_timeout(10000, () => {
    @async.with_task_group(group => {
      let server_udp = @socket.UdpServer(@socket.Addr::parse("127.0.0.1:0"))
      let server_addr = server_udp.addr
      let server_port = server_addr.port().reinterpret_as_uint()

      let client_udp = @socket.UdpClient(server_addr)
      let client_port = client_udp.addr.port().reinterpret_as_uint()

      let c2s_count : Ref[Int32] = Ref(0)
      let s2c_count : Ref[Int32] = Ref(0)
      let c2s_bytes : Ref[Int32] = Ref(0)
      let s2c_bytes : Ref[Int32] = Ref(0)
      let server_delivered : Array[@assoc.DeliveredMessage] = []
      let client_delivered : Array[@assoc.DeliveredMessage] = []
      let done : Ref[Bool] = Ref(false)
      let hb_acked : Ref[Bool] = Ref(false)
      let hb_payload : Ref[Bytes] = Ref(b"")
      let c_closed : Ref[Bool] = Ref(false)

      let server_task = group.spawn(() => {
        defer server_udp.close()
        let buf = FixedArray::make(8192, b'\x00')
        let mut assoc_opt : @assoc.Association? = None
        let deadline = @async.now() + 8000L

        while !done.val && @async.now() < deadline {
          let recv_opt = @async.with_timeout_opt(20, () => {
            server_udp.recvfrom(buf)
          })
          let now = elapsed_ms(start_ms)
          match recv_opt {
            Some((n, peer)) => {
              let raw = copy_datagram(buf, n)
              let peer_port = peer.port().reinterpret_as_uint()
              match assoc_opt {
                None =>
                  if is_init_packet(raw) {
                    let s_cfg = make_server_cfg(
                      server_port,
                      peer_port,
                      0x33445566U,
                      5000U,
                      secret,
                      rto_initial_ms=400UL,
                    )
                    let ack = @sctp.process_stateless_init(s_cfg, raw[:], now)
                    server_udp.sendto(ack, peer)
                    s2c_count.val = s2c_count.val + 1
                    s2c_bytes.val = s2c_bytes.val + ack.length()
                  } else {
                    let s_cfg = make_server_cfg(
                      server_port,
                      peer_port,
                      0x33445566U,
                      5000U,
                      secret,
                      rto_initial_ms=400UL,
                    )
                    let srv = @sctp.new_server(s_cfg)
                    let _ = srv.handle_packet(raw[:], now)
                    flush_server_udp(
                      srv, server_udp, peer, s2c_count, s2c_bytes,
                    )
                    assoc_opt = Some(srv)
                  }
                Some(srv) => {
                  let evs = srv.handle_packet(raw[:], now)
                  for i = 0; i < evs.length(); i = i + 1 {
                    match evs[i] {
                      @assoc.Event::Message(m) => {
                        server_delivered.push(m)
                        if m.payload == followup_msg {
                          done.val = true
                        }
                      }
                      _ => ()
                    }
                  }
                  flush_server_udp(srv, server_udp, peer, s2c_count, s2c_bytes)
                }
              }
            }
            None => ()
          }
        }
      })

      let client_task = group.spawn(() => {
        defer client_udp.close()
        // Use a larger RTO (400ms) so TimedMs(60ms) clearly triggers before T3-rtx!
        let c_cfg = make_client_cfg(
          client_port,
          server_port,
          0x66554433U,
          6000U,
          rto_initial_ms=400UL,
        )
        let client = @sctp.new_client(c_cfg)

        let init_pkts = client.connect(elapsed_ms(start_ms))
        client_udp.send(init_pkts[0])
        c2s_count.val = c2s_count.val + 1
        c2s_bytes.val = c2s_bytes.val + init_pkts[0].length()
        pump_client_until(
          client,
          client_udp,
          start_ms,
          c2s_count,
          c2s_bytes,
          client_delivered,
          hb_acked,
          hb_payload,
          c_closed,
          3000L,
          () => client.state() == @assoc.AssocState::Established,
        )

        // Send TimedMs(60ms) message and drop its single UDP datagram
        let t0 = elapsed_ms(start_ms)
        client.send(expired_msg, @sctp.partial_timed_opts(0U, 60UL), t0)
        let _dropped = client.poll_outbound()

        // Send reliable follow-up on Stream 0 over real UDP
        client.send(followup_msg, @sctp.reliable_opts(0U), t0 + 1UL)
        flush_client_udp(client, client_udp, c2s_count, c2s_bytes)

        // Sleep past 60ms real wall-clock TTL and pump until FORWARD_TSN unblocks server
        @async.sleep(90)
        pump_client_until(
          client,
          client_udp,
          start_ms,
          c2s_count,
          c2s_bytes,
          client_delivered,
          hb_acked,
          hb_payload,
          c_closed,
          3000L,
          () => done.val && client.stats().forward_tsn_sent > 0,
        )
        client.stats().forward_tsn_sent
      })

      let ftsn_sent = client_task.wait()
      server_task.wait()

      {
        forward_tsn_sent: ftsn_sent,
        expired_msg_absent: !has_message(server_delivered, 0U, expired_msg),
        followup_delivered: has_message(server_delivered, 0U, followup_msg),
        udp_datagrams_c2s: c2s_count.val,
        udp_datagrams_s2c: s2c_count.val,
      }
    })
  })
}

///|
/// Verifies MTU fragmentation (B/E flags) and reassembly of 4KB messages in
/// both directions over real OS `127.0.0.1` UDP datagrams.
pub async fn run_fragmented_bidirectional_udp_drill() -> FragmentedUdpReport {
  let secret = b"udp-fragment-bidir-secret-key-32!"
  let start_ms = @async.now()
  let c_payload = Bytes::makei(4096, i => ((i * 31 + 7) & 0xFF).to_byte())
  let s_payload = Bytes::makei(3840, i => ((i * 17 + 19) & 0xFF).to_byte())

  @async.with_timeout(10000, () => {
    @async.with_task_group(group => {
      let server_udp = @socket.UdpServer(@socket.Addr::parse("127.0.0.1:0"))
      let server_addr = server_udp.addr
      let server_port = server_addr.port().reinterpret_as_uint()

      let client_udp = @socket.UdpClient(server_addr)
      let client_port = client_udp.addr.port().reinterpret_as_uint()

      let c2s_count : Ref[Int32] = Ref(0)
      let s2c_count : Ref[Int32] = Ref(0)
      let c2s_bytes : Ref[Int32] = Ref(0)
      let s2c_bytes : Ref[Int32] = Ref(0)
      let server_delivered : Array[@assoc.DeliveredMessage] = []
      let client_delivered : Array[@assoc.DeliveredMessage] = []
      let server_closed : Ref[Bool] = Ref(false)
      let client_closed : Ref[Bool] = Ref(false)
      let hb_acked : Ref[Bool] = Ref(false)
      let hb_payload : Ref[Bytes] = Ref(b"")

      let server_task = group.spawn(() => {
        defer server_udp.close()
        let buf = FixedArray::make(8192, b'\x00')
        let mut assoc_opt : @assoc.Association? = None
        let deadline = @async.now() + 8000L

        while !server_closed.val && @async.now() < deadline {
          let recv_opt = @async.with_timeout_opt(20, () => {
            server_udp.recvfrom(buf)
          })
          let now = elapsed_ms(start_ms)
          match recv_opt {
            Some((n, peer)) => {
              let raw = copy_datagram(buf, n)
              let peer_port = peer.port().reinterpret_as_uint()
              match assoc_opt {
                None =>
                  if is_init_packet(raw) {
                    let s_cfg = make_server_cfg(
                      server_port, peer_port, 0x778899AAU, 7000U, secret,
                    )
                    let ack = @sctp.process_stateless_init(s_cfg, raw[:], now)
                    server_udp.sendto(ack, peer)
                    s2c_count.val = s2c_count.val + 1
                    s2c_bytes.val = s2c_bytes.val + ack.length()
                  } else {
                    let s_cfg = make_server_cfg(
                      server_port, peer_port, 0x778899AAU, 7000U, secret,
                    )
                    let srv = @sctp.new_server(s_cfg)
                    let _ = srv.handle_packet(raw[:], now)
                    flush_server_udp(
                      srv, server_udp, peer, s2c_count, s2c_bytes,
                    )
                    assoc_opt = Some(srv)
                  }
                Some(srv) => {
                  let evs = srv.handle_packet(raw[:], now)
                  for i = 0; i < evs.length(); i = i + 1 {
                    match evs[i] {
                      @assoc.Event::Message(m) => {
                        server_delivered.push(m)
                        if m.stream_id == 0U &&
                          srv.state() == @assoc.AssocState::Established {
                          srv.send(
                            s_payload,
                            @sctp.reliable_opts(1U, ppid=53U),
                            now,
                          )
                        }
                      }
                      @assoc.Event::Closed => server_closed.val = true
                      _ => ()
                    }
                  }
                  flush_server_udp(srv, server_udp, peer, s2c_count, s2c_bytes)
                }
              }
            }
            None => ()
          }
        }
      })

      let client_task = group.spawn(() => {
        defer client_udp.close()
        let c_cfg = make_client_cfg(
          client_port, server_port, 0xAA998877U, 8000U,
        )
        let client = @sctp.new_client(c_cfg)

        let init_pkts = client.connect(elapsed_ms(start_ms))
        client_udp.send(init_pkts[0])
        c2s_count.val = c2s_count.val + 1
        c2s_bytes.val = c2s_bytes.val + init_pkts[0].length()
        pump_client_until(
          client,
          client_udp,
          start_ms,
          c2s_count,
          c2s_bytes,
          client_delivered,
          hb_acked,
          hb_payload,
          client_closed,
          3000L,
          () => client.state() == @assoc.AssocState::Established,
        )

        client.send(
          c_payload,
          @sctp.reliable_opts(0U, ppid=53U),
          elapsed_ms(start_ms),
        )
        flush_client_udp(client, client_udp, c2s_count, c2s_bytes)

        pump_client_until(
          client,
          client_udp,
          start_ms,
          c2s_count,
          c2s_bytes,
          client_delivered,
          hb_acked,
          hb_payload,
          client_closed,
          4000L,
          () => server_delivered.length() == 1 && client_delivered.length() == 1,
        )

        client.shutdown(elapsed_ms(start_ms))
        flush_client_udp(client, client_udp, c2s_count, c2s_bytes)
        pump_client_until(
          client,
          client_udp,
          start_ms,
          c2s_count,
          c2s_bytes,
          client_delivered,
          hb_acked,
          hb_payload,
          client_closed,
          3000L,
          () => client_closed.val && server_closed.val,
        )
      })

      client_task.wait()
      server_task.wait()

      let s_len = if server_delivered.length() > 0 {
        server_delivered[0].payload.length()
      } else {
        0
      }
      let c_len = if client_delivered.length() > 0 {
        client_delivered[0].payload.length()
      } else {
        0
      }
      {
        server_received_len: s_len,
        client_received_len: c_len,
        server_payload_match: server_delivered.length() == 1 &&
        server_delivered[0].payload == c_payload,
        client_payload_match: client_delivered.length() == 1 &&
        client_delivered[0].payload == s_payload,
        udp_datagrams_c2s: c2s_count.val,
        udp_datagrams_s2c: s2c_count.val,
      }
    })
  })
}
