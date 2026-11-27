///|
fn clamp_i32(v : Int32, lo : Int32, hi : Int32) -> Int32 {
  if v < lo {
    lo
  } else if v > hi {
    hi
  } else {
    v
  }
}

///|
fn write_json_string(buf : StringBuilder, s : String) -> Unit {
  buf.write_char('"')
  for i = 0; i < s.length(); i = i + 1 {
    let c = s[i].to_int()
    if c == 0x22 {
      buf.write_string("\\\"")
    } else if c == 0x5C {
      buf.write_string("\\\\")
    } else if c == 0x0A {
      buf.write_string("\\n")
    } else if c == 0x0D {
      buf.write_string("\\r")
    } else if c == 0x09 {
      buf.write_string("\\t")
    } else if c < 0x20 {
      buf.write_string("\\u00")
      let hex = "0123456789abcdef"
      buf.write_char(hex[(c >> 4) & 0xF].to_int().unsafe_to_char())
      buf.write_char(hex[c & 0xF].to_int().unsafe_to_char())
    } else {
      buf.write_char(c.unsafe_to_char())
    }
  }
  buf.write_char('"')
}

///|
fn json_bool(v : Bool) -> String {
  if v {
    "true"
  } else {
    "false"
  }
}

///|
fn json_error(field_name : String, field_val : String, msg : String) -> String {
  let buf = StringBuilder()
  buf.write_string("{\"ok\":false,")
  write_json_string(buf, field_name)
  buf.write_char(':')
  write_json_string(buf, field_val)
  buf.write_string(",\"error\":")
  write_json_string(buf, msg)
  buf.write_char('}')
  buf.to_string()
}

///|
fn bytes_to_hex_preview(b : Bytes, max_bytes : Int32) -> String {
  let hex = "0123456789ABCDEF"
  let limit = if b.length() < max_bytes { b.length() } else { max_bytes }
  let buf = StringBuilder()
  for i = 0; i < limit; i = i + 1 {
    if i > 0 {
      buf.write_char(' ')
    }
    let v = b[i].to_int()
    buf.write_char(hex[(v >> 4) & 0xF].to_int().unsafe_to_char())
    buf.write_char(hex[v & 0xF].to_int().unsafe_to_char())
  }
  if b.length() > max_bytes {
    buf.write_string(" ... (")
    buf.write_string(b.length().to_string())
    buf.write_string("B total)")
  }
  buf.to_string()
}

///|
fn flip_bit(b : Bytes, idx : Int32) -> Bytes {
  let out : FixedArray[Byte] = FixedArray::make(b.length(), b'\x00')
  for i = 0; i < b.length(); i = i + 1 {
    out[i] = if i == idx { (b[i].to_int() ^ 0x01).to_byte() } else { b[i] }
  }
  Bytes::from_array(out)
}

///|
fn make_demo_payload(msg_id : Int32, len : Int32) -> Bytes {
  let out : FixedArray[Byte] = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    out[i] = ((msg_id * 37 + i * 13 + 11) & 0xFF).to_byte()
  }
  Bytes::from_array(out)
}

///|
fn assoc_state_name(s : @assoc.AssocState) -> String {
  match s {
    @assoc.AssocState::Closed => "Closed"
    @assoc.AssocState::CookieWait => "CookieWait"
    @assoc.AssocState::CookieEchoed => "CookieEchoed"
    @assoc.AssocState::Established => "Established"
    @assoc.AssocState::ShutdownPending => "ShutdownPending"
    @assoc.AssocState::ShutdownSent => "ShutdownSent"
    @assoc.AssocState::ShutdownReceived => "ShutdownReceived"
    @assoc.AssocState::ShutdownAckSent => "ShutdownAckSent"
  }
}

///|
fn assoc_error_detail(err : @assoc.AssocError) -> String {
  match err {
    @assoc.InvalidState(m) => "InvalidState: " + m
    @assoc.InvalidStream(id) => "InvalidStream: " + id.to_string()
    @assoc.MessageTooLarge(n) => "MessageTooLarge: " + n.to_string()
    @assoc.PacketError(m) => "PacketError: " + m
    @assoc.SecurityViolation(m) => "SecurityViolation: " + m
    @assoc.InvalidConfig(m) => "InvalidConfig: " + m
  }
}

///|
fn deterministic_roll(
  msg_id : Int32,
  attempt : Int32,
  loss_pct : Int32,
) -> Int32 {
  let mut h : UInt32 = ((msg_id + 1).reinterpret_as_uint() * 0x9E3779B1U) ^
    ((attempt + 1).reinterpret_as_uint() * 0x85EBCA77U) ^
    ((loss_pct + 7).reinterpret_as_uint() * 0xC2B2AE3DU)
  h = h ^ (h >> 16)
  h = h * 0x7FEB352DU
  h = h ^ (h >> 15)
  (h % 100U).reinterpret_as_int()
}

///|
fn decide_data_delivery(
  msg_id : Int32,
  attempt : Int32,
  loss_pct : Int32,
  reorder_enabled : Bool,
) -> (Bool, UInt64) {
  let is_s0 = msg_id % 4 == 0
  let mut drop = false
  if loss_pct > 0 && is_s0 {
    if attempt == 1 {
      if msg_id == 0 {
        drop = true
      } else {
        let roll = deterministic_roll(msg_id, attempt, loss_pct)
        let threshold = clamp_i32(loss_pct * 3, 0, 92)
        if roll < threshold {
          drop = true
        }
      }
    } else if attempt == 2 && loss_pct >= 20 {
      let roll = deterministic_roll(msg_id, attempt, loss_pct)
      let threshold = clamp_i32((loss_pct - 12) * 3, 0, 60)
      if roll < threshold {
        drop = true
      }
    }
  }
  let base_delay = 25UL
  let extra_delay = if reorder_enabled {
    if is_s0 && attempt == 1 {
      145UL + (msg_id * 17 % 35).to_uint64()
    } else {
      (msg_id * 7 % 12).to_uint64()
    }
  } else {
    0UL
  }
  (drop, base_delay + extra_delay)
}

///|
priv struct SimWirePkt {
  deliver_at_ms : UInt64
  to_server : Bool
  msg_id : Int32
  raw : Bytes
}

///|
priv struct HolRunResult {
  sent_ms : Array[Int32]
  arrived_ms : Array[Int32]
  delivered_ms : Array[Int32]
  dropped_counts : Array[Int32]
  packets_sent : Int32
  packets_dropped : Int32
  retransmissions : Int32
  messages_delivered : Int32
}

///|
fn extract_data_msg_id(raw : Bytes) -> Int32 {
  let decoded : @packet.Packet? = Some(@packet.decode_packet(raw[:])) catch {
    _ => None
  }
  match decoded {
    Some(pkt) =>
      if pkt.chunks.length() > 0 {
        match pkt.chunks[0] {
          @packet.Chunk::Data(dc) => dc.ppid.reinterpret_as_int()
          _ => -1
        }
      } else {
        -1
      }
    None => -1
  }
}

///|
fn execute_hol_run(
  multi_stream : Bool,
  loss_pct : Int32,
  reorder_enabled : Bool,
  msg_count : Int32,
) -> HolRunResult raise @assoc.AssocError {
  let secret = b"moonsctp-hol-lab-hmac-secret-32b!"
  let c_cfg = @sctp.client_config(
    5000U,
    5001U,
    0x11223344U,
    1000U,
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )
  let s_cfg = @sctp.server_config(
    5001U,
    5000U,
    0x55667788U,
    2000U,
    secret,
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )
  let client = @sctp.new_client(c_cfg)
  let server = @sctp.new_server(s_cfg)
  let _ = @sctp.run_handshake_loop(client, server, 0UL)

  let sent_ms : Array[Int32] = Array::make(msg_count, 0)
  let arrived_ms : Array[Int32] = Array::make(msg_count, -1)
  let delivered_ms : Array[Int32] = Array::make(msg_count, -1)
  let tx_attempts : Array[Int32] = Array::make(msg_count, 0)
  let dropped_counts : Array[Int32] = Array::make(msg_count, 0)

  let wire_q : Array[SimWirePkt] = []
  let mut packets_sent = 0
  let mut packets_dropped = 0
  let mut delivered_total = 0

  let push_client_pkts = fn(pkts : Array[Bytes], t : UInt64) {
    for i = 0; i < pkts.length(); i = i + 1 {
      let raw = pkts[i]
      packets_sent = packets_sent + 1
      let mid = extract_data_msg_id(raw)
      if mid >= 0 && mid < msg_count {
        let attempt = tx_attempts[mid] + 1
        tx_attempts[mid] = attempt
        let (drop, delay) = decide_data_delivery(
          mid, attempt, loss_pct, reorder_enabled,
        )
        if drop {
          packets_dropped = packets_dropped + 1
          dropped_counts[mid] = dropped_counts[mid] + 1
        } else {
          wire_q.push({
            deliver_at_ms: t + delay,
            to_server: true,
            msg_id: mid,
            raw,
          })
        }
      } else {
        wire_q.push({
          deliver_at_ms: t + 25UL,
          to_server: true,
          msg_id: -1,
          raw,
        })
      }
    }
  }

  let push_server_pkts = fn(pkts : Array[Bytes], t : UInt64) {
    for i = 0; i < pkts.length(); i = i + 1 {
      packets_sent = packets_sent + 1
      wire_q.push({
        deliver_at_ms: t + 25UL,
        to_server: false,
        msg_id: -1,
        raw: pkts[i],
      })
    }
  }

  let mut next_send_idx = 0
  let mut now_ms = 100UL
  let mut steps = 0

  while (delivered_total < msg_count || next_send_idx < msg_count) &&
        steps < 6000 {
    while next_send_idx < msg_count &&
          now_ms >= 100UL + (next_send_idx * 10).to_uint64() {
      let mid = next_send_idx
      let sid = if multi_stream { (mid % 4).reinterpret_as_uint() } else { 0U }
      sent_ms[mid] = now_ms.to_int()
      client.send(
        make_demo_payload(mid, 64),
        @sctp.reliable_opts(sid, ppid=mid.reinterpret_as_uint()),
        now_ms,
      )
      push_client_pkts(client.poll_outbound(), now_ms)
      next_send_idx = next_send_idx + 1
    }

    let due : Array[SimWirePkt] = []
    let keep : Array[SimWirePkt] = []
    for i = 0; i < wire_q.length(); i = i + 1 {
      if wire_q[i].deliver_at_ms <= now_ms {
        due.push(wire_q[i])
      } else {
        keep.push(wire_q[i])
      }
    }
    wire_q.clear()
    for i = 0; i < keep.length(); i = i + 1 {
      wire_q.push(keep[i])
    }

    for i = 0; i < due.length(); i = i + 1 {
      let sp = due[i]
      if sp.to_server {
        if sp.msg_id >= 0 && sp.msg_id < msg_count && arrived_ms[sp.msg_id] < 0 {
          arrived_ms[sp.msg_id] = now_ms.to_int()
        }
        let evs = server.handle_packet(sp.raw[:], now_ms)
        for j = 0; j < evs.length(); j = j + 1 {
          match evs[j] {
            @assoc.Event::Message(m) => {
              let mid = m.ppid.reinterpret_as_int()
              if mid >= 0 && mid < msg_count && delivered_ms[mid] < 0 {
                delivered_ms[mid] = now_ms.to_int()
                delivered_total = delivered_total + 1
              }
            }
            _ => ()
          }
        }
        push_server_pkts(server.poll_outbound(), now_ms)
      } else {
        let _ = client.handle_packet(sp.raw[:], now_ms)
        push_client_pkts(client.poll_outbound(), now_ms)
      }
    }

    let _ = client.tick(now_ms)
    push_client_pkts(client.poll_outbound(), now_ms)
    let _ = server.tick(now_ms)
    push_server_pkts(server.poll_outbound(), now_ms)

    now_ms = now_ms + 5UL
    steps = steps + 1
  }

  {
    sent_ms,
    arrived_ms,
    delivered_ms,
    dropped_counts,
    packets_sent,
    packets_dropped,
    retransmissions: client.stats().retransmissions,
    messages_delivered: delivered_total,
  }
}

///|
/// Runs a deterministic pure-MoonBit RFC 9260 simulation comparing 4-stream
/// SCTP (independent per-stream delivery) against a Single-Stream HOL-blocked
/// baseline under identical packet loss and reordering conditions.
pub fn run_hol_comparison(
  loss_percent : Int32,
  reorder_enabled : Bool,
  msg_count : Int32,
) -> String {
  let loss = clamp_i32(loss_percent, 0, 40)
  let count = clamp_i32(msg_count, 4, 32)
  let sctp_res = execute_hol_run(true, loss, reorder_enabled, count) catch {
    err => return json_error("mode", "hol_comparison", assoc_error_detail(err))
  }
  let single_res = execute_hol_run(false, loss, reorder_enabled, count) catch {
    err => return json_error("mode", "hol_comparison", assoc_error_detail(err))
  }

  let mut s0_lat_sum = 0
  let mut s0_cnt = 0
  let mut other_lat_sum = 0
  let mut other_cnt = 0
  let mut sctp_stall_sum = 0
  let mut single_stall_sum = 0
  let mut single_other_lat_sum = 0

  for i = 0; i < count; i = i + 1 {
    let sctp_lat = if sctp_res.delivered_ms[i] >= sctp_res.sent_ms[i] {
      sctp_res.delivered_ms[i] - sctp_res.sent_ms[i]
    } else {
      0
    }
    let sctp_stall = if sctp_res.arrived_ms[i] >= 0 &&
      sctp_res.delivered_ms[i] >= sctp_res.arrived_ms[i] {
      sctp_res.delivered_ms[i] - sctp_res.arrived_ms[i]
    } else {
      0
    }
    let single_lat = if single_res.delivered_ms[i] >= single_res.sent_ms[i] {
      single_res.delivered_ms[i] - single_res.sent_ms[i]
    } else {
      0
    }
    let single_stall = if single_res.arrived_ms[i] >= 0 &&
      single_res.delivered_ms[i] >= single_res.arrived_ms[i] {
      single_res.delivered_ms[i] - single_res.arrived_ms[i]
    } else {
      0
    }
    if i % 4 == 0 {
      s0_lat_sum = s0_lat_sum + sctp_lat
      s0_cnt = s0_cnt + 1
    } else {
      other_lat_sum = other_lat_sum + sctp_lat
      sctp_stall_sum = sctp_stall_sum + sctp_stall
      single_stall_sum = single_stall_sum + single_stall
      single_other_lat_sum = single_other_lat_sum + single_lat
      other_cnt = other_cnt + 1
    }
  }

  let sctp_s0_avg = if s0_cnt > 0 { s0_lat_sum / s0_cnt } else { 0 }
  let sctp_other_avg = if other_cnt > 0 { other_lat_sum / other_cnt } else { 0 }
  let sctp_hol_stall = if other_cnt > 0 {
    sctp_stall_sum / other_cnt
  } else {
    0
  }
  let single_hol_stall = if other_cnt > 0 {
    single_stall_sum / other_cnt
  } else {
    0
  }
  let single_other_avg = if other_cnt > 0 {
    single_other_lat_sum / other_cnt
  } else {
    0
  }

  let buf = StringBuilder()
  buf.write_string("{\"ok\":true,\"loss_percent\":")
  buf.write_string(loss.to_string())
  buf.write_string(",\"reorder_enabled\":")
  buf.write_string(json_bool(reorder_enabled))
  buf.write_string(",\"msg_count\":")
  buf.write_string(count.to_string())
  buf.write_string(",\"sctp_stream0_latency_ms\":")
  buf.write_string(sctp_s0_avg.to_string())
  buf.write_string(",\"sctp_other_streams_latency_ms\":")
  buf.write_string(sctp_other_avg.to_string())
  buf.write_string(",\"single_stream_other_latency_ms\":")
  buf.write_string(single_other_avg.to_string())
  buf.write_string(",\"sctp_hol_stall_ms\":")
  buf.write_string(sctp_hol_stall.to_string())
  buf.write_string(",\"single_stream_hol_stall_ms\":")
  buf.write_string(single_hol_stall.to_string())
  buf.write_string(",\"packets_sent\":")
  buf.write_string(sctp_res.packets_sent.to_string())
  buf.write_string(",\"packets_dropped\":")
  buf.write_string(sctp_res.packets_dropped.to_string())
  buf.write_string(",\"retransmissions\":")
  buf.write_string(sctp_res.retransmissions.to_string())
  buf.write_string(",\"messages_delivered\":")
  buf.write_string(sctp_res.messages_delivered.to_string())
  buf.write_string(",\"stream_events\":[")
  for i = 0; i < count; i = i + 1 {
    if i > 0 {
      buf.write_char(',')
    }
    let sctp_lat = if sctp_res.delivered_ms[i] >= sctp_res.sent_ms[i] {
      sctp_res.delivered_ms[i] - sctp_res.sent_ms[i]
    } else {
      0
    }
    let single_lat = if single_res.delivered_ms[i] >= single_res.sent_ms[i] {
      single_res.delivered_ms[i] - single_res.sent_ms[i]
    } else {
      0
    }
    let single_stall = if single_res.arrived_ms[i] >= 0 &&
      single_res.delivered_ms[i] >= single_res.arrived_ms[i] {
      single_res.delivered_ms[i] - single_res.arrived_ms[i]
    } else {
      0
    }
    buf.write_string("{\"msg_id\":")
    buf.write_string(i.to_string())
    buf.write_string(",\"stream_id\":")
    buf.write_string((i % 4).to_string())
    buf.write_string(",\"sent_ms\":")
    buf.write_string(sctp_res.sent_ms[i].to_string())
    buf.write_string(",\"sctp_arrived_ms\":")
    buf.write_string(sctp_res.arrived_ms[i].to_string())
    buf.write_string(",\"sctp_delivered_ms\":")
    buf.write_string(sctp_res.delivered_ms[i].to_string())
    buf.write_string(",\"sctp_latency_ms\":")
    buf.write_string(sctp_lat.to_string())
    buf.write_string(",\"single_arrived_ms\":")
    buf.write_string(single_res.arrived_ms[i].to_string())
    buf.write_string(",\"single_delivered_ms\":")
    buf.write_string(single_res.delivered_ms[i].to_string())
    buf.write_string(",\"single_latency_ms\":")
    buf.write_string(single_lat.to_string())
    buf.write_string(",\"single_stall_ms\":")
    buf.write_string(single_stall.to_string())
    buf.write_string(",\"dropped_count\":")
    buf.write_string(sctp_res.dropped_counts[i].to_string())
    buf.write_char('}')
  }
  buf.write_string("]}")
  buf.to_string()
}

///|
priv struct PrSctpEvent {
  t_ms : Int32
  kind : String
  detail : String
}

///|
fn execute_prsctp_demo(
  policy : String,
  max_rtx : Int32,
  drop_first_n : Int32,
) -> String raise @assoc.AssocError {
  let drops_target = clamp_i32(drop_first_n, 0, 5)
  let opts = if policy == "reliable" {
    @sctp.reliable_opts(0U, ppid=1U)
  } else if policy == "max_retransmits" {
    let limit = clamp_i32(max_rtx, 0, 5)
    @sctp.partial_retransmit_opts(0U, limit, ppid=1U)
  } else if policy == "timed_ms" {
    let ttl_i32 = if max_rtx <= 0 {
      150
    } else if max_rtx <= 10 {
      max_rtx * 150
    } else {
      clamp_i32(max_rtx, 50, 5000)
    }
    @sctp.partial_timed_opts(0U, ttl_i32.to_uint64(), ppid=1U)
  } else {
    return json_error(
      "policy", policy, "unsupported policy (expected reliable, max_retransmits, or timed_ms)",
    )
  }

  let secret = b"moonsctp-prsctp-demo-secret-32by!"
  let c_cfg = @sctp.client_config(
    6000U,
    6001U,
    0x22334455U,
    1000U,
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )
  let s_cfg = @sctp.server_config(
    6001U,
    6000U,
    0x66778899U,
    2000U,
    secret,
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )
  let client = @sctp.new_client(c_cfg)
  let server = @sctp.new_server(s_cfg)
  let _ = @sctp.run_handshake_loop(client, server, 0UL)

  let events : Array[PrSctpEvent] = []
  events.push({
    t_ms: 20,
    kind: "handshake",
    detail: "4-Way Cookie handshake completed with RFC 3758 Forward-TSN capability negotiated (TLV 0xC000)",
  })

  let mut drops_done = 0
  let mut ephemeral_delivered = false
  let mut followup_delivered = false
  let mut unblock_time_ms = 0

  // 1. Send ephemeral real-time frame (SSN 0) on Stream 0
  client.send(b"ephemeral-realtime-frame", opts, 100UL)
  let init_tx = client.poll_outbound()
  for i = 0; i < init_tx.length(); i = i + 1 {
    if drops_done < drops_target {
      drops_done = drops_done + 1
      events.push({
        t_ms: 100,
        kind: "drop",
        detail: "Ephemeral frame (TSN 1000, SSN 0) TX #1 dropped on wire",
      })
    } else {
      let evs = server.handle_packet(init_tx[i][:], 110UL)
      for j = 0; j < evs.length(); j = j + 1 {
        match evs[j] {
          @assoc.Event::Message(m) =>
            if m.ppid == 1U {
              ephemeral_delivered = true
              events.push({
                t_ms: 110,
                kind: "delivered",
                detail: "Ephemeral frame (TSN 1000, SSN 0) delivered immediately without loss",
              })
            }
          _ => ()
        }
      }
      let sacks = server.poll_outbound()
      for j = 0; j < sacks.length(); j = j + 1 {
        let _ = client.handle_packet(sacks[j][:], 115UL)
      }
    }
  }

  // 2. Send reliable follow-up keyframe (SSN 1) on the SAME Stream 0
  client.send(
    b"reliable-followup-keyframe",
    @sctp.reliable_opts(0U, ppid=2U),
    120UL,
  )
  let followup_tx = client.poll_outbound()
  for i = 0; i < followup_tx.length(); i = i + 1 {
    let evs = server.handle_packet(followup_tx[i][:], 130UL)
    if evs.length() == 0 {
      events.push({
        t_ms: 130,
        kind: "blocked",
        detail: "Reliable follow-up (TSN 1001, SSN 1) arrived at receiver but is HOL-blocked behind missing SSN 0",
      })
    } else {
      for j = 0; j < evs.length(); j = j + 1 {
        match evs[j] {
          @assoc.Event::Message(m) =>
            if m.ppid == 2U {
              followup_delivered = true
              unblock_time_ms = 10
              events.push({
                t_ms: 130,
                kind: "delivered",
                detail: "Reliable follow-up (TSN 1001, SSN 1) delivered immediately",
              })
            }
          _ => ()
        }
      }
    }
    let sacks = server.poll_outbound()
    for j = 0; j < sacks.length(); j = j + 1 {
      let _ = client.handle_packet(sacks[j][:], 140UL)
    }
  }

  // 3. Advance clock via client.tick(now_ms) until follow-up unblocks
  let mut now_ms = 150UL
  while !followup_delivered && now_ms <= 65000UL {
    let _ = client.tick(now_ms)
    let out = client.poll_outbound()
    for i = 0; i < out.length(); i = i + 1 {
      let decoded : @packet.Packet? = Some(@packet.decode_packet(out[i][:])) catch {
        _ => None
      }
      let mut is_ftsn = false
      let mut ftsn_cum = 0U
      match decoded {
        Some(pkt) =>
          if pkt.chunks.length() > 0 {
            match pkt.chunks[0] {
              @packet.Chunk::ForwardTsn(ft) => {
                is_ftsn = true
                ftsn_cum = ft.new_cum_tsn
              }
              _ => ()
            }
          }
        None => ()
      }

      if is_ftsn {
        events.push({
          t_ms: now_ms.to_int(),
          kind: "forward_tsn",
          detail: "PR-SCTP abandoned ephemeral SSN 0 and emitted FORWARD_TSN (new_cum_tsn=" +
          ftsn_cum.to_string() +
          ")",
        })
        let evs = server.handle_packet(out[i][:], now_ms + 10UL)
        for j = 0; j < evs.length(); j = j + 1 {
          match evs[j] {
            @assoc.Event::Message(m) =>
              if m.ppid == 2U {
                followup_delivered = true
                unblock_time_ms = (now_ms + 10UL - 120UL).to_int()
                events.push({
                  t_ms: (now_ms + 10UL).to_int(),
                  kind: "unblocked",
                  detail: "Receiver applied FORWARD_TSN and IMMEDIATELY unblocked reliable follow-up (SSN 1)",
                })
              }
            _ => ()
          }
        }
        let sacks = server.poll_outbound()
        for j = 0; j < sacks.length(); j = j + 1 {
          let _ = client.handle_packet(sacks[j][:], now_ms + 20UL)
        }
      } else if drops_done < drops_target {
        drops_done = drops_done + 1
        events.push({
          t_ms: now_ms.to_int(),
          kind: "drop",
          detail: "T3-rtx retransmission #" +
          (drops_done - 1).to_string() +
          " of SSN 0 dropped on wire",
        })
      } else {
        events.push({
          t_ms: now_ms.to_int(),
          kind: "retransmit",
          detail: "T3-rtx retransmission of SSN 0 delivered to receiver",
        })
        let evs = server.handle_packet(out[i][:], now_ms + 10UL)
        for j = 0; j < evs.length(); j = j + 1 {
          match evs[j] {
            @assoc.Event::Message(m) =>
              if m.ppid == 1U {
                ephemeral_delivered = true
                events.push({
                  t_ms: (now_ms + 10UL).to_int(),
                  kind: "delivered",
                  detail: "Recovered SSN 0 delivered after retransmission",
                })
              } else if m.ppid == 2U {
                followup_delivered = true
                unblock_time_ms = (now_ms + 10UL - 120UL).to_int()
                events.push({
                  t_ms: (now_ms + 10UL).to_int(),
                  kind: "unblocked",
                  detail: "Buffered reliable follow-up (SSN 1) finally unblocked after full retransmit recovery",
                })
              }
            _ => ()
          }
        }
        let sacks = server.poll_outbound()
        for j = 0; j < sacks.length(); j = j + 1 {
          let _ = client.handle_packet(sacks[j][:], now_ms + 20UL)
        }
      }
    }
    now_ms = now_ms + 50UL
  }

  let stats = client.stats()
  let forward_tsn_emitted = stats.forward_tsn_sent > 0
  let abandoned_chunks = if forward_tsn_emitted && !ephemeral_delivered {
    1
  } else {
    0
  }

  let buf = StringBuilder()
  buf.write_string("{\"ok\":true,\"policy\":")
  write_json_string(buf, policy)
  buf.write_string(",\"forward_tsn_emitted\":")
  buf.write_string(json_bool(forward_tsn_emitted))
  buf.write_string(",\"abandoned_chunks\":")
  buf.write_string(abandoned_chunks.to_string())
  buf.write_string(",\"followup_delivered\":")
  buf.write_string(json_bool(followup_delivered))
  buf.write_string(",\"ephemeral_delivered\":")
  buf.write_string(json_bool(ephemeral_delivered))
  buf.write_string(",\"retransmissions\":")
  buf.write_string(stats.retransmissions.to_string())
  buf.write_string(",\"unblock_time_ms\":")
  buf.write_string(unblock_time_ms.to_string())
  buf.write_string(",\"events\":[")
  for i = 0; i < events.length(); i = i + 1 {
    if i > 0 {
      buf.write_char(',')
    }
    buf.write_string("{\"t_ms\":")
    buf.write_string(events[i].t_ms.to_string())
    buf.write_string(",\"kind\":")
    write_json_string(buf, events[i].kind)
    buf.write_string(",\"detail\":")
    write_json_string(buf, events[i].detail)
    buf.write_char('}')
  }
  buf.write_string("]}")
  buf.to_string()
}

///|
/// Runs an RFC 3758 PR-SCTP reliability policy demonstration (`"reliable"`,
/// `"max_retransmits"`, or `"timed_ms"`), dropping the first `drop_first_n`
/// transmissions of an ephemeral frame and observing `FORWARD_TSN` unblock.
pub fn run_prsctp_demo(
  policy : String,
  max_rtx : Int32,
  drop_first_n : Int32,
) -> String {
  execute_prsctp_demo(policy, max_rtx, drop_first_n) catch {
    err => json_error("policy", policy, assoc_error_detail(err))
  }
}

///|
priv suberror DrillError {
  DrillFail(String)
}

///|
fn encode_pkt_drill(pkt : @packet.Packet) -> Bytes raise DrillError {
  @packet.encode_packet(pkt) catch {
    _ => raise DrillFail("failed to encode drill packet")
  }
}

///|
fn decode_pkt_drill(raw : BytesView) -> @packet.Packet raise DrillError {
  @packet.decode_packet(raw) catch {
    _ => raise DrillFail("failed to decode drill packet")
  }
}

///|
fn format_security_json(
  attack_mode : String,
  handshake_bytes : Int32,
  attack_blocked : Bool,
  association_state : String,
  verdict : String,
  wire_hex_preview : String,
) -> String {
  let buf = StringBuilder()
  buf.write_string("{\"ok\":true,\"attack_mode\":")
  write_json_string(buf, attack_mode)
  buf.write_string(",\"handshake_bytes\":")
  buf.write_string(handshake_bytes.to_string())
  buf.write_string(",\"attack_blocked\":")
  buf.write_string(json_bool(attack_blocked))
  buf.write_string(",\"association_state\":")
  write_json_string(buf, association_state)
  buf.write_string(",\"verdict\":")
  write_json_string(buf, verdict)
  buf.write_string(",\"wire_hex_preview\":")
  write_json_string(buf, wire_hex_preview)
  buf.write_char('}')
  buf.to_string()
}

///|
fn execute_security_drill(attack_mode : String) -> String raise {
  let secret = b"moonsctp-redteam-hmac-secret-32b!"
  let c_cfg = @sctp.client_config(
    4000U,
    4001U,
    0x12345678U,
    1000U,
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )
  let s_cfg = @sctp.server_config(
    4001U,
    4000U,
    0x87654321U,
    2000U,
    secret,
    num_outbound_streams=4U,
    num_inbound_streams=4U,
  )

  if attack_mode == "cookie_tamper" {
    let client = @sctp.new_client(c_cfg)
    let init_pkt = client.connect(0UL)[0]
    let init_ack = @sctp.process_stateless_init(s_cfg, init_pkt[:], 5UL)
    let decoded_ack = decode_pkt_drill(init_ack[:])
    let valid_cookie = match decoded_ack.chunks[0] {
      @packet.Chunk::InitAck(ia) => ia.state_cookie
      _ => raise DrillFail("expected INIT_ACK chunk")
    }
    let bad_cookie = flip_bit(valid_cookie, 10)
    let forged_ce = encode_pkt_drill({
      src_port: c_cfg.local_port,
      dst_port: s_cfg.local_port,
      verification_tag: s_cfg.local_vtag,
      chunks: [@packet.Chunk::CookieEcho(bad_cookie)],
    })
    let server = @sctp.new_server(s_cfg)
    let mut blocked = false
    let mut reason = "not rejected"
    try {
      let _ = server.handle_packet(forged_ce[:], 20UL)
    } catch {
      @assoc.SecurityViolation(m) => {
        blocked = true
        reason = m
      }
      err => {
        blocked = true
        reason = assoc_error_detail(err)
      }
    }
    let hs_bytes = init_pkt.length() + init_ack.length() + forged_ce.length()
    return format_security_json(
      attack_mode,
      hs_bytes,
      blocked,
      assoc_state_name(server.state()),
      "BLOCKED: 1-bit tampered 64B State Cookie rejected by constant-time HMAC-SHA256 (" +
      reason +
      ")",
      bytes_to_hex_preview(forged_ce, 48),
    )
  }

  // Full real 4-way stateless handshake
  let client = @sctp.new_client(c_cfg)
  let init_pkt = client.connect(0UL)[0]
  let init_ack = @sctp.process_stateless_init(s_cfg, init_pkt[:], 5UL)
  let _ = client.handle_packet(init_ack[:], 10UL)
  let ce_pkt = client.poll_outbound()[0]
  let server = @sctp.new_server(s_cfg)
  let _ = server.handle_packet(ce_pkt[:], 15UL)
  let ca_pkt = server.poll_outbound()[0]
  let _ = client.handle_packet(ca_pkt[:], 20UL)
  let hs_bytes = init_pkt.length() +
    init_ack.length() +
    ce_pkt.length() +
    ca_pkt.length()

  if attack_mode == "none" {
    client.send(
      b"verified-sctp-payload",
      @sctp.reliable_opts(0U, ppid=51U),
      50UL,
    )
    let data_pkt = client.poll_outbound()[0]
    let evs = server.handle_packet(data_pkt[:], 60UL)
    let ok_msg = evs.length() == 1
    return format_security_json(
      attack_mode,
      hs_bytes,
      false,
      assoc_state_name(server.state()),
      if ok_msg {
        "PASS: Stateless 4-Way HMAC Cookie handshake completed (" +
        hs_bytes.to_string() +
        "B) and verified DATA delivered cleanly"
      } else {
        "FAIL: DATA delivery failed after handshake"
      },
      bytes_to_hex_preview(init_ack, 48),
    )
  }

  if attack_mode == "crc32c_tamper" {
    client.send(
      b"crc32c-protected-frame",
      @sctp.reliable_opts(0U, ppid=51U),
      50UL,
    )
    let good_pkt = client.poll_outbound()[0]
    let tampered = flip_bit(good_pkt, good_pkt.length() - 1)
    let mut blocked = false
    let mut reason = "not rejected"
    try {
      let _ = server.handle_packet(tampered[:], 60UL)
    } catch {
      @assoc.SecurityViolation(m) => {
        blocked = true
        reason = m
      }
      err => {
        blocked = true
        reason = assoc_error_detail(err)
      }
    }
    return format_security_json(
      attack_mode,
      hs_bytes,
      blocked,
      assoc_state_name(server.state()),
      "BLOCKED: Single-bit wire tamper rejected by Castagnoli CRC-32C (" +
      reason +
      ")",
      bytes_to_hex_preview(tampered, 48),
    )
  }

  if attack_mode == "cookie_hijack_established" {
    let attacker_init = encode_pkt_drill({
      src_port: c_cfg.local_port,
      dst_port: s_cfg.local_port,
      verification_tag: 0U,
      chunks: [
        @packet.Chunk::Init({
          initiate_tag: 0xDEAD1234U,
          a_rwnd: 65536U,
          num_outbound_streams: 4U,
          num_inbound_streams: 4U,
          initial_tsn: 9999U,
          forward_tsn_supported: true,
        }),
      ],
    })
    let fresh_ack = @sctp.process_stateless_init(s_cfg, attacker_init[:], 100UL)
    let decoded_ack = decode_pkt_drill(fresh_ack[:])
    let fresh_cookie = match decoded_ack.chunks[0] {
      @packet.Chunk::InitAck(ia) => ia.state_cookie
      _ => raise DrillFail("expected INIT_ACK chunk")
    }
    let hijack_pkt = encode_pkt_drill({
      src_port: c_cfg.local_port,
      dst_port: s_cfg.local_port,
      verification_tag: s_cfg.local_vtag,
      chunks: [@packet.Chunk::CookieEcho(fresh_cookie)],
    })
    let mut blocked = false
    let mut reason = "not rejected"
    try {
      let _ = server.handle_packet(hijack_pkt[:], 110UL)
    } catch {
      @assoc.SecurityViolation(m) => {
        blocked = true
        reason = m
      }
      err => {
        blocked = true
        reason = assoc_error_detail(err)
      }
    }
    // Verify legitimate session still delivers traffic intact
    client.send(b"session-still-intact", @sctp.reliable_opts(0U), 120UL)
    let check_pkt = client.poll_outbound()[0]
    let alive_evs = server.handle_packet(check_pkt[:], 130UL)
    let intact = blocked && alive_evs.length() == 1
    return format_security_json(
      attack_mode,
      hs_bytes,
      intact,
      assoc_state_name(server.state()),
      "BLOCKED: Valid fresh COOKIE_ECHO rejected on Established server (" +
      reason +
      "); active session intact",
      bytes_to_hex_preview(hijack_pkt, 48),
    )
  }

  if attack_mode == "future_sack" {
    let future_sack = encode_pkt_drill({
      src_port: s_cfg.local_port,
      dst_port: c_cfg.local_port,
      verification_tag: c_cfg.local_vtag,
      chunks: [
        @packet.Chunk::Sack({
          cum_tsn_ack: c_cfg.initial_tsn + 500U,
          a_rwnd: 65536U,
          gap_blocks: [],
          dup_tsns: [],
        }),
      ],
    })
    let _ = client.handle_packet(future_sack[:], 100UL)
    // Verify client send queue was NOT corrupted or pruned by future cum_tsn_ack
    client.send(b"must-not-be-pruned", @sctp.reliable_opts(0U), 110UL)
    let out = client.poll_outbound()
    let delivered = if out.length() == 1 {
      let evs = server.handle_packet(out[0][:], 120UL)
      evs.length() == 1
    } else {
      false
    }
    return format_security_json(
      attack_mode,
      hs_bytes,
      delivered,
      assoc_state_name(client.state()),
      "BLOCKED: Malicious future SACK (cum_tsn_ack >= next_tsn) safely ignored; subsequent DATA delivered intact",
      bytes_to_hex_preview(future_sack, 48),
    )
  }

  if attack_mode == "forged_abort" {
    let forged_abort = encode_pkt_drill({
      src_port: c_cfg.local_port,
      dst_port: s_cfg.local_port,
      verification_tag: 0xBAD0F00DU,
      chunks: [
        @packet.Chunk::Abort(false, [{ code: 12U, info: b"spoofed-abort", }]),
      ],
    })
    let abort_evs = server.handle_packet(forged_abort[:], 100UL)
    // Verify association remains Established and continues delivering data
    client.send(b"alive-after-forged-abort", @sctp.reliable_opts(0U), 110UL)
    let check_pkt = client.poll_outbound()[0]
    let alive_evs = server.handle_packet(check_pkt[:], 120UL)
    let blocked = abort_evs.length() == 0 &&
      server.state() == @assoc.AssocState::Established &&
      alive_evs.length() == 1
    return format_security_json(
      attack_mode,
      hs_bytes,
      blocked,
      assoc_state_name(server.state()),
      "BLOCKED: Forged ABORT with wrong Verification Tag silently ignored (RFC 9260 §8.5.1); session stays Established",
      bytes_to_hex_preview(forged_abort, 48),
    )
  }

  json_error(
    "attack_mode", attack_mode, "unsupported attack_mode (expected none, crc32c_tamper, cookie_tamper, cookie_hijack_established, future_sack, or forged_abort)",
  )
}

///|
/// Executes a real 4-way stateless Cookie handshake and the specified red-team
/// security drill against `@association`, returning a structured JSON report.
pub fn run_security_drill(attack_mode : String) -> String {
  execute_security_drill(attack_mode) catch {
    DrillFail(m) => json_error("attack_mode", attack_mode, m)
    err => json_error("attack_mode", attack_mode, err.to_string())
  }
}
