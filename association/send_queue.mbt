///|
/// A queued outbound DATA chunk tracked through transmission, SACK, retransmit,
/// and RFC 3758 PR-SCTP abandonment.
priv struct OutChunk {
  msg_id : Int32
  chunk : @packet.DataChunk
  reliability : ReliabilityPolicy
  created_ms : UInt64
  mut sent : Bool
  mut acked : Bool
  mut abandoned : Bool
  mut in_flight : Bool
  mut tx_count : Int32
  mut last_sent_ms : UInt64
  mut missing_reports : Int32
  mut needs_retransmit : Bool
}

///|
/// Result returned when flushing outbound data / PR-SCTP control chunks.
priv struct FlushBatch {
  chunks : Array[@packet.Chunk]
  retransmitted : Int32
}

///|
/// Sender-side transmission queue, RFC 9260 congestion control, Jacobson/Karels
/// RTT/RTO estimator, and RFC 3758 PR-SCTP abandonment engine.
priv struct SendQueue {
  mut next_tsn : UInt32
  mut peer_cum_tsn_ack : UInt32
  mut advanced_peer_ack_point : UInt32
  mut forward_tsn_dirty : Bool
  mut next_msg_id : Int32
  out_stream_ssn : Array[UInt32]
  queue : Array[OutChunk]
  mtu : Int32
  max_message_size : Int32
  mut peer_rwnd : UInt32
  mut cwnd : Int32
  mut ssthresh : Int32
  mut partial_bytes_acked : Int32
  mut srtt_ms : UInt64
  mut rttvar_ms : UInt64
  mut has_rtt : Bool
  mut rto_ms : UInt64
  rto_min_ms : UInt64
  rto_max_ms : UInt64
  mut t3_deadline_ms : UInt64?
}

///|
fn SendQueue::new(
  initial_tsn : UInt32,
  num_out_streams : UInt32,
  mtu : Int32,
  max_message_size : Int32,
  peer_rwnd : UInt32,
  rto_initial_ms : UInt64,
  rto_max_ms : UInt64,
) -> SendQueue {
  let count = num_out_streams.reinterpret_as_int()
  let out_stream_ssn : Array[UInt32] = Array(capacity=count)
  for i = 0; i < count; i = i + 1 {
    out_stream_ssn.push(0U)
  }
  let init_cwnd = min_int(4 * mtu, max_int(2 * mtu, 4380))
  let init_ssthresh = max_int(peer_rwnd.reinterpret_as_int(), 4 * mtu)
  let rto_min = if DEFAULT_RTO_MIN_MS < rto_initial_ms {
    DEFAULT_RTO_MIN_MS
  } else {
    rto_initial_ms
  }
  {
    next_tsn: initial_tsn,
    peer_cum_tsn_ack: initial_tsn - 1U,
    advanced_peer_ack_point: initial_tsn - 1U,
    forward_tsn_dirty: false,
    next_msg_id: 1,
    out_stream_ssn,
    queue: [],
    mtu,
    max_message_size,
    peer_rwnd,
    cwnd: init_cwnd,
    ssthresh: init_ssthresh,
    partial_bytes_acked: 0,
    srtt_ms: 0UL,
    rttvar_ms: 0UL,
    has_rtt: false,
    rto_ms: rto_initial_ms,
    rto_min_ms: rto_min,
    rto_max_ms,
    t3_deadline_ms: None,
  }
}

///|
fn SendQueue::is_empty(self : SendQueue) -> Bool {
  self.queue.length() == 0
}

///|
fn SendQueue::flight_bytes(self : SendQueue) -> Int32 {
  let mut total = 0
  for i = 0; i < self.queue.length(); i = i + 1 {
    let c = self.queue[i]
    if c.in_flight && !c.acked && !c.abandoned {
      total = total + max_int(1, c.chunk.payload.length())
    }
  }
  total
}

///|
/// Splits a user message into MTU-bounded DATA chunks and appends them to the queue.
fn SendQueue::enqueue_message(
  self : SendQueue,
  payload : Bytes,
  opts : SendOptions,
  now_ms : UInt64,
) -> Unit raise AssocError {
  if opts.stream_id >= self.out_stream_ssn.length().reinterpret_as_uint() {
    raise InvalidStream(opts.stream_id)
  }
  if payload.length() > self.max_message_size {
    raise MessageTooLarge(payload.length())
  }
  let sid = opts.stream_id.reinterpret_as_int()
  let ssn = if opts.unordered {
    0U
  } else {
    let cur = self.out_stream_ssn[sid]
    self.out_stream_ssn[sid] = @packet.ssn_inc(cur)
    cur
  }
  let msg_id = self.next_msg_id
  self.next_msg_id = self.next_msg_id + 1

  let total_len = payload.length()
  if total_len == 0 {
    let tsn = self.next_tsn
    self.next_tsn = self.next_tsn + 1U
    self.queue.push({
      msg_id,
      chunk: {
        tsn,
        stream_id: opts.stream_id,
        stream_seq: ssn,
        ppid: opts.ppid,
        unordered: opts.unordered,
        beginning: true,
        ending: true,
        payload: b"",
      },
      reliability: opts.reliability,
      created_ms: now_ms,
      sent: false,
      acked: false,
      abandoned: false,
      in_flight: false,
      tx_count: 0,
      last_sent_ms: 0UL,
      missing_reports: 0,
      needs_retransmit: false,
    })
    return
  }

  let mut offset = 0
  while offset < total_len {
    let end = min_int(offset + self.mtu, total_len)
    let frag_payload = payload[offset:end].to_owned()
    let tsn = self.next_tsn
    self.next_tsn = self.next_tsn + 1U
    self.queue.push({
      msg_id,
      chunk: {
        tsn,
        stream_id: opts.stream_id,
        stream_seq: ssn,
        ppid: opts.ppid,
        unordered: opts.unordered,
        beginning: offset == 0,
        ending: end == total_len,
        payload: frag_payload,
      },
      reliability: opts.reliability,
      created_ms: now_ms,
      sent: false,
      acked: false,
      abandoned: false,
      in_flight: false,
      tx_count: 0,
      last_sent_ms: 0UL,
      missing_reports: 0,
      needs_retransmit: false,
    })
    offset = end
  }
}

///|
fn SendQueue::abandon_message(self : SendQueue, msg_id : Int32) -> Unit {
  for i = 0; i < self.queue.length(); i = i + 1 {
    let c = self.queue[i]
    if c.msg_id == msg_id && !c.acked {
      c.abandoned = true
      c.in_flight = false
      c.needs_retransmit = false
    }
  }
}

///|
fn SendQueue::should_abandon_on_rtx(c : OutChunk, now_ms : UInt64) -> Bool {
  match c.reliability {
    Reliable => false
    MaxRetransmits(max_r) => {
      let limit = if max_r < 0 { 0 } else { max_r }
      c.tx_count > limit
    }
    TimedMs(ttl) => now_ms >= c.created_ms && now_ms - c.created_ms >= ttl
  }
}

///|
/// Checks TimedMs policies across all queued chunks and updates the PR-SCTP
/// advanced peer ack point.
fn SendQueue::check_timed_abandonments(
  self : SendQueue,
  now_ms : UInt64,
) -> Unit {
  let to_abandon : Array[Int32] = []
  for i = 0; i < self.queue.length(); i = i + 1 {
    let c = self.queue[i]
    if !c.acked && !c.abandoned {
      match c.reliability {
        TimedMs(ttl) =>
          if now_ms >= c.created_ms && now_ms - c.created_ms >= ttl {
            to_abandon.push(c.msg_id)
          }
        _ => ()
      }
    }
  }
  for i = 0; i < to_abandon.length(); i = i + 1 {
    self.abandon_message(to_abandon[i])
  }
  self.recompute_advanced_ack_point()
}

///|
fn SendQueue::recompute_advanced_ack_point(self : SendQueue) -> Unit {
  let mut adv = self.peer_cum_tsn_ack
  let mut saw_abandoned = false
  for i = 0; i < self.queue.length(); i = i + 1 {
    let c = self.queue[i]
    if c.chunk.tsn == adv + 1U && (c.acked || c.abandoned) {
      adv = c.chunk.tsn
      if c.abandoned {
        saw_abandoned = true
      }
    } else if @packet.tsn_le(c.chunk.tsn, adv) {
      if c.abandoned {
        saw_abandoned = true
      }
    } else {
      break
    }
  }
  if saw_abandoned && @packet.tsn_gt(adv, self.advanced_peer_ack_point) {
    self.advanced_peer_ack_point = adv
    self.forward_tsn_dirty = true
  } else if @packet.tsn_gt(self.peer_cum_tsn_ack, self.advanced_peer_ack_point) {
    self.advanced_peer_ack_point = self.peer_cum_tsn_ack
  }
}

///|
fn SendQueue::build_forward_tsn(self : SendQueue) -> @packet.ForwardTsnChunk? {
  if !@packet.tsn_gt(self.advanced_peer_ack_point, self.peer_cum_tsn_ack) {
    return None
  }
  let streams : Array[@packet.ForwardTsnStream] = []
  for i = 0; i < self.queue.length(); i = i + 1 {
    let c = self.queue[i]
    if c.abandoned &&
      !c.chunk.unordered &&
      @packet.tsn_le(c.chunk.tsn, self.advanced_peer_ack_point) {
      let mut found = false
      for j = 0; j < streams.length(); j = j + 1 {
        if streams[j].stream_id == c.chunk.stream_id {
          if @packet.ssn_lt(streams[j].stream_seq, c.chunk.stream_seq) {
            streams[j] = {
              stream_id: c.chunk.stream_id,
              stream_seq: c.chunk.stream_seq,
            }
          }
          found = true
          break
        }
      }
      if !found {
        streams.push({
          stream_id: c.chunk.stream_id,
          stream_seq: c.chunk.stream_seq,
        })
      }
    }
  }
  Some({ new_cum_tsn: self.advanced_peer_ack_point, streams, })
}

///|
fn SendQueue::update_rto(self : SendQueue, sample_ms : UInt64) -> Unit {
  if !self.has_rtt {
    self.srtt_ms = sample_ms
    self.rttvar_ms = sample_ms / 2UL
    self.has_rtt = true
  } else {
    let diff = if self.srtt_ms >= sample_ms {
      self.srtt_ms - sample_ms
    } else {
      sample_ms - self.srtt_ms
    }
    self.rttvar_ms = (3UL * self.rttvar_ms + diff) / 4UL
    self.srtt_ms = (7UL * self.srtt_ms + sample_ms) / 8UL
  }
  let mut next_rto = self.srtt_ms + 4UL * self.rttvar_ms
  if next_rto < self.rto_min_ms {
    next_rto = self.rto_min_ms
  }
  if next_rto > self.rto_max_ms {
    next_rto = self.rto_max_ms
  }
  self.rto_ms = next_rto
}

///|
/// Acknowledges all queued chunks up to peer_cum_tsn (e.g., from SHUTDOWN chunk).
fn SendQueue::ack_up_to(self : SendQueue, cum_tsn : UInt32) -> Unit {
  if @packet.tsn_gt(cum_tsn, self.peer_cum_tsn_ack) {
    self.peer_cum_tsn_ack = cum_tsn
    if @packet.tsn_gt(cum_tsn, self.advanced_peer_ack_point) {
      self.advanced_peer_ack_point = cum_tsn
      self.forward_tsn_dirty = false
    }
    self.prune_acked()
  }
}

///|
fn SendQueue::prune_acked(self : SendQueue) -> Unit {
  let kept : Array[OutChunk] = []
  for i = 0; i < self.queue.length(); i = i + 1 {
    let c = self.queue[i]
    if @packet.tsn_gt(c.chunk.tsn, self.peer_cum_tsn_ack) {
      kept.push(c)
    }
  }
  self.queue.clear()
  for i = 0; i < kept.length(); i = i + 1 {
    self.queue.push(kept[i])
  }
  if self.queue.length() == 0 {
    self.t3_deadline_ms = None
    self.forward_tsn_dirty = false
  }
}

///|
/// Processes an incoming SACK chunk: updates cumulative/gap acknowledgements,
/// triggers 3-missing-report fast retransmit, updates cwnd and RTO.
fn SendQueue::on_sack(
  self : SendQueue,
  sack : @packet.SackChunk,
  now_ms : UInt64,
) -> Unit {
  if @packet.tsn_lt(sack.cum_tsn_ack, self.peer_cum_tsn_ack) {
    return
  }
  self.peer_rwnd = sack.a_rwnd

  let cum_advanced = @packet.tsn_gt(sack.cum_tsn_ack, self.peer_cum_tsn_ack)
  let mut bytes_newly_acked = 0
  let mut highest_newly_acked : UInt32? = None
  let mut rtt_sample : UInt64? = None

  // 1. Cumulative acks
  for i = 0; i < self.queue.length(); i = i + 1 {
    let c = self.queue[i]
    if @packet.tsn_le(c.chunk.tsn, sack.cum_tsn_ack) {
      if !c.acked {
        c.acked = true
        c.needs_retransmit = false
        if c.in_flight {
          c.in_flight = false
          bytes_newly_acked = bytes_newly_acked +
            max_int(1, c.chunk.payload.length())
        }
        if c.tx_count == 1 && !c.abandoned && now_ms >= c.last_sent_ms {
          rtt_sample = Some(now_ms - c.last_sent_ms)
        }
        highest_newly_acked = match highest_newly_acked {
          None => Some(c.chunk.tsn)
          Some(prev) =>
            if @packet.tsn_gt(c.chunk.tsn, prev) {
              Some(c.chunk.tsn)
            } else {
              Some(prev)
            }
        }
      }
    }
  }

  // 2. Gap Ack Blocks
  for g = 0; g < sack.gap_blocks.length(); g = g + 1 {
    let blk = sack.gap_blocks[g]
    if blk.start == 0U || blk.end < blk.start {
      continue
    }
    let gap_start = sack.cum_tsn_ack + blk.start
    let gap_end = sack.cum_tsn_ack + blk.end
    for i = 0; i < self.queue.length(); i = i + 1 {
      let c = self.queue[i]
      if @packet.tsn_ge(c.chunk.tsn, gap_start) &&
        @packet.tsn_le(c.chunk.tsn, gap_end) {
        if !c.acked {
          c.acked = true
          c.needs_retransmit = false
          if c.in_flight {
            c.in_flight = false
            bytes_newly_acked = bytes_newly_acked +
              max_int(1, c.chunk.payload.length())
          }
          if c.tx_count == 1 && !c.abandoned && now_ms >= c.last_sent_ms {
            rtt_sample = Some(now_ms - c.last_sent_ms)
          }
          highest_newly_acked = match highest_newly_acked {
            None => Some(c.chunk.tsn)
            Some(prev) =>
              if @packet.tsn_gt(c.chunk.tsn, prev) {
                Some(c.chunk.tsn)
              } else {
                Some(prev)
              }
          }
        }
      }
    }
  }

  // 3. RFC 9260 Section 7.2.4 Fast Retransmit (3 missing reports)
  let mut fast_rtx_triggered = false
  match highest_newly_acked {
    Some(hi) => {
      let to_abandon : Array[Int32] = []
      for i = 0; i < self.queue.length(); i = i + 1 {
        let c = self.queue[i]
        if c.sent && !c.acked && !c.abandoned && @packet.tsn_lt(c.chunk.tsn, hi) {
          c.missing_reports = c.missing_reports + 1
          if c.missing_reports >= 3 {
            if SendQueue::should_abandon_on_rtx(c, now_ms) {
              to_abandon.push(c.msg_id)
            } else {
              c.needs_retransmit = true
              c.in_flight = false
              c.missing_reports = 0
              fast_rtx_triggered = true
            }
          }
        }
      }
      for i = 0; i < to_abandon.length(); i = i + 1 {
        self.abandon_message(to_abandon[i])
      }
    }
    None => ()
  }

  if cum_advanced {
    self.peer_cum_tsn_ack = sack.cum_tsn_ack
    if @packet.tsn_ge(self.peer_cum_tsn_ack, self.advanced_peer_ack_point) {
      self.advanced_peer_ack_point = self.peer_cum_tsn_ack
      self.forward_tsn_dirty = false
    }
  }
  self.prune_acked()
  self.recompute_advanced_ack_point()

  match rtt_sample {
    Some(r) => self.update_rto(r)
    None => ()
  }

  // 4. Congestion control (RFC 9260 Section 7.2)
  if fast_rtx_triggered {
    self.ssthresh = max_int(self.cwnd / 2, 4 * self.mtu)
    self.cwnd = self.ssthresh
    self.partial_bytes_acked = 0
  } else if bytes_newly_acked > 0 && cum_advanced {
    if self.cwnd <= self.ssthresh {
      // Slow Start
      self.cwnd = self.cwnd + min_int(bytes_newly_acked, self.mtu)
    } else {
      // Congestion Avoidance
      self.partial_bytes_acked = self.partial_bytes_acked + bytes_newly_acked
      if self.partial_bytes_acked >= self.cwnd {
        self.partial_bytes_acked = self.partial_bytes_acked - self.cwnd
        self.cwnd = self.cwnd + self.mtu
      }
    }
  }

  if self.queue.length() > 0 && cum_advanced {
    self.t3_deadline_ms = Some(now_ms + self.rto_ms)
  }
}

///|
/// Handles T3-rtx timeout: exponential RTO backoff, cwnd collapse to 1 MTU,
/// PR-SCTP abandonment checks, and marking unacked chunks for retransmission.
fn SendQueue::on_t3_timeout(self : SendQueue, now_ms : UInt64) -> Unit {
  let next_rto = self.rto_ms * 2UL
  self.rto_ms = if next_rto > self.rto_max_ms {
    self.rto_max_ms
  } else {
    next_rto
  }
  self.ssthresh = max_int(self.cwnd / 2, 4 * self.mtu)
  self.cwnd = self.mtu
  self.partial_bytes_acked = 0

  let to_abandon : Array[Int32] = []
  for i = 0; i < self.queue.length(); i = i + 1 {
    let c = self.queue[i]
    if !c.acked && !c.abandoned {
      if SendQueue::should_abandon_on_rtx(c, now_ms) {
        to_abandon.push(c.msg_id)
      } else if c.sent {
        c.needs_retransmit = true
        c.in_flight = false
        c.missing_reports = 0
      }
    }
  }
  for i = 0; i < to_abandon.length(); i = i + 1 {
    self.abandon_message(to_abandon[i])
  }
  self.recompute_advanced_ack_point()

  if @packet.tsn_gt(self.advanced_peer_ack_point, self.peer_cum_tsn_ack) {
    self.forward_tsn_dirty = true
  }

  if self.queue.length() > 0 {
    self.t3_deadline_ms = Some(now_ms + self.rto_ms)
  } else {
    self.t3_deadline_ms = None
  }
}

///|
/// Collects eligible outbound FORWARD_TSN and DATA chunks respecting cwnd and peer_rwnd.
fn SendQueue::collect_outbound(self : SendQueue, now_ms : UInt64) -> FlushBatch {
  let chunks : Array[@packet.Chunk] = []
  let mut retransmitted = 0

  self.check_timed_abandonments(now_ms)

  if self.forward_tsn_dirty {
    match self.build_forward_tsn() {
      Some(ft) => {
        chunks.push(@packet.Chunk::ForwardTsn(ft))
        self.forward_tsn_dirty = false
        if self.t3_deadline_ms is None {
          self.t3_deadline_ms = Some(now_ms + self.rto_ms)
        }
      }
      None => self.forward_tsn_dirty = false
    }
  }

  let mut flight = self.flight_bytes()
  let rwnd_limit = self.peer_rwnd.reinterpret_as_int()

  // 1. Retransmissions first
  for i = 0; i < self.queue.length(); i = i + 1 {
    let c = self.queue[i]
    if c.needs_retransmit && !c.acked && !c.abandoned {
      let sz = max_int(1, c.chunk.payload.length())
      if flight == 0 || flight + sz <= self.cwnd {
        c.needs_retransmit = false
        c.in_flight = true
        c.sent = true
        c.tx_count = c.tx_count + 1
        c.last_sent_ms = now_ms
        flight = flight + sz
        retransmitted = retransmitted + 1
        chunks.push(@packet.Chunk::Data(c.chunk))
      }
    }
  }

  // 2. Fresh unsent DATA chunks within min(cwnd, peer_rwnd)
  for i = 0; i < self.queue.length(); i = i + 1 {
    let c = self.queue[i]
    if !c.sent && !c.acked && !c.abandoned {
      let sz = max_int(1, c.chunk.payload.length())
      let effective_wnd = min_int(self.cwnd, rwnd_limit)
      if flight == 0 || flight + sz <= effective_wnd {
        c.sent = true
        c.in_flight = true
        c.tx_count = 1
        c.last_sent_ms = now_ms
        flight = flight + sz
        chunks.push(@packet.Chunk::Data(c.chunk))
      } else {
        break
      }
    }
  }

  if chunks.length() > 0 && self.t3_deadline_ms is None {
    self.t3_deadline_ms = Some(now_ms + self.rto_ms)
  }

  { chunks, retransmitted, }
}
