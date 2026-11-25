///|
/// Single received DATA fragment awaiting reassembly.
priv struct RecvFrag {
  tsn : UInt32
  ppid : UInt32
  beginning : Bool
  ending : Bool
  payload : Bytes
}

///|
/// Ordered message reassembly slot keyed by stream_seq.
priv struct OrderedMsgBuf {
  stream_seq : UInt32
  frags : Array[RecvFrag]
  mut total_bytes : Int32
}

///|
/// Per-stream independent receive state eliminating cross-stream HOL blocking.
priv struct StreamRecvState {
  mut next_ssn : UInt32
  pending_ordered : Array[OrderedMsgBuf]
  pending_unordered : Array[RecvFrag]
  mut unordered_bytes : Int32
}

///|
/// Multi-stream SCTP receive tracker with RFC 1982 TSN tracking, Gap Ack Block
/// calculation, independent per-stream reassembly, and RFC 3758 FORWARD_TSN support.
priv struct RecvTracker {
  mut cum_tsn : UInt32
  out_of_order_tsns : Array[UInt32]
  dup_tsns : Array[UInt32]
  streams : Array[StreamRecvState]
  max_message_size : Int32
  base_arwnd : UInt32
  mut buffered_bytes : Int32
}

///|
fn RecvTracker::new(
  peer_initial_tsn : UInt32,
  num_in_streams : UInt32,
  max_message_size : Int32,
  base_arwnd : UInt32,
) -> RecvTracker {
  let count = num_in_streams.reinterpret_as_int()
  let streams : Array[StreamRecvState] = Array(capacity=count)
  for i = 0; i < count; i = i + 1 {
    streams.push({
      next_ssn: 0U,
      pending_ordered: [],
      pending_unordered: [],
      unordered_bytes: 0,
    })
  }
  {
    cum_tsn: peer_initial_tsn - 1U,
    out_of_order_tsns: [],
    dup_tsns: [],
    streams,
    max_message_size,
    base_arwnd,
    buffered_bytes: 0,
  }
}

///|
fn RecvTracker::contains_ooo(self : RecvTracker, tsn : UInt32) -> Bool {
  for i = 0; i < self.out_of_order_tsns.length(); i = i + 1 {
    if self.out_of_order_tsns[i] == tsn {
      return true
    }
  }
  false
}

///|
fn RecvTracker::insert_tsn(self : RecvTracker, tsn : UInt32) -> Unit {
  let mut pos = self.out_of_order_tsns.length()
  for i = 0; i < self.out_of_order_tsns.length(); i = i + 1 {
    if @packet.tsn_lt(tsn, self.out_of_order_tsns[i]) {
      pos = i
      break
    }
  }
  self.out_of_order_tsns.insert(pos, tsn)
  self.advance_cum_tsn()
}

///|
fn RecvTracker::advance_cum_tsn(self : RecvTracker) -> Unit {
  let mut consumed = 0
  while consumed < self.out_of_order_tsns.length() &&
        self.out_of_order_tsns[consumed] == self.cum_tsn + 1U {
    self.cum_tsn = self.cum_tsn + 1U
    consumed = consumed + 1
  }
  if consumed > 0 {
    let remaining : Array[UInt32] = Array(
      capacity=self.out_of_order_tsns.length() - consumed,
    )
    for i = consumed; i < self.out_of_order_tsns.length(); i = i + 1 {
      remaining.push(self.out_of_order_tsns[i])
    }
    self.out_of_order_tsns.clear()
    for i = 0; i < remaining.length(); i = i + 1 {
      self.out_of_order_tsns.push(remaining[i])
    }
  }
}

///|
fn insert_frag_sorted(frags : Array[RecvFrag], frag : RecvFrag) -> Unit {
  let mut pos = frags.length()
  for i = 0; i < frags.length(); i = i + 1 {
    if frags[i].tsn == frag.tsn {
      return
    }
    if @packet.tsn_lt(frag.tsn, frags[i].tsn) {
      pos = i
      break
    }
  }
  frags.insert(pos, frag)
}

///|
fn concat_frags(
  frags : Array[RecvFrag],
  start : Int32,
  end_incl : Int32,
) -> Bytes {
  let mut total = 0
  for i = start; i <= end_incl; i = i + 1 {
    total = total + frags[i].payload.length()
  }
  let out : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  let mut offset = 0
  for i = start; i <= end_incl; i = i + 1 {
    let p = frags[i].payload
    for j = 0; j < p.length(); j = j + 1 {
      out[offset + j] = p[j]
    }
    offset = offset + p.length()
  }
  Bytes::from_array(out)
}

///|
fn RecvTracker::drain_ordered_stream(
  self : RecvTracker,
  stream_id : UInt32,
  delivered : Array[DeliveredMessage],
) -> Unit {
  let st = self.streams[stream_id.reinterpret_as_int()]
  while true {
    let mut found_idx = -1
    for i = 0; i < st.pending_ordered.length(); i = i + 1 {
      if st.pending_ordered[i].stream_seq == st.next_ssn {
        found_idx = i
        break
      }
    }
    if found_idx < 0 {
      break
    }
    let msg_buf = st.pending_ordered[found_idx]
    let n = msg_buf.frags.length()
    if n == 0 {
      break
    }
    if !msg_buf.frags[0].beginning || !msg_buf.frags[n - 1].ending {
      break
    }
    let mut contiguous = true
    for i = 0; i + 1 < n; i = i + 1 {
      if msg_buf.frags[i + 1].tsn != msg_buf.frags[i].tsn + 1U {
        contiguous = false
        break
      }
    }
    if !contiguous {
      break
    }
    let payload = concat_frags(msg_buf.frags, 0, n - 1)
    let ppid = msg_buf.frags[0].ppid
    self.buffered_bytes = max_int(0, self.buffered_bytes - msg_buf.total_bytes)
    let _ = st.pending_ordered.remove(found_idx)
    st.next_ssn = @packet.ssn_inc(st.next_ssn)
    delivered.push({ stream_id, ppid, unordered: false, payload, })
  }
}

///|
fn RecvTracker::drain_unordered_stream(
  self : RecvTracker,
  stream_id : UInt32,
  delivered : Array[DeliveredMessage],
) -> Unit {
  let st = self.streams[stream_id.reinterpret_as_int()]
  while true {
    let n = st.pending_unordered.length()
    let mut matched_start = -1
    let mut matched_end = -1
    for i = 0; i < n; i = i + 1 {
      if st.pending_unordered[i].beginning {
        let mut j = i
        while j < n {
          if j > i &&
            st.pending_unordered[j].tsn != st.pending_unordered[j - 1].tsn + 1U {
            break
          }
          if st.pending_unordered[j].ending {
            matched_start = i
            matched_end = j
            break
          }
          j = j + 1
        }
        if matched_start >= 0 {
          break
        }
      }
    }
    if matched_start < 0 {
      break
    }
    let payload = concat_frags(st.pending_unordered, matched_start, matched_end)
    let ppid = st.pending_unordered[matched_start].ppid
    let mut removed_bytes = 0
    for k = matched_start; k <= matched_end; k = k + 1 {
      removed_bytes = removed_bytes + st.pending_unordered[k].payload.length()
    }
    let next_list : Array[RecvFrag] = Array(
      capacity=n - (matched_end - matched_start + 1),
    )
    for k = 0; k < n; k = k + 1 {
      if k < matched_start || k > matched_end {
        next_list.push(st.pending_unordered[k])
      }
    }
    st.pending_unordered.clear()
    for k = 0; k < next_list.length(); k = k + 1 {
      st.pending_unordered.push(next_list[k])
    }
    st.unordered_bytes = max_int(0, st.unordered_bytes - removed_bytes)
    self.buffered_bytes = max_int(0, self.buffered_bytes - removed_bytes)
    delivered.push({ stream_id, ppid, unordered: true, payload, })
  }
}

///|
/// Processes an incoming DATA chunk and returns any immediately deliverable messages.
fn RecvTracker::on_data(
  self : RecvTracker,
  chunk : @packet.DataChunk,
) -> Array[DeliveredMessage] raise AssocError {
  if chunk.stream_id >= self.streams.length().reinterpret_as_uint() {
    raise InvalidStream(chunk.stream_id)
  }
  if chunk.payload.length() > self.max_message_size {
    raise MessageTooLarge(chunk.payload.length())
  }
  if @packet.tsn_le(chunk.tsn, self.cum_tsn) || self.contains_ooo(chunk.tsn) {
    self.dup_tsns.push(chunk.tsn)
    return []
  }

  let delivered : Array[DeliveredMessage] = []
  let sid = chunk.stream_id.reinterpret_as_int()
  let st = self.streams[sid]

  if chunk.unordered {
    if chunk.beginning && chunk.ending {
      self.insert_tsn(chunk.tsn)
      delivered.push({
        stream_id: chunk.stream_id,
        ppid: chunk.ppid,
        unordered: true,
        payload: chunk.payload,
      })
      return delivered
    }
    let next_unordered = st.unordered_bytes + chunk.payload.length()
    if next_unordered > self.max_message_size {
      raise MessageTooLarge(next_unordered)
    }
    self.insert_tsn(chunk.tsn)
    insert_frag_sorted(st.pending_unordered, {
      tsn: chunk.tsn,
      ppid: chunk.ppid,
      beginning: chunk.beginning,
      ending: chunk.ending,
      payload: chunk.payload,
    })
    st.unordered_bytes = next_unordered
    self.buffered_bytes = self.buffered_bytes + chunk.payload.length()
    self.drain_unordered_stream(chunk.stream_id, delivered)
    return delivered
  }

  // Ordered message path (completely independent per stream_id!)
  if @packet.ssn_lt(chunk.stream_seq, st.next_ssn) {
    // Late fragment for an already delivered or PR-SCTP skipped SSN.
    self.insert_tsn(chunk.tsn)
    return delivered
  }

  let mut slot_idx = -1
  for i = 0; i < st.pending_ordered.length(); i = i + 1 {
    if st.pending_ordered[i].stream_seq == chunk.stream_seq {
      slot_idx = i
      break
    }
  }
  if slot_idx >= 0 {
    let slot = st.pending_ordered[slot_idx]
    let next_total = slot.total_bytes + chunk.payload.length()
    if next_total > self.max_message_size {
      // Purge oversized reassembly buffer to prevent OOM DoS.
      self.buffered_bytes = max_int(0, self.buffered_bytes - slot.total_bytes)
      let _ = st.pending_ordered.remove(slot_idx)
      raise MessageTooLarge(next_total)
    }
    self.insert_tsn(chunk.tsn)
    insert_frag_sorted(slot.frags, {
      tsn: chunk.tsn,
      ppid: chunk.ppid,
      beginning: chunk.beginning,
      ending: chunk.ending,
      payload: chunk.payload,
    })
    slot.total_bytes = next_total
    self.buffered_bytes = self.buffered_bytes + chunk.payload.length()
  } else {
    // Fast path for in-sequence single-fragment ordered message.
    if chunk.stream_seq == st.next_ssn && chunk.beginning && chunk.ending {
      self.insert_tsn(chunk.tsn)
      st.next_ssn = @packet.ssn_inc(st.next_ssn)
      delivered.push({
        stream_id: chunk.stream_id,
        ppid: chunk.ppid,
        unordered: false,
        payload: chunk.payload,
      })
      self.drain_ordered_stream(chunk.stream_id, delivered)
      return delivered
    }
    self.insert_tsn(chunk.tsn)
    st.pending_ordered.push({
      stream_seq: chunk.stream_seq,
      frags: [
        {
          tsn: chunk.tsn,
          ppid: chunk.ppid,
          beginning: chunk.beginning,
          ending: chunk.ending,
          payload: chunk.payload,
        },
      ],
      total_bytes: chunk.payload.length(),
    })
    self.buffered_bytes = self.buffered_bytes + chunk.payload.length()
  }

  self.drain_ordered_stream(chunk.stream_id, delivered)
  delivered
}

///|
/// Applies an incoming RFC 3758 FORWARD_TSN chunk, advancing cumulative TSN and
/// stream SSNs, pruning abandoned fragments, and immediately delivering newly
/// unblocked messages.
fn RecvTracker::on_forward_tsn(
  self : RecvTracker,
  ft : @packet.ForwardTsnChunk,
) -> Array[DeliveredMessage] {
  let delivered : Array[DeliveredMessage] = []

  if @packet.tsn_gt(ft.new_cum_tsn, self.cum_tsn) {
    self.cum_tsn = ft.new_cum_tsn
    let remaining : Array[UInt32] = []
    for i = 0; i < self.out_of_order_tsns.length(); i = i + 1 {
      let t = self.out_of_order_tsns[i]
      if @packet.tsn_gt(t, self.cum_tsn) {
        remaining.push(t)
      }
    }
    self.out_of_order_tsns.clear()
    for i = 0; i < remaining.length(); i = i + 1 {
      self.out_of_order_tsns.push(remaining[i])
    }
    self.advance_cum_tsn()

    // Prune abandoned unordered fragments at or below new_cum_tsn.
    for sid = 0; sid < self.streams.length(); sid = sid + 1 {
      let st = self.streams[sid]
      if st.pending_unordered.length() > 0 {
        let kept : Array[RecvFrag] = []
        let mut removed_bytes = 0
        for j = 0; j < st.pending_unordered.length(); j = j + 1 {
          let f = st.pending_unordered[j]
          if @packet.tsn_le(f.tsn, ft.new_cum_tsn) {
            removed_bytes = removed_bytes + f.payload.length()
          } else {
            kept.push(f)
          }
        }
        st.pending_unordered.clear()
        for j = 0; j < kept.length(); j = j + 1 {
          st.pending_unordered.push(kept[j])
        }
        st.unordered_bytes = max_int(0, st.unordered_bytes - removed_bytes)
        self.buffered_bytes = max_int(0, self.buffered_bytes - removed_bytes)
      }
    }
  }

  for i = 0; i < ft.streams.length(); i = i + 1 {
    let entry = ft.streams[i]
    if entry.stream_id < self.streams.length().reinterpret_as_uint() {
      let st = self.streams[entry.stream_id.reinterpret_as_int()]
      if @packet.ssn_le(st.next_ssn, entry.stream_seq) {
        st.next_ssn = @packet.ssn_inc(entry.stream_seq)
      }
      let kept : Array[OrderedMsgBuf] = []
      let mut removed_bytes = 0
      for j = 0; j < st.pending_ordered.length(); j = j + 1 {
        let slot = st.pending_ordered[j]
        if @packet.ssn_le(slot.stream_seq, entry.stream_seq) {
          removed_bytes = removed_bytes + slot.total_bytes
        } else {
          kept.push(slot)
        }
      }
      st.pending_ordered.clear()
      for j = 0; j < kept.length(); j = j + 1 {
        st.pending_ordered.push(kept[j])
      }
      self.buffered_bytes = max_int(0, self.buffered_bytes - removed_bytes)
      self.drain_ordered_stream(entry.stream_id, delivered)
    }
  }

  delivered
}

///|
/// Builds an RFC 9260 SACK chunk reflecting exact cumulative TSN, Gap Ack Blocks,
/// advertised receive window, and duplicate TSNs (clearing dup_tsns).
fn RecvTracker::build_sack(self : RecvTracker) -> @packet.SackChunk {
  let gap_blocks : Array[@packet.GapAckBlock] = []
  let n = self.out_of_order_tsns.length()
  let mut i = 0
  while i < n {
    let block_start = self.out_of_order_tsns[i]
    let mut block_end = block_start
    while i + 1 < n && self.out_of_order_tsns[i + 1] == block_end + 1U {
      i = i + 1
      block_end = self.out_of_order_tsns[i]
    }
    let start_off = @packet.tsn_diff(block_start, self.cum_tsn)
    let end_off = @packet.tsn_diff(block_end, self.cum_tsn)
    if start_off >= 1 && end_off >= start_off && end_off <= 65535 {
      gap_blocks.push({
        start: start_off.reinterpret_as_uint(),
        end: end_off.reinterpret_as_uint(),
      })
    }
    i = i + 1
  }

  let dup_copy : Array[UInt32] = Array(capacity=self.dup_tsns.length())
  for k = 0; k < self.dup_tsns.length(); k = k + 1 {
    dup_copy.push(self.dup_tsns[k])
  }
  self.dup_tsns.clear()

  let arwnd = if self.buffered_bytes >= self.base_arwnd.reinterpret_as_int() {
    0U
  } else {
    self.base_arwnd - self.buffered_bytes.reinterpret_as_uint()
  }

  { cum_tsn_ack: self.cum_tsn, a_rwnd: arwnd, gap_blocks, dup_tsns: dup_copy, }
}
