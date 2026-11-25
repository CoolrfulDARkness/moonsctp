///|
/// IETF RFC 9260 §3.3 & RFC 3758 §3.2 SCTP Chunk Definitions, Constants,
/// Error Types, and Byte-Exact Chunk Wire Encoders/Decoders.

///|
pub const CHUNK_DATA : Byte = b'\x00'

///|
pub const CHUNK_INIT : Byte = b'\x01'

///|
pub const CHUNK_INIT_ACK : Byte = b'\x02'

///|
pub const CHUNK_SACK : Byte = b'\x03'

///|
pub const CHUNK_HEARTBEAT : Byte = b'\x04'

///|
pub const CHUNK_HEARTBEAT_ACK : Byte = b'\x05'

///|
pub const CHUNK_ABORT : Byte = b'\x06'

///|
pub const CHUNK_SHUTDOWN : Byte = b'\x07'

///|
pub const CHUNK_SHUTDOWN_ACK : Byte = b'\x08'

///|
pub const CHUNK_ERROR : Byte = b'\x09'

///|
pub const CHUNK_COOKIE_ECHO : Byte = b'\x0A'

///|
pub const CHUNK_COOKIE_ACK : Byte = b'\x0B'

///|
pub const CHUNK_SHUTDOWN_COMPLETE : Byte = b'\x0E'

///|
/// RFC 3758 §3.2 PR-SCTP FORWARD-TSN Chunk Type (`192 = 0xC0`).
pub const CHUNK_FORWARD_TSN : Byte = b'\xC0'

///|
pub const FLAG_DATA_E : Byte = b'\x01'

///|
pub const FLAG_DATA_B : Byte = b'\x02'

///|
pub const FLAG_DATA_U : Byte = b'\x04'

///|
pub const FLAG_DATA_I : Byte = b'\x08'

///|
const PARAM_HEARTBEAT_INFO : UInt32 = 0x0001U

///|
const PARAM_STATE_COOKIE : UInt32 = 0x0007U

///|
const PARAM_FORWARD_TSN_SUPPORTED : UInt32 = 0xC000U

///|
#derive(Debug, Eq)
pub suberror PacketError {
  TooShort(Int32)
  BadChecksum(UInt32, UInt32)
  InvalidChunkLength(Int32)
  TruncatedChunk
  InvalidParameter(String)
  UnknownCriticalChunk(Byte)
  InvalidFlags(Byte)
  ProtocolViolation(String)
}

///|
#derive(Debug, Eq)
pub(all) struct DataChunk {
  tsn : UInt32
  stream_id : UInt32
  stream_seq : UInt32
  ppid : UInt32
  unordered : Bool
  beginning : Bool
  ending : Bool
  payload : Bytes
}

///|
#derive(Debug, Eq)
pub(all) struct InitChunk {
  initiate_tag : UInt32
  a_rwnd : UInt32
  num_outbound_streams : UInt32
  num_inbound_streams : UInt32
  initial_tsn : UInt32
  forward_tsn_supported : Bool
}

///|
#derive(Debug, Eq)
pub(all) struct InitAckChunk {
  initiate_tag : UInt32
  a_rwnd : UInt32
  num_outbound_streams : UInt32
  num_inbound_streams : UInt32
  initial_tsn : UInt32
  state_cookie : Bytes
  forward_tsn_supported : Bool
}

///|
#derive(Debug, Eq)
pub(all) struct GapAckBlock {
  start : UInt32
  end : UInt32
}

///|
#derive(Debug, Eq)
pub(all) struct SackChunk {
  cum_tsn_ack : UInt32
  a_rwnd : UInt32
  gap_blocks : Array[GapAckBlock]
  dup_tsns : Array[UInt32]
}

///|
#derive(Debug, Eq)
pub(all) struct ErrorCause {
  code : UInt32
  info : Bytes
}

///|
#derive(Debug, Eq)
pub(all) struct ForwardTsnStream {
  stream_id : UInt32
  stream_seq : UInt32
}

///|
#derive(Debug, Eq)
pub(all) struct ForwardTsnChunk {
  new_cum_tsn : UInt32
  streams : Array[ForwardTsnStream]
}

///|
/// All 14 RFC 9260 + RFC 3758 SCTP chunk types.
#derive(Debug, Eq)
pub(all) enum Chunk {
  Data(DataChunk)
  Init(InitChunk)
  InitAck(InitAckChunk)
  Sack(SackChunk)
  Heartbeat(Bytes)
  HeartbeatAck(Bytes)
  Abort(Bool, Array[ErrorCause])
  Shutdown(UInt32)
  ShutdownAck
  Error(Array[ErrorCause])
  CookieEcho(Bytes)
  CookieAck
  ShutdownComplete(Bool)
  ForwardTsn(ForwardTsnChunk)
}

// ============================================================================
// Internal Big-Endian / Padding Helpers
// ============================================================================

///|
fn push_be16(out : Array[Byte], v : UInt32) -> Unit {
  out.push(((v >> 8) & 0xFFU).to_byte())
  out.push((v & 0xFFU).to_byte())
}

///|
fn push_be32(out : Array[Byte], v : UInt32) -> Unit {
  out.push(((v >> 24) & 0xFFU).to_byte())
  out.push(((v >> 16) & 0xFFU).to_byte())
  out.push(((v >> 8) & 0xFFU).to_byte())
  out.push((v & 0xFFU).to_byte())
}

///|
fn push_bytes(out : Array[Byte], data : Bytes) -> Unit {
  for i = 0; i < data.length(); i = i + 1 {
    out.push(data[i])
  }
}

///|
fn push_pad4(out : Array[Byte], unpadded_len : Int32) -> Unit {
  let pad = (4 - unpadded_len % 4) % 4
  for _i = 0; _i < pad; _i = _i + 1 {
    out.push(b'\x00')
  }
}

///|
fn read_be16(buf : BytesView, off : Int32) -> UInt32 {
  (buf[off].to_uint() << 8) | buf[off + 1].to_uint()
}

///|
fn read_be32(buf : BytesView, off : Int32) -> UInt32 {
  (buf[off].to_uint() << 24) |
  (buf[off + 1].to_uint() << 16) |
  (buf[off + 2].to_uint() << 8) |
  buf[off + 3].to_uint()
}

///|
fn slice_view(buf : BytesView, off : Int32, len : Int32) -> Bytes {
  let out = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    out[i] = buf[off + i]
  }
  Bytes::from_array(out)
}

///|
fn encode_tlv(
  out : Array[Byte],
  tlv_type : UInt32,
  val : Bytes,
  pad_trailing : Bool,
) -> Unit raise PacketError {
  let len = 4 + val.length()
  if len > 65535 {
    raise InvalidParameter("TLV parameter length exceeds 65535")
  }
  push_be16(out, tlv_type)
  push_be16(out, len.reinterpret_as_uint())
  push_bytes(out, val)
  if pad_trailing {
    push_pad4(out, len)
  }
}

///|
fn encode_error_causes(
  out : Array[Byte],
  causes : Array[ErrorCause],
) -> Unit raise PacketError {
  for i = 0; i < causes.length(); i = i + 1 {
    let is_last = i == causes.length() - 1
    encode_tlv(out, causes[i].code, causes[i].info, !is_last)
  }
}

///|
fn decode_error_causes(body : BytesView) -> Array[ErrorCause] raise PacketError {
  let causes : Array[ErrorCause] = []
  let mut pos = 0
  while pos < body.length() {
    if pos + 4 > body.length() {
      raise InvalidParameter("truncated error cause header")
    }
    let code = read_be16(body, pos)
    let len = read_be16(body, pos + 2).reinterpret_as_int()
    if len < 4 || pos + len > body.length() {
      raise InvalidParameter("invalid error cause length")
    }
    let info = slice_view(body, pos + 4, len - 4)
    causes.push({ code, info, })
    if pos + len == body.length() {
      break
    }
    let pad = (4 - len % 4) % 4
    if pos + len + pad > body.length() {
      raise InvalidParameter("truncated error cause padding")
    }
    pos = pos + len + pad
  }
  causes
}

///|
/// Encodes a single `Chunk` into `(chunk_type, flags, body_bytes)`.
fn encode_chunk_parts(chunk : Chunk) -> (Byte, Byte, Bytes) raise PacketError {
  let body : Array[Byte] = []
  match chunk {
    Data(d) => {
      let mut flags = 0U
      if d.ending {
        flags = flags | FLAG_DATA_E.to_uint()
      }
      if d.beginning {
        flags = flags | FLAG_DATA_B.to_uint()
      }
      if d.unordered {
        flags = flags | FLAG_DATA_U.to_uint()
      }
      push_be32(body, d.tsn)
      push_be16(body, d.stream_id)
      push_be16(body, d.stream_seq)
      push_be32(body, d.ppid)
      push_bytes(body, d.payload)
      (CHUNK_DATA, flags.to_byte(), Bytes::from_array(body))
    }
    Init(init) => {
      push_be32(body, init.initiate_tag)
      push_be32(body, init.a_rwnd)
      push_be16(body, init.num_outbound_streams)
      push_be16(body, init.num_inbound_streams)
      push_be32(body, init.initial_tsn)
      if init.forward_tsn_supported {
        encode_tlv(body, PARAM_FORWARD_TSN_SUPPORTED, b"", false)
      }
      (CHUNK_INIT, b'\x00', Bytes::from_array(body))
    }
    InitAck(ack) => {
      push_be32(body, ack.initiate_tag)
      push_be32(body, ack.a_rwnd)
      push_be16(body, ack.num_outbound_streams)
      push_be16(body, ack.num_inbound_streams)
      push_be32(body, ack.initial_tsn)
      encode_tlv(
        body,
        PARAM_STATE_COOKIE,
        ack.state_cookie,
        ack.forward_tsn_supported,
      )
      if ack.forward_tsn_supported {
        encode_tlv(body, PARAM_FORWARD_TSN_SUPPORTED, b"", false)
      }
      (CHUNK_INIT_ACK, b'\x00', Bytes::from_array(body))
    }
    Sack(s) => {
      if s.gap_blocks.length() > 65535 || s.dup_tsns.length() > 65535 {
        raise InvalidChunkLength(s.gap_blocks.length() + s.dup_tsns.length())
      }
      push_be32(body, s.cum_tsn_ack)
      push_be32(body, s.a_rwnd)
      push_be16(body, s.gap_blocks.length().reinterpret_as_uint())
      push_be16(body, s.dup_tsns.length().reinterpret_as_uint())
      for i = 0; i < s.gap_blocks.length(); i = i + 1 {
        push_be16(body, s.gap_blocks[i].start)
        push_be16(body, s.gap_blocks[i].end)
      }
      for i = 0; i < s.dup_tsns.length(); i = i + 1 {
        push_be32(body, s.dup_tsns[i])
      }
      (CHUNK_SACK, b'\x00', Bytes::from_array(body))
    }
    Heartbeat(info) => {
      encode_tlv(body, PARAM_HEARTBEAT_INFO, info, false)
      (CHUNK_HEARTBEAT, b'\x00', Bytes::from_array(body))
    }
    HeartbeatAck(info) => {
      encode_tlv(body, PARAM_HEARTBEAT_INFO, info, false)
      (CHUNK_HEARTBEAT_ACK, b'\x00', Bytes::from_array(body))
    }
    Abort(t_bit, causes) => {
      encode_error_causes(body, causes)
      let flags = if t_bit { b'\x01' } else { b'\x00' }
      (CHUNK_ABORT, flags, Bytes::from_array(body))
    }
    Shutdown(cum_tsn) => {
      push_be32(body, cum_tsn)
      (CHUNK_SHUTDOWN, b'\x00', Bytes::from_array(body))
    }
    ShutdownAck => (CHUNK_SHUTDOWN_ACK, b'\x00', b"")
    Error(causes) => {
      encode_error_causes(body, causes)
      (CHUNK_ERROR, b'\x00', Bytes::from_array(body))
    }
    CookieEcho(cookie) => (CHUNK_COOKIE_ECHO, b'\x00', cookie)
    CookieAck => (CHUNK_COOKIE_ACK, b'\x00', b"")
    ShutdownComplete(t_bit) => {
      let flags = if t_bit { b'\x01' } else { b'\x00' }
      (CHUNK_SHUTDOWN_COMPLETE, flags, b"")
    }
    ForwardTsn(ft) => {
      push_be32(body, ft.new_cum_tsn)
      for i = 0; i < ft.streams.length(); i = i + 1 {
        push_be16(body, ft.streams[i].stream_id)
        push_be16(body, ft.streams[i].stream_seq)
      }
      (CHUNK_FORWARD_TSN, b'\x00', Bytes::from_array(body))
    }
  }
}

///|
fn decode_heartbeat_info(body : BytesView) -> Bytes raise PacketError {
  if body.length() == 0 {
    return b""
  }
  if body.length() < 4 {
    raise InvalidParameter("truncated Heartbeat Info TLV header")
  }
  let ptype = read_be16(body, 0)
  let plen = read_be16(body, 2).reinterpret_as_int()
  if ptype != PARAM_HEARTBEAT_INFO || plen < 4 || plen > body.length() {
    raise InvalidParameter("invalid Heartbeat Info TLV")
  }
  slice_view(body, 4, plen - 4)
}

///|
fn parse_init_params(
  params : BytesView,
  require_cookie : Bool,
) -> (Bytes, Bool) raise PacketError {
  let mut cookie : Bytes = b""
  let mut has_cookie = false
  let mut fwd_tsn = false
  let mut pos = 0
  while pos < params.length() {
    if pos + 4 > params.length() {
      raise InvalidParameter("truncated TLV parameter header in INIT/INIT-ACK")
    }
    let ptype = read_be16(params, pos)
    let plen = read_be16(params, pos + 2).reinterpret_as_int()
    if plen < 4 || pos + plen > params.length() {
      raise InvalidParameter("invalid TLV parameter length in INIT/INIT-ACK")
    }
    if ptype == PARAM_STATE_COOKIE {
      cookie = slice_view(params, pos + 4, plen - 4)
      has_cookie = true
    } else if ptype == PARAM_FORWARD_TSN_SUPPORTED {
      if plen != 4 {
        raise InvalidParameter("Forward-TSN-Supported TLV length must be 4")
      }
      fwd_tsn = true
    } else {
      // RFC 9260 §3.2.1 unknown parameter top-2-bit handling
      let action = (ptype >> 14) & 0x03U
      if action == 0U {
        break
      } else if action == 1U {
        raise InvalidParameter(
          "unrecognized critical parameter: " + ptype.to_string(),
        )
      }
      // action == 2 or 3: skip and continue
    }
    if pos + plen == params.length() {
      break
    }
    let pad = (4 - plen % 4) % 4
    if pos + plen + pad > params.length() {
      raise InvalidParameter("truncated TLV parameter padding")
    }
    pos = pos + plen + pad
  }
  if require_cookie && (!has_cookie || cookie.length() == 0) {
    raise InvalidParameter("INIT-ACK missing non-empty State Cookie TLV")
  }
  (cookie, fwd_tsn)
}

///|
/// Decodes one chunk given `(chunk_type, flags, body)` (where `chunk_len == 4 + body.length()`).
/// Returns `None` if an unknown non-critical chunk (top bit set) is skipped per RFC 9260 §3.2.
fn decode_chunk(
  chunk_type : Byte,
  flags : Byte,
  body : BytesView,
) -> Chunk? raise PacketError {
  let chunk_len = 4 + body.length()
  match chunk_type {
    CHUNK_DATA => {
      if chunk_len < 16 {
        raise InvalidChunkLength(chunk_len)
      }
      // Reject reserved upper flag bits outside E|B|U|I (0x0F)
      if (flags.to_uint() & 0xF0U) != 0U {
        raise InvalidFlags(flags)
      }
      let tsn = read_be32(body, 0)
      let stream_id = read_be16(body, 4)
      let stream_seq = read_be16(body, 6)
      let ppid = read_be32(body, 8)
      let payload = slice_view(body, 12, body.length() - 12)
      Some(
        Data({
          tsn,
          stream_id,
          stream_seq,
          ppid,
          unordered: (flags.to_uint() & FLAG_DATA_U.to_uint()) != 0U,
          beginning: (flags.to_uint() & FLAG_DATA_B.to_uint()) != 0U,
          ending: (flags.to_uint() & FLAG_DATA_E.to_uint()) != 0U,
          payload,
        }),
      )
    }
    CHUNK_INIT => {
      if chunk_len < 20 {
        raise InvalidChunkLength(chunk_len)
      }
      let initiate_tag = read_be32(body, 0)
      let a_rwnd = read_be32(body, 4)
      let num_outbound_streams = read_be16(body, 8)
      let num_inbound_streams = read_be16(body, 10)
      let initial_tsn = read_be32(body, 12)
      if initiate_tag == 0U {
        raise ProtocolViolation("INIT initiate_tag must not be zero")
      }
      if num_outbound_streams == 0U || num_inbound_streams == 0U {
        raise ProtocolViolation("INIT stream counts must not be zero")
      }
      let (_, forward_tsn_supported) = parse_init_params(body[16:], false)
      Some(
        Init({
          initiate_tag,
          a_rwnd,
          num_outbound_streams,
          num_inbound_streams,
          initial_tsn,
          forward_tsn_supported,
        }),
      )
    }
    CHUNK_INIT_ACK => {
      if chunk_len < 20 {
        raise InvalidChunkLength(chunk_len)
      }
      let initiate_tag = read_be32(body, 0)
      let a_rwnd = read_be32(body, 4)
      let num_outbound_streams = read_be16(body, 8)
      let num_inbound_streams = read_be16(body, 10)
      let initial_tsn = read_be32(body, 12)
      if initiate_tag == 0U {
        raise ProtocolViolation("INIT-ACK initiate_tag must not be zero")
      }
      if num_outbound_streams == 0U || num_inbound_streams == 0U {
        raise ProtocolViolation("INIT-ACK stream counts must not be zero")
      }
      let (state_cookie, forward_tsn_supported) = parse_init_params(
        body[16:],
        true,
      )
      Some(
        InitAck({
          initiate_tag,
          a_rwnd,
          num_outbound_streams,
          num_inbound_streams,
          initial_tsn,
          state_cookie,
          forward_tsn_supported,
        }),
      )
    }
    CHUNK_SACK => {
      if chunk_len < 16 {
        raise InvalidChunkLength(chunk_len)
      }
      let cum_tsn_ack = read_be32(body, 0)
      let a_rwnd = read_be32(body, 4)
      let num_gaps = read_be16(body, 8).reinterpret_as_int()
      let num_dups = read_be16(body, 10).reinterpret_as_int()
      if 16 + num_gaps * 4 + num_dups * 4 != chunk_len {
        raise InvalidChunkLength(chunk_len)
      }
      let gap_blocks : Array[GapAckBlock] = Array(capacity=num_gaps)
      let mut pos = 12
      for _i = 0; _i < num_gaps; _i = _i + 1 {
        let start = read_be16(body, pos)
        let end = read_be16(body, pos + 2)
        gap_blocks.push({ start, end, })
        pos = pos + 4
      }
      let dup_tsns : Array[UInt32] = Array(capacity=num_dups)
      for _i = 0; _i < num_dups; _i = _i + 1 {
        dup_tsns.push(read_be32(body, pos))
        pos = pos + 4
      }
      Some(Sack({ cum_tsn_ack, a_rwnd, gap_blocks, dup_tsns, }))
    }
    CHUNK_HEARTBEAT => Some(Heartbeat(decode_heartbeat_info(body)))
    CHUNK_HEARTBEAT_ACK => Some(HeartbeatAck(decode_heartbeat_info(body)))
    CHUNK_ABORT => {
      let t_bit = (flags.to_uint() & 0x01U) != 0U
      let causes = decode_error_causes(body)
      Some(Abort(t_bit, causes))
    }
    CHUNK_SHUTDOWN => {
      if chunk_len != 8 {
        raise InvalidChunkLength(chunk_len)
      }
      Some(Shutdown(read_be32(body, 0)))
    }
    CHUNK_SHUTDOWN_ACK => {
      if chunk_len != 4 {
        raise InvalidChunkLength(chunk_len)
      }
      Some(ShutdownAck)
    }
    CHUNK_ERROR => Some(Error(decode_error_causes(body)))
    CHUNK_COOKIE_ECHO => Some(CookieEcho(slice_view(body, 0, body.length())))
    CHUNK_COOKIE_ACK => {
      if chunk_len != 4 {
        raise InvalidChunkLength(chunk_len)
      }
      Some(CookieAck)
    }
    CHUNK_SHUTDOWN_COMPLETE => {
      if chunk_len != 4 {
        raise InvalidChunkLength(chunk_len)
      }
      let t_bit = (flags.to_uint() & 0x01U) != 0U
      Some(ShutdownComplete(t_bit))
    }
    CHUNK_FORWARD_TSN => {
      if chunk_len < 8 || (chunk_len - 8) % 4 != 0 {
        raise InvalidChunkLength(chunk_len)
      }
      let new_cum_tsn = read_be32(body, 0)
      let num_streams = (body.length() - 4) / 4
      let streams : Array[ForwardTsnStream] = Array(capacity=num_streams)
      let mut pos = 4
      for _i = 0; _i < num_streams; _i = _i + 1 {
        let stream_id = read_be16(body, pos)
        let stream_seq = read_be16(body, pos + 2)
        streams.push({ stream_id, stream_seq, })
        pos = pos + 4
      }
      Some(ForwardTsn({ new_cum_tsn, streams, }))
    }
    _ => {
      // RFC 9260 §3.2 unknown chunk type handling via highest 2 bits:
      // 00 / 01 => stop processing packet (critical)
      // 10 / 11 => skip chunk and continue processing
      let action = (chunk_type.to_int() >> 6) & 0x03
      if action == 0 || action == 1 {
        raise UnknownCriticalChunk(chunk_type)
      }
      None
    }
  }
}
