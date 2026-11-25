///|
/// IETF RFC 9260 §3.1–3.2 SCTP Packet Wire Encoder & Decoder with
/// 12-Byte Common Header, 4-Byte Chunk Alignment Padding, and Little-Endian
/// Castagnoli CRC-32C Checksum Verification (RFC 9260 §6.8 / Appendix B).

///|
pub const COMMON_HEADER_LEN : Int32 = 12

///|
/// Decoded RFC 9260 SCTP Packet.
#derive(Debug, Eq)
pub(all) struct Packet {
  src_port : UInt32
  dst_port : UInt32
  verification_tag : UInt32
  chunks : Array[Chunk]
}

///|
fn write_le32_arr(out : FixedArray[Byte], off : Int32, v : UInt32) -> Unit {
  out[off] = (v & 0xFFU).to_byte()
  out[off + 1] = ((v >> 8) & 0xFFU).to_byte()
  out[off + 2] = ((v >> 16) & 0xFFU).to_byte()
  out[off + 3] = ((v >> 24) & 0xFFU).to_byte()
}

///|
fn read_le32(buf : BytesView, off : Int32) -> UInt32 {
  buf[off].to_uint() |
  (buf[off + 1].to_uint() << 8) |
  (buf[off + 2].to_uint() << 16) |
  (buf[off + 3].to_uint() << 24)
}

///|
/// Serializes an SCTP `Packet` into wire bytes:
/// 12-byte common header (`src_port`, `dst_port`, `verification_tag`, little-endian
/// Castagnoli CRC-32C) followed by 4-byte aligned bundled chunks.
pub fn encode_packet(pkt : Packet) -> Bytes raise PacketError {
  let out : Array[Byte] = []
  push_be16(out, pkt.src_port)
  push_be16(out, pkt.dst_port)
  push_be32(out, pkt.verification_tag)
  // Placeholder 4 zero bytes for CRC-32C checksum at offset 8..12
  push_be32(out, 0U)
  for i = 0; i < pkt.chunks.length(); i = i + 1 {
    let (ctype, flags, body) = encode_chunk_parts(pkt.chunks[i])
    let chunk_len = 4 + body.length()
    if chunk_len > 65535 {
      raise InvalidChunkLength(chunk_len)
    }
    out.push(ctype)
    out.push(flags)
    push_be16(out, chunk_len.reinterpret_as_uint())
    push_bytes(out, body)
    // RFC 9260 §3.2: 4-byte zero padding after chunks whose length is not a multiple of 4
    push_pad4(out, chunk_len)
  }
  let buf = FixedArray::make(out.length(), b'\x00')
  for i = 0; i < out.length(); i = i + 1 {
    buf[i] = out[i]
  }
  let pre_bytes = Bytes::from_array(buf)
  let checksum = @crc32c.sctp_packet_checksum(pre_bytes[:])
  // RFC 9260 §6.8 / Appendix B: write CRC-32C in little-endian byte order at bytes 8..12
  write_le32_arr(buf, 8, checksum)
  Bytes::from_array(buf)
}

///|
/// Decodes and validates a wire SCTP packet:
/// - Rejects packets `< 12` bytes with `TooShort`
/// - Verifies little-endian Castagnoli CRC-32C (`BadChecksum(expected, actual)`)
/// - Parses all bundled chunks with strict length/boundary validation and
///   RFC 9260 §3.2 top-2-bit unknown chunk handling.
pub fn decode_packet(raw : BytesView) -> Packet raise PacketError {
  if raw.length() < COMMON_HEADER_LEN {
    raise TooShort(raw.length())
  }
  let actual_crc = read_le32(raw, 8)
  let expected_crc = @crc32c.sctp_packet_checksum(raw)
  if actual_crc != expected_crc {
    raise BadChecksum(expected_crc, actual_crc)
  }
  let src_port = read_be16(raw, 0)
  let dst_port = read_be16(raw, 2)
  let verification_tag = read_be32(raw, 4)
  let chunks : Array[Chunk] = []
  let mut pos = COMMON_HEADER_LEN
  while pos < raw.length() {
    if pos + 4 > raw.length() {
      raise TruncatedChunk
    }
    let chunk_type = raw[pos]
    let flags = raw[pos + 1]
    let chunk_len = read_be16(raw, pos + 2).reinterpret_as_int()
    if chunk_len < 4 {
      raise InvalidChunkLength(chunk_len)
    }
    if pos + chunk_len > raw.length() {
      raise TruncatedChunk
    }
    let body = raw[pos + 4:pos + chunk_len]
    match decode_chunk(chunk_type, flags, body) {
      Some(c) => chunks.push(c)
      None => ()
    }
    if pos + chunk_len == raw.length() {
      break
    }
    let pad = (4 - chunk_len % 4) % 4
    if pos + chunk_len + pad > raw.length() {
      raise TruncatedChunk
    }
    pos = pos + chunk_len + pad
  }
  { src_port, dst_port, verification_tag, chunks, }
}
