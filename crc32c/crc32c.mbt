///|
/// RFC 9260 Appendix B Castagnoli CRC-32C (`0x1EDC6F41`, reflected `0x82F63B78`).
/// Uses 4-slice lookup tables (1024 entries) for high-throughput Wasm/JS/Native execution.

///|
const POLY_REFLECTED : UInt32 = 0x82F63B78U

///|
fn build_tables() -> FixedArray[FixedArray[UInt32]] {
  let t0 = FixedArray::make(256, 0U)
  let t1 = FixedArray::make(256, 0U)
  let t2 = FixedArray::make(256, 0U)
  let t3 = FixedArray::make(256, 0U)
  for i = 0; i < 256; i = i + 1 {
    let mut c = i.reinterpret_as_uint()
    for _b = 0; _b < 8; _b = _b + 1 {
      if (c & 1U) != 0U {
        c = (c >> 1) ^ POLY_REFLECTED
      } else {
        c = c >> 1
      }
    }
    t0[i] = c
  }
  for i = 0; i < 256; i = i + 1 {
    let c0 = t0[i]
    let c1 = (c0 >> 8) ^ t0[(c0 & 0xFFU).reinterpret_as_int()]
    let c2 = (c1 >> 8) ^ t0[(c1 & 0xFFU).reinterpret_as_int()]
    let c3 = (c2 >> 8) ^ t0[(c2 & 0xFFU).reinterpret_as_int()]
    t1[i] = c1
    t2[i] = c2
    t3[i] = c3
  }
  [t0, t1, t2, t3]
}

///|
let tables : FixedArray[FixedArray[UInt32]] = build_tables()

///|
/// Streaming CRC-32C checksum builder.
pub struct Crc32c {
  mut state : UInt32
}

///|
pub fn Crc32c::new() -> Crc32c {
  { state: 0xFFFFFFFFU, }
}

///|
pub fn Crc32c::update_view(self : Crc32c, data : BytesView) -> Unit {
  let t0 = tables[0]
  let t1 = tables[1]
  let t2 = tables[2]
  let t3 = tables[3]
  let mut crc = self.state
  let len = data.length()
  let mut i = 0
  while i + 4 <= len {
    let w = data[i].to_uint() |
      (data[i + 1].to_uint() << 8) |
      (data[i + 2].to_uint() << 16) |
      (data[i + 3].to_uint() << 24)
    let x = crc ^ w
    crc = t3[(x & 0xFFU).reinterpret_as_int()] ^
      t2[((x >> 8) & 0xFFU).reinterpret_as_int()] ^
      t1[((x >> 16) & 0xFFU).reinterpret_as_int()] ^
      t0[((x >> 24) & 0xFFU).reinterpret_as_int()]
    i = i + 4
  }
  while i < len {
    let idx = ((crc ^ data[i].to_uint()) & 0xFFU).reinterpret_as_int()
    crc = (crc >> 8) ^ t0[idx]
    i = i + 1
  }
  self.state = crc
}

///|
pub fn Crc32c::update(self : Crc32c, data : Bytes) -> Unit {
  self.update_view(data[:])
}

///|
pub fn Crc32c::finalize(self : Crc32c) -> UInt32 {
  self.state ^ 0xFFFFFFFFU
}

///|
/// Computes Castagnoli CRC-32C over `Bytes`.
pub fn crc32c(data : Bytes) -> UInt32 {
  let h = Crc32c::new()
  h.update(data)
  h.finalize()
}

///|
/// Computes Castagnoli CRC-32C over `BytesView`.
pub fn crc32c_view(data : BytesView) -> UInt32 {
  let h = Crc32c::new()
  h.update_view(data)
  h.finalize()
}

///|
/// Computes RFC 9260 §6.8 SCTP packet checksum (bytes 8..12 treated as zero).
pub fn sctp_packet_checksum(packet : BytesView) -> UInt32 {
  let h = Crc32c::new()
  if packet.length() < 12 {
    h.update_view(packet)
    return h.finalize()
  }
  h.update_view(packet[0:8])
  h.update(b"\x00\x00\x00\x00")
  h.update_view(packet[12:])
  h.finalize()
}
