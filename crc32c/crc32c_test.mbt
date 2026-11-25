///|
test "RFC 9260 / iSCSI official CRC-32C Castagnoli test vectors" {
  // Standard check value: "123456789" -> 0xE3069283
  assert_eq(@crc32c.crc32c(b"123456789"), 0xE3069283U)
  // Empty input -> 0x00000000
  assert_eq(@crc32c.crc32c(b""), 0x00000000U)
  // RFC 3720 / RFC 9260 Appendix B vectors:
  // 32 bytes of zeros -> 0x8A9136AA
  let zeros = Bytes::from_array(FixedArray::make(32, b'\x00'))
  assert_eq(@crc32c.crc32c(zeros), 0x8A9136AAU)
  // 32 bytes of 0xFF -> 0x62A8AB43
  let ones = Bytes::from_array(FixedArray::make(32, b'\xFF'))
  assert_eq(@crc32c.crc32c(ones), 0x62A8AB43U)
  // 32 bytes incrementing 0x00..0x1F -> 0x46DD794E
  let inc = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    inc[i] = i.to_byte()
  }
  assert_eq(@crc32c.crc32c(Bytes::from_array(inc)), 0x46DD794EU)
  // 32 bytes decrementing 0x1F..0x00 -> 0x113FDB5C
  let dec = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    dec[i] = (31 - i).to_byte()
  }
  assert_eq(@crc32c.crc32c(Bytes::from_array(dec)), 0x113FDB5CU)
}

///|
test "CRC-32C streaming matches one-shot across odd boundaries" {
  let msg = b"The quick brown fox jumps over the lazy dog 0123456789!"
  let h = @crc32c.Crc32c::new()
  h.update_view(msg[0:1])
  h.update_view(msg[1:6])
  h.update_view(msg[6:29])
  h.update_view(msg[29:])
  assert_eq(h.finalize(), @crc32c.crc32c(msg))
}
