///|
/// IETF RFC 1982 Serial Number Arithmetic for 32-bit SCTP TSNs and 16-bit SSNs.
/// Handles full modular wraparound (`0xFFFFFFFF -> 0x00000000` and `0xFFFF -> 0x0000`).

///|
/// RFC 1982 §3.2 strict less-than comparison for 32-bit TSNs.
/// Returns `false` when `a == b` or when `a` and `b` differ by exactly `2^31`.
pub fn tsn_lt(a : UInt32, b : UInt32) -> Bool {
  a != b && b - a < 0x80000000U
}

///|
/// RFC 1982 less-than-or-equal comparison for 32-bit TSNs.
pub fn tsn_le(a : UInt32, b : UInt32) -> Bool {
  a == b || tsn_lt(a, b)
}

///|
/// RFC 1982 strict greater-than comparison for 32-bit TSNs.
pub fn tsn_gt(a : UInt32, b : UInt32) -> Bool {
  tsn_lt(b, a)
}

///|
/// RFC 1982 greater-than-or-equal comparison for 32-bit TSNs.
pub fn tsn_ge(a : UInt32, b : UInt32) -> Bool {
  a == b || tsn_lt(b, a)
}

///|
/// Signed modular difference `a - b` in 32-bit TSN space (positive if `a > b`,
/// negative if `a < b`, handling `0xFFFFFFFF -> 0x00000000` wraparound).
pub fn tsn_diff(a : UInt32, b : UInt32) -> Int32 {
  (a - b).reinterpret_as_int()
}

///|
/// RFC 1982 §3.2 strict less-than comparison for 16-bit Stream Sequence Numbers (SSNs).
pub fn ssn_lt(a : UInt32, b : UInt32) -> Bool {
  let a16 = a & 0xFFFFU
  let b16 = b & 0xFFFFU
  a16 != b16 && ((b16 - a16) & 0xFFFFU) < 0x8000U
}

///|
/// RFC 1982 less-than-or-equal comparison for 16-bit SSNs.
pub fn ssn_le(a : UInt32, b : UInt32) -> Bool {
  (a & 0xFFFFU) == (b & 0xFFFFU) || ssn_lt(a, b)
}

///|
/// Increments a 16-bit SSN with modular wraparound (`0xFFFF -> 0x0000`).
pub fn ssn_inc(a : UInt32) -> UInt32 {
  (a + 1U) & 0xFFFFU
}
