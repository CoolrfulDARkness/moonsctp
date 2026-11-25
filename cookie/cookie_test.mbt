///|
fn to_hex(data : Bytes) -> String {
  let digits = "0123456789abcdef"
  let buf = StringBuilder()
  for i = 0; i < data.length(); i = i + 1 {
    let v = data[i].to_int()
    buf.write_char(digits[(v >> 4) & 0xF].to_int().unsafe_to_char())
    buf.write_char(digits[v & 0xF].to_int().unsafe_to_char())
  }
  buf.to_string()
}

///|
test "RFC 4231 HMAC-SHA256 vector and stateless cookie round-trip" {
  // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
  let mac = @cookie.hmac_sha256(b"Jefe", b"what do ya want for nothing?")
  assert_eq(
    to_hex(mac),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  )
  let secret = b"sctp-server-cookie-secret-key-01"
  let p : @cookie.CookiePayload = {
    local_vtag: 0x11223344U,
    peer_vtag: 0xAABBCCDDU,
    local_tsn: 1000U,
    peer_tsn: 2000U,
    out_streams: 16U,
    in_streams: 16U,
    peer_arwnd: 65536U,
    created_ms: 5000UL,
  }
  let cookie_bytes = @cookie.seal_cookie(secret, p)
  assert_eq(cookie_bytes.length(), 64)
  assert_eq(@cookie.open_cookie(secret, cookie_bytes, 10000UL, 60000UL), p)
  // Expired cookie rejected
  let expired = try {
    ignore(@cookie.open_cookie(secret, cookie_bytes, 70000UL, 60000UL))
    false
  } catch {
    @cookie.Expired(_) => true
    _ => false
  }
  assert_true(expired)
  // Tampered cookie rejected
  let bad = FixedArray::make(64, b'\x00')
  for i = 0; i < 64; i = i + 1 {
    bad[i] = cookie_bytes[i]
  }
  bad[0] = (bad[0].to_uint() ^ 0x01U).to_byte()
  let forged = try {
    ignore(
      @cookie.open_cookie(secret, Bytes::from_array(bad), 10000UL, 60000UL),
    )
    false
  } catch {
    @cookie.InvalidMac => true
    _ => false
  }
  assert_true(forged)
}
