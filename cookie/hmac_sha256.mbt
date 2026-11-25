///|
/// Pure MoonBit HMAC-SHA256 and constant-time comparison for
/// RFC 9260 §5.1.3 stateless State Cookie generation and verification.

///|
let k256 : FixedArray[UInt32] = [
  0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
  0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
  0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
  0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
  0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
  0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
  0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
  0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
  0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
  0xc67178f2U,
]

///|
fn rotr32(x : UInt32, n : Int32) -> UInt32 {
  (x >> n) | (x << (32 - n))
}

///|
fn read_be32(b : FixedArray[Byte], off : Int32) -> UInt32 {
  (b[off].to_uint() << 24) |
  (b[off + 1].to_uint() << 16) |
  (b[off + 2].to_uint() << 8) |
  b[off + 3].to_uint()
}

///|
fn write_be32(b : FixedArray[Byte], off : Int32, v : UInt32) -> Unit {
  b[off] = ((v >> 24) & 0xFFU).to_byte()
  b[off + 1] = ((v >> 16) & 0xFFU).to_byte()
  b[off + 2] = ((v >> 8) & 0xFFU).to_byte()
  b[off + 3] = (v & 0xFFU).to_byte()
}

///|
pub fn sha256(data : Bytes) -> Bytes {
  let state : FixedArray[UInt32] = [
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU,
    0x1f83d9abU, 0x5be0cd19U,
  ]
  let len = data.length()
  let pad_blocks = (len + 9 + 63) / 64
  let padded = FixedArray::make(pad_blocks * 64, b'\x00')
  for i = 0; i < len; i = i + 1 {
    padded[i] = data[i]
  }
  padded[len] = b'\x80'
  let bit_len = len.to_uint64() << 3
  write_be32(padded, pad_blocks * 64 - 8, (bit_len >> 32).to_uint())
  write_be32(padded, pad_blocks * 64 - 4, (bit_len & 0xFFFFFFFFUL).to_uint())
  let w = FixedArray::make(64, 0U)
  let mut off = 0
  while off < pad_blocks * 64 {
    for i = 0; i < 16; i = i + 1 {
      w[i] = read_be32(padded, off + i * 4)
    }
    for i = 16; i < 64; i = i + 1 {
      let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
      let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
      w[i] = w[i - 16] + s0 + w[i - 7] + s1
    }
    let mut a = state[0]
    let mut b = state[1]
    let mut c = state[2]
    let mut d = state[3]
    let mut e = state[4]
    let mut f = state[5]
    let mut g = state[6]
    let mut h = state[7]
    for i = 0; i < 64; i = i + 1 {
      let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
      let ch = (e & f) ^ (e.lnot() & g)
      let t1 = h + s1 + ch + k256[i] + w[i]
      let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
      let maj = (a & b) ^ (a & c) ^ (b & c)
      let t2 = s0 + maj
      h = g
      g = f
      f = e
      e = d + t1
      d = c
      c = b
      b = a
      a = t1 + t2
    }
    state[0] = state[0] + a
    state[1] = state[1] + b
    state[2] = state[2] + c
    state[3] = state[3] + d
    state[4] = state[4] + e
    state[5] = state[5] + f
    state[6] = state[6] + g
    state[7] = state[7] + h
    off = off + 64
  }
  let out = FixedArray::make(32, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    write_be32(out, i * 4, state[i])
  }
  Bytes::from_array(out)
}

///|
pub fn hmac_sha256(key : Bytes, data : Bytes) -> Bytes {
  let k = if key.length() > 64 { sha256(key) } else { key }
  let inner = FixedArray::make(64 + data.length(), b'\x36')
  let outer = FixedArray::make(64 + 32, b'\x5c')
  for i = 0; i < k.length(); i = i + 1 {
    inner[i] = (k[i].to_uint() ^ 0x36U).to_byte()
    outer[i] = (k[i].to_uint() ^ 0x5CU).to_byte()
  }
  for i = 0; i < data.length(); i = i + 1 {
    inner[64 + i] = data[i]
  }
  let idig = sha256(Bytes::from_array(inner))
  for i = 0; i < 32; i = i + 1 {
    outer[64 + i] = idig[i]
  }
  sha256(Bytes::from_array(outer))
}

///|
/// Constant-time byte comparison for cookie MAC verification.
pub fn ct_eq(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0U
  for i = 0; i < a.length(); i = i + 1 {
    diff = diff | (a[i].to_uint() ^ b[i].to_uint())
  }
  diff == 0U
}

///|
/// Signed stateless State Cookie payload (RFC 9260 §5.1.3):
/// Wire layout (64 bytes):
/// `local_vtag(4) || peer_vtag(4) || local_tsn(4) || peer_tsn(4) ||
///  out_streams(2) || in_streams(2) || peer_arwnd(4) || created_ms(8) ||
///  mac_hmac_sha256(32)`
pub const COOKIE_WIRE_LEN : Int32 = 64

///|
#derive(Debug, Eq)
pub suberror CookieError {
  InvalidLength(Int32)
  InvalidMac
  Expired(UInt64)
}

///|
#derive(Debug, Eq)
pub(all) struct CookiePayload {
  local_vtag : UInt32
  peer_vtag : UInt32
  local_tsn : UInt32
  peer_tsn : UInt32
  out_streams : UInt32
  in_streams : UInt32
  peer_arwnd : UInt32
  created_ms : UInt64
}

///|
fn write_u16_be(buf : FixedArray[Byte], off : Int32, v : UInt32) -> Unit {
  buf[off] = ((v >> 8) & 0xFFU).to_byte()
  buf[off + 1] = (v & 0xFFU).to_byte()
}

///|
fn read_u16_be(b : Bytes, off : Int32) -> UInt32 {
  (b[off].to_uint() << 8) | b[off + 1].to_uint()
}

///|
fn read_u32_be(b : Bytes, off : Int32) -> UInt32 {
  (b[off].to_uint() << 24) |
  (b[off + 1].to_uint() << 16) |
  (b[off + 2].to_uint() << 8) |
  b[off + 3].to_uint()
}

///|
/// Seals a stateless cookie with HMAC-SHA256 under `secret`.
pub fn seal_cookie(secret : Bytes, payload : CookiePayload) -> Bytes {
  let body = FixedArray::make(32, b'\x00')
  write_be32(body, 0, payload.local_vtag)
  write_be32(body, 4, payload.peer_vtag)
  write_be32(body, 8, payload.local_tsn)
  write_be32(body, 12, payload.peer_tsn)
  write_u16_be(body, 16, payload.out_streams)
  write_u16_be(body, 18, payload.in_streams)
  write_be32(body, 20, payload.peer_arwnd)
  write_be32(body, 24, (payload.created_ms >> 32).to_uint())
  write_be32(body, 28, (payload.created_ms & 0xFFFFFFFFUL).to_uint())
  let body_bytes = Bytes::from_array(body)
  let mac = hmac_sha256(secret, body_bytes)
  let out = FixedArray::make(COOKIE_WIRE_LEN, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    out[i] = body_bytes[i]
    out[32 + i] = mac[i]
  }
  Bytes::from_array(out)
}

///|
/// Verifies HMAC-SHA256 in constant time and enforces lifetime (`now_ms - created_ms <= lifetime_ms`).
pub fn open_cookie(
  secret : Bytes,
  cookie : Bytes,
  now_ms : UInt64,
  lifetime_ms : UInt64,
) -> CookiePayload raise CookieError {
  if cookie.length() != COOKIE_WIRE_LEN {
    raise InvalidLength(cookie.length())
  }
  let body = FixedArray::make(32, b'\x00')
  let mac = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    body[i] = cookie[i]
    mac[i] = cookie[32 + i]
  }
  let body_bytes = Bytes::from_array(body)
  let expected = hmac_sha256(secret, body_bytes)
  if !ct_eq(expected, Bytes::from_array(mac)) {
    raise InvalidMac
  }
  let hi = read_u32_be(body_bytes, 24).to_uint64()
  let lo = read_u32_be(body_bytes, 28).to_uint64()
  let created_ms = (hi << 32) | lo
  if now_ms < created_ms || now_ms - created_ms > lifetime_ms {
    raise Expired(created_ms)
  }
  {
    local_vtag: read_u32_be(body_bytes, 0),
    peer_vtag: read_u32_be(body_bytes, 4),
    local_tsn: read_u32_be(body_bytes, 8),
    peer_tsn: read_u32_be(body_bytes, 12),
    out_streams: read_u16_be(body_bytes, 16),
    in_streams: read_u16_be(body_bytes, 18),
    peer_arwnd: read_u32_be(body_bytes, 20),
    created_ms,
  }
}
