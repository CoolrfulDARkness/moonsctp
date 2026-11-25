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
fn u32_to_hex(v : UInt32) -> String {
  let arr = FixedArray::make(4, b'\x00')
  arr[0] = ((v >> 24) & 0xFFU).to_byte()
  arr[1] = ((v >> 16) & 0xFFU).to_byte()
  arr[2] = ((v >> 8) & 0xFFU).to_byte()
  arr[3] = (v & 0xFFU).to_byte()
  to_hex(Bytes::from_array(arr))
}

///|
fn emit_bytes(key : String, val : Bytes) -> Unit {
  println("\{key}=\{to_hex(val)}")
}

///|
fn emit_u32(key : String, val : UInt32) -> Unit {
  println("\{key}=\{u32_to_hex(val)}")
}

///|
/// Emits 6 classes of RFC 9260 / RFC 3758 SCTP wire packets, HMAC-SHA256 cookies,
/// and Castagnoli CRC-32C vectors for independent Python wire dissection.
fn main {
  // 1. Castagnoli CRC-32C reference vectors
  let inc32_arr = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    inc32_arr[i] = i.to_byte()
  }
  let inc32 = Bytes::from_array(inc32_arr)
  let long_msg = b"MoonSCTP RFC 9260 Castagnoli CRC-32C cross-language verification payload (73B)"
  emit_u32("CRC_EMPTY", @crc32c.crc32c(b""))
  emit_u32("CRC_123456789", @crc32c.crc32c(b"123456789"))
  emit_u32("CRC_INC32", @crc32c.crc32c(inc32))
  emit_bytes("CRC_LONG_MSG", long_msg)
  emit_u32("CRC_LONG_VAL", @crc32c.crc32c(long_msg))

  // 2. Stateless 64-byte HMAC-SHA256 Cookie
  let secret = b"moonsctp-interop-hmac-secret-32b"
  let c_payload : @cookie.CookiePayload = {
    local_vtag: 0x55667788U,
    peer_vtag: 0x11223344U,
    local_tsn: 0x10000001U,
    peer_tsn: 0xFFFFFFFEU,
    out_streams: 16U,
    in_streams: 32U,
    peer_arwnd: 131072U,
    created_ms: 1780272000123UL,
  }
  let cookie_wire = @cookie.seal_cookie(secret, c_payload)
  emit_bytes("COOKIE_SECRET", secret)
  emit_bytes("COOKIE_WIRE", cookie_wire)

  // 3. Packet 1: INIT with Forward-TSN Supported TLV (0xC000) & near-wraparound initial TSN
  let pkt_init : @packet.Packet = {
    src_port: 5000U,
    dst_port: 5001U,
    verification_tag: 0U,
    chunks: [
      @packet.Chunk::Init({
        initiate_tag: 0x11223344U,
        a_rwnd: 131072U,
        num_outbound_streams: 16U,
        num_inbound_streams: 32U,
        initial_tsn: 0xFFFFFFFEU,
        forward_tsn_supported: true,
      }),
    ],
  }
  emit_bytes("PKT_INIT", try! @packet.encode_packet(pkt_init))

  // 4. Packet 2: INIT_ACK with 64B HMAC-SHA256 State Cookie + Forward-TSN Supported TLV
  let pkt_init_ack : @packet.Packet = {
    src_port: 5001U,
    dst_port: 5000U,
    verification_tag: 0x11223344U,
    chunks: [
      @packet.Chunk::InitAck({
        initiate_tag: 0x55667788U,
        a_rwnd: 262144U,
        num_outbound_streams: 16U,
        num_inbound_streams: 16U,
        initial_tsn: 0x10000001U,
        state_cookie: cookie_wire,
        forward_tsn_supported: true,
      }),
    ],
  }
  emit_bytes("PKT_INIT_ACK", try! @packet.encode_packet(pkt_init_ack))

  // 5. Packet 3: COOKIE_ECHO + COOKIE_ACK bundled
  let pkt_cookie_echo_ack : @packet.Packet = {
    src_port: 5000U,
    dst_port: 5001U,
    verification_tag: 0x55667788U,
    chunks: [@packet.Chunk::CookieEcho(cookie_wire), @packet.Chunk::CookieAck],
  }
  emit_bytes(
    "PKT_COOKIE_ECHO_ACK",
    try! @packet.encode_packet(pkt_cookie_echo_ack),
  )

  // 6. Packet 4: Multi-chunk bundle with non-4B-aligned DATA (B/E/U flags) + SACK (Gap + Dup TSN)
  let pkt_data_sack : @packet.Packet = {
    src_port: 5000U,
    dst_port: 5001U,
    verification_tag: 0x55667788U,
    chunks: [
      @packet.Chunk::Data({
        tsn: 0xFFFFFFFFU,
        stream_id: 3U,
        stream_seq: 42U,
        ppid: 51U, // WebRTC String PPID
        unordered: false,
        beginning: true,
        ending: true,
        payload: b"Hello, SCTP!!", // 13 bytes -> requires 3 zero padding bytes
      }),
      @packet.Chunk::Data({
        tsn: 0x00000000U, // TSN wraparound!
        stream_id: 7U,
        stream_seq: 0U,
        ppid: 53U, // WebRTC Binary PPID
        unordered: true,
        beginning: true,
        ending: false,
        payload: b"FRAG1", // 5 bytes -> requires 3 zero padding bytes
      }),
      @packet.Chunk::Sack({
        cum_tsn_ack: 0xFFFFFFFFU,
        a_rwnd: 130000U,
        gap_blocks: [{ start: 2U, end: 4U, }, { start: 7U, end: 9U, }],
        dup_tsns: [0x00000001U, 0xFFFFFFFFU],
      }),
    ],
  }
  emit_bytes("PKT_DATA_SACK_BUNDLE", try! @packet.encode_packet(pkt_data_sack))

  // 7. Packet 5: HEARTBEAT + HEARTBEAT_ACK with non-4B-aligned info payloads
  let pkt_heartbeat : @packet.Packet = {
    src_port: 5000U,
    dst_port: 5001U,
    verification_tag: 0x55667788U,
    chunks: [
      @packet.Chunk::Heartbeat(b"hb-probe-17bytes!"), // 17 bytes
      @packet.Chunk::HeartbeatAck(b"hb-ack-11b!"), // 11 bytes
    ],
  }
  emit_bytes("PKT_HEARTBEAT", try! @packet.encode_packet(pkt_heartbeat))

  // 8. Packet 6: FORWARD_TSN (RFC 3758) + SHUTDOWN + ABORT (T-bit + ErrorCause)
  let pkt_fwd_shutdown_abort : @packet.Packet = {
    src_port: 5001U,
    dst_port: 5000U,
    verification_tag: 0x11223344U,
    chunks: [
      @packet.Chunk::ForwardTsn({
        new_cum_tsn: 0x00000005U,
        streams: [
          { stream_id: 0U, stream_seq: 3U, },
          { stream_id: 2U, stream_seq: 7U, },
        ],
      }),
      @packet.Chunk::Shutdown(0x00000005U),
      @packet.Chunk::Abort(true, [{ code: 12U, info: b"user abort!", }]),
    ],
  }
  emit_bytes(
    "PKT_FWD_SHUTDOWN_ABORT",
    try! @packet.encode_packet(pkt_fwd_shutdown_abort),
  )
}
