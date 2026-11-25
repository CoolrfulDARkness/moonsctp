///|
fn raw_with_valid_crc(body_after_hdr : Bytes, vtag : UInt32) -> Bytes {
  let total = 12 + body_after_hdr.length()
  let buf = FixedArray::make(total, b'\x00')
  // src_port = 5000 (0x1388), dst_port = 5001 (0x1389)
  buf[0] = b'\x13'
  buf[1] = b'\x88'
  buf[2] = b'\x13'
  buf[3] = b'\x89'
  buf[4] = ((vtag >> 24) & 0xFFU).to_byte()
  buf[5] = ((vtag >> 16) & 0xFFU).to_byte()
  buf[6] = ((vtag >> 8) & 0xFFU).to_byte()
  buf[7] = (vtag & 0xFFU).to_byte()
  for i = 0; i < body_after_hdr.length(); i = i + 1 {
    buf[12 + i] = body_after_hdr[i]
  }
  let pre = Bytes::from_array(buf)
  let crc = @crc32c.sctp_packet_checksum(pre[:])
  buf[8] = (crc & 0xFFU).to_byte()
  buf[9] = ((crc >> 8) & 0xFFU).to_byte()
  buf[10] = ((crc >> 16) & 0xFFU).to_byte()
  buf[11] = ((crc >> 24) & 0xFFU).to_byte()
  Bytes::from_array(buf)
}

///|
fn flip_pkt_byte(data : Bytes, idx : Int32, mask : UInt32) -> Bytes {
  let buf = FixedArray::make(data.length(), b'\x00')
  for i = 0; i < data.length(); i = i + 1 {
    buf[i] = data[i]
  }
  buf[idx] = (buf[idx].to_uint() ^ mask).to_byte()
  Bytes::from_array(buf)
}

///|
test "RFC 1982 32-bit TSN and 16-bit SSN wraparound serial arithmetic" {
  // Normal comparisons
  assert_true(@packet.tsn_lt(10U, 20U))
  assert_true(@packet.tsn_le(10U, 10U))
  assert_true(@packet.tsn_gt(20U, 10U))
  assert_true(@packet.tsn_ge(20U, 20U))
  assert_eq(@packet.tsn_diff(20U, 10U), 10)
  assert_eq(@packet.tsn_diff(10U, 20U), -10)
  // 32-bit wraparound across 0xFFFFFFFF -> 0x00000000
  assert_true(@packet.tsn_lt(0xFFFFFFFEU, 0xFFFFFFFFU))
  assert_true(@packet.tsn_lt(0xFFFFFFFFU, 0x00000000U))
  assert_true(@packet.tsn_lt(0xFFFFFFFFU, 0x00000005U))
  assert_true(@packet.tsn_gt(0x00000000U, 0xFFFFFFFFU))
  assert_true(@packet.tsn_gt(0x00000005U, 0xFFFFFFF0U))
  assert_true(!@packet.tsn_lt(0x00000000U, 0xFFFFFFFFU))
  assert_eq(@packet.tsn_diff(0x00000000U, 0xFFFFFFFFU), 1)
  assert_eq(@packet.tsn_diff(0xFFFFFFFFU, 0x00000000U), -1)
  assert_eq(@packet.tsn_diff(0x00000003U, 0xFFFFFFFEU), 5)
  // Exact 2^31 boundary is incomparable in RFC 1982
  assert_true(!@packet.tsn_lt(0x00000000U, 0x80000000U))
  assert_true(!@packet.tsn_lt(0x80000000U, 0x00000000U))
  assert_true(@packet.tsn_lt(0x00000000U, 0x7FFFFFFFU))
  // 16-bit SSN wraparound across 0xFFFF -> 0x0000
  assert_true(@packet.ssn_lt(0xFFFEU, 0xFFFFU))
  assert_true(@packet.ssn_lt(0xFFFFU, 0x0000U))
  assert_true(@packet.ssn_lt(0xFFFFU, 0x0010U))
  assert_true(!@packet.ssn_lt(0x0000U, 0xFFFFU))
  assert_true(@packet.ssn_le(0xFFFFU, 0xFFFFU))
  assert_true(!@packet.ssn_lt(0x0000U, 0x8000U))
  assert_eq(@packet.ssn_inc(0xFFFEU), 0xFFFFU)
  assert_eq(@packet.ssn_inc(0xFFFFU), 0x0000U)
  assert_eq(@packet.ssn_inc(0x0000U), 0x0001U)
}

///|
test "all 14 RFC 9260 + RFC 3758 SCTP chunk types exact encode/decode round-trip" {
  let all_chunks : Array[@packet.Chunk] = [
    @packet.Data({
      tsn: 0x12345678U,
      stream_id: 3U,
      stream_seq: 42U,
      ppid: 51U,
      unordered: false,
      beginning: true,
      ending: true,
      payload: b"hello sctp!",
    }),
    @packet.Data({
      tsn: 0xFFFFFFFFU,
      stream_id: 7U,
      stream_seq: 0U,
      ppid: 53U,
      unordered: true,
      beginning: true,
      ending: false,
      payload: b"X",
    }),
    @packet.Init({
      initiate_tag: 0xAABBCCDDU,
      a_rwnd: 131072U,
      num_outbound_streams: 16U,
      num_inbound_streams: 64U,
      initial_tsn: 0x01020304U,
      forward_tsn_supported: true,
    }),
    @packet.Init({
      initiate_tag: 0x11223344U,
      a_rwnd: 65536U,
      num_outbound_streams: 1U,
      num_inbound_streams: 1U,
      initial_tsn: 0U,
      forward_tsn_supported: false,
    }),
    @packet.InitAck({
      initiate_tag: 0xDEADBEEFU,
      a_rwnd: 262144U,
      num_outbound_streams: 32U,
      num_inbound_streams: 32U,
      initial_tsn: 0xCAFEBABEU,
      state_cookie: b"signed-hmac-cookie-payload-odd-len!",
      forward_tsn_supported: true,
    }),
    @packet.Sack({
      cum_tsn_ack: 1000U,
      a_rwnd: 65535U,
      gap_blocks: [{ start: 2U, end: 5U, }, { start: 8U, end: 10U, }],
      dup_tsns: [1003U, 1009U],
    }),
    @packet.Heartbeat(b"hb-nonce-12345"),
    @packet.HeartbeatAck(b"hb-nonce-12345"),
    @packet.Abort(true, [
      { code: 1U, info: b"bad", },
      { code: 12U, info: b"user-initiated-abort", },
    ]),
    @packet.Shutdown(0x00001234U),
    @packet.ShutdownAck,
    @packet.Error([{ code: 3U, info: b"stale-cookie", }]),
    @packet.CookieEcho(b"opaque-state-cookie-bytes"),
    @packet.CookieAck,
    @packet.ShutdownComplete(true),
    @packet.ShutdownComplete(false),
    @packet.ForwardTsn({
      new_cum_tsn: 2050U,
      streams: [
        { stream_id: 1U, stream_seq: 10U, },
        { stream_id: 4U, stream_seq: 0xFFFFU, },
      ],
    }),
  ]
  for i = 0; i < all_chunks.length(); i = i + 1 {
    let pkt = @packet.Packet::{
      src_port: 5000U,
      dst_port: 5001U,
      verification_tag: 0x01020304U + i.reinterpret_as_uint(),
      chunks: [all_chunks[i]],
    }
    let wire = @packet.encode_packet(pkt)
    // Encoded packet is 4-byte aligned and >= 16 bytes
    assert_true(wire.length() >= 16)
    assert_eq(wire.length() % 4, 0)
    let decoded = @packet.decode_packet(wire[:])
    assert_eq(decoded, pkt)
  }
}

///|
test "multi-chunk bundling with 1B/2B/3B unaligned payloads and unpadded final chunk decoding" {
  let pkt = @packet.Packet::{
    src_port: 9000U,
    dst_port: 9001U,
    verification_tag: 0x55667788U,
    chunks: [
      @packet.Data({
        tsn: 1U,
        stream_id: 0U,
        stream_seq: 0U,
        ppid: 51U,
        unordered: false,
        beginning: true,
        ending: true,
        payload: b"A", // 1 byte -> 3 pad bytes
      }),
      @packet.Data({
        tsn: 2U,
        stream_id: 0U,
        stream_seq: 1U,
        ppid: 51U,
        unordered: false,
        beginning: true,
        ending: true,
        payload: b"BC", // 2 bytes -> 2 pad bytes
      }),
      @packet.Data({
        tsn: 3U,
        stream_id: 0U,
        stream_seq: 2U,
        ppid: 51U,
        unordered: false,
        beginning: true,
        ending: true,
        payload: b"DEF", // 3 bytes -> 1 pad byte
      }),
      @packet.Sack({
        cum_tsn_ack: 3U,
        a_rwnd: 65536U,
        gap_blocks: [],
        dup_tsns: [],
      }),
      @packet.CookieEcho(b"12345"), // 5 bytes -> 3 pad bytes
    ],
  }
  let wire = @packet.encode_packet(pkt)
  assert_eq(wire.length() % 4, 0)
  let decoded = @packet.decode_packet(wire[:])
  assert_eq(decoded, pkt)
  // Also verify decoding a packet whose final chunk omits trailing padding (permitted by RFC 9260 §3.2)
  // CookieEcho with 1-byte cookie ("Z"): chunk header(4) + 1 = 5 bytes, no trailing padding
  let unpadded = raw_with_valid_crc(
    Bytes::from_array([b'\x0A', b'\x00', b'\x00', b'\x05', b'Z']),
    0x11223344U,
  )
  assert_eq(unpadded.length(), 17)
  let dec_unpadded = @packet.decode_packet(unpadded[:])
  assert_eq(dec_unpadded.chunks, [@packet.CookieEcho(b"Z")])
}

///|
test "CRC-32C little-endian wire byte order verification and tamper rejection" {
  let pkt = @packet.Packet::{
    src_port: 5000U,
    dst_port: 5000U,
    verification_tag: 0x00000000U,
    chunks: [
      @packet.Init({
        initiate_tag: 0x12345678U,
        a_rwnd: 65536U,
        num_outbound_streams: 10U,
        num_inbound_streams: 10U,
        initial_tsn: 1U,
        forward_tsn_supported: true,
      }),
    ],
  }
  let wire = @packet.encode_packet(pkt)
  // Verify exact RFC 9260 §6.8 / Appendix B little-endian byte order at bytes 8..12
  let expected_crc = @crc32c.sctp_packet_checksum(wire[:])
  assert_eq(wire[8], (expected_crc & 0xFFU).to_byte())
  assert_eq(wire[9], ((expected_crc >> 8) & 0xFFU).to_byte())
  assert_eq(wire[10], ((expected_crc >> 16) & 0xFFU).to_byte())
  assert_eq(wire[11], ((expected_crc >> 24) & 0xFFU).to_byte())
  // Flip 1 bit in header, checksum, and chunk body -> all must raise BadChecksum
  for off in [0, 7, 8, 11, 12, wire.length() - 1] {
    let tampered = flip_pkt_byte(wire, off, 0x01U)
    let rej = try {
      ignore(@packet.decode_packet(tampered[:]))
      false
    } catch {
      @packet.BadChecksum(exp, act) => exp != act
      _ => false
    }
    assert_true(rej)
  }
}

///|
test "strict rejection of malformed packets, invalid chunk lengths, bad INIT, and RFC 9260 unknown chunk rules" {
  // 1. Packet too short (< 12B)
  for n in [0, 4, 11] {
    let rej = try {
      ignore(@packet.decode_packet(Bytes::make(n, b'\x00')[:]))
      false
    } catch {
      @packet.TooShort(l) => l == n
      _ => false
    }
    assert_true(rej)
  }
  // 2. Chunk length < 4 (e.g. length = 2)
  let bad_len_pkt = raw_with_valid_crc(
    Bytes::from_array([b'\x0B', b'\x00', b'\x00', b'\x02']),
    1U,
  )
  let r_lt4 = try {
    ignore(@packet.decode_packet(bad_len_pkt[:]))
    false
  } catch {
    @packet.InvalidChunkLength(2) => true
    _ => false
  }
  assert_true(r_lt4)
  // 3. Truncated chunk (declared length 20, only 8 bytes present)
  let trunc_pkt = raw_with_valid_crc(
    Bytes::from_array([
      b'\x00', b'\x03', b'\x00', b'\x14', b'\x00', b'\x00', b'\x00', b'\x01',
    ]),
    1U,
  )
  let r_trunc = try {
    ignore(@packet.decode_packet(trunc_pkt[:]))
    false
  } catch {
    @packet.TruncatedChunk => true
    _ => false
  }
  assert_true(r_trunc)
  // 4. Invalid INIT: initiate_tag == 0
  let zero_tag_init = @packet.encode_packet({
    src_port: 1U,
    dst_port: 2U,
    verification_tag: 0U,
    chunks: [
      @packet.Init({
        initiate_tag: 0U,
        a_rwnd: 65536U,
        num_outbound_streams: 4U,
        num_inbound_streams: 4U,
        initial_tsn: 1U,
        forward_tsn_supported: false,
      }),
    ],
  })
  let r_ztag = try {
    ignore(@packet.decode_packet(zero_tag_init[:]))
    false
  } catch {
    @packet.ProtocolViolation(_) => true
    _ => false
  }
  assert_true(r_ztag)
  // 5. Invalid INIT: num_outbound_streams == 0
  let zero_streams_init = @packet.encode_packet({
    src_port: 1U,
    dst_port: 2U,
    verification_tag: 0U,
    chunks: [
      @packet.Init({
        initiate_tag: 0x1234U,
        a_rwnd: 65536U,
        num_outbound_streams: 0U,
        num_inbound_streams: 4U,
        initial_tsn: 1U,
        forward_tsn_supported: false,
      }),
    ],
  })
  let r_zstr = try {
    ignore(@packet.decode_packet(zero_streams_init[:]))
    false
  } catch {
    @packet.ProtocolViolation(_) => true
    _ => false
  }
  assert_true(r_zstr)
  // 6. INIT-ACK missing State Cookie TLV
  let no_cookie_ack = raw_with_valid_crc(
    Bytes::from_array([
      b'\x02', b'\x00', b'\x00', b'\x14', b'\x11', b'\x22', b'\x33', b'\x44', b'\x00',
      b'\x01', b'\x00', b'\x00', b'\x00', b'\x04', b'\x00', b'\x04', b'\x00', b'\x00',
      b'\x00', b'\x01',
    ]),
    0x1234U,
  )
  let r_nocookie = try {
    ignore(@packet.decode_packet(no_cookie_ack[:]))
    false
  } catch {
    @packet.InvalidParameter(_) => true
    _ => false
  }
  assert_true(r_nocookie)
  // 7. DATA reserved upper flag bits (0x80) rejected with InvalidFlags
  let bad_flags = raw_with_valid_crc(
    Bytes::from_array([
      b'\x00', b'\x83', b'\x00', b'\x10', b'\x00', b'\x00', b'\x00', b'\x01', b'\x00',
      b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
    ]),
    1U,
  )
  let r_flags = try {
    ignore(@packet.decode_packet(bad_flags[:]))
    false
  } catch {
    @packet.InvalidFlags(b'\x83') => true
    _ => false
  }
  assert_true(r_flags)
  // 8. RFC 9260 §3.2 unknown chunk handling:
  //    - 0x20 (top 2 bits = 00) and 0x45 (top 2 bits = 01) => UnknownCriticalChunk
  for crit in [b'\x20', b'\x45'] {
    let crit_pkt = raw_with_valid_crc(
      Bytes::from_array([crit, b'\x00', b'\x00', b'\x04']),
      1U,
    )
    let r_crit = try {
      ignore(@packet.decode_packet(crit_pkt[:]))
      false
    } catch {
      @packet.UnknownCriticalChunk(c) => c == crit
      _ => false
    }
    assert_true(r_crit)
  }
  //    - 0x85 (top 2 bits = 10) and 0xC5 (top 2 bits = 11) => skipped, subsequent CookieAck decoded!
  let skip_pkt = raw_with_valid_crc(
    Bytes::from_array([
      b'\x85', b'\x00', b'\x00', b'\x05', b'\xAA', b'\x00', b'\x00', b'\x00', b'\xC5',
      b'\x00', b'\x00', b'\x04', b'\x0B', b'\x00', b'\x00', b'\x04',
    ]),
    1U,
  )
  let dec_skip = @packet.decode_packet(skip_pkt[:])
  assert_eq(dec_skip.chunks, [@packet.CookieAck])
}
