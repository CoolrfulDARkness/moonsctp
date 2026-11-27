# Third-Party Notices & Standards Attribution

`CoolrfulDARkness/moonsctp` is an original, clean-room, zero-FFI MoonBit implementation released under the Apache License 2.0 (`LICENSE`).

## Technical Standards Referenced

- **IETF RFC 9260**: *Stream Control Transmission Protocol (SCTP)* — packet/chunk wire format, 4-way stateless cookie handshake, multi-stream ordered/unordered delivery, SACK, congestion control, and Appendix B Castagnoli CRC-32C polynomial (`0x1EDC6F41` / reflected `0x82F63B78`).
- **IETF RFC 3758**: *Stream Control Transmission Protocol (SCTP) Partial Reliability Extension (PR-SCTP)* — `FORWARD_TSN` chunk (`0xC0`), `0xC000` capability parameter, and timed/max-retransmit abandonment policies.
- **IETF RFC 1982**: *Serial Number Arithmetic* — 32-bit TSN and 16-bit SSN wrap-around comparison semantics.
- **IETF RFC 4231 / FIPS 180-4**: *HMAC-SHA-256* — stateless anti-SYN-flood cookie authentication and official test vectors.
- **IETF RFC 8831**: *WebRTC Data Channels* — architectural motivation for multi-stream HOL-free Sans-I/O SCTP transport.

## Independent Verification Baselines

- `harness/interop_wire.py` uses Python 3 standard library only (`hashlib`, `hmac`, `struct`) to implement an independent bitwise Castagnoli CRC-32C calculator and RFC 9260 packet dissector for cross-language wire verification. No third-party C/Rust/Go SCTP source code is copied or linked into this repository.
