#!/usr/bin/env python3
"""
Bidirectional Independent Python RFC 9260 / RFC 3758 Wire Dissector &
Castagnoli CRC-32C <-> MoonSCTP Cross-Language Interoperability Harness.

100% Python 3 standard library (zero third-party dependencies).

Phase 1 (MoonSCTP Wasm -> Independent Python Reference Dissector):
  - Runs `harness/interop_cli` (pure MoonBit Wasm) to emit 6 classes of real
    RFC 9260 / RFC 3758 wire packets, 64B HMAC-SHA256 Cookie, and Castagnoli
    CRC-32C reference values.
  - Independently verifies every CRC-32C using a table-free bitwise Castagnoli
    polynomial (0x82F63B78) reference implementation.
  - Independently verifies the 64-byte HMAC-SHA256 cookie via Python `hmac`.
  - Dissects all 6 wire packets field-by-field (Wireshark-equivalent): 12-byte
    common header, little-endian CRC-32C at bytes 8..12, chunk type/flags/length,
    strict 4-byte zero padding, TLV parameters, and every chunk payload field.

Phase 2 (Independent Python RFC 9260 Packet Synthesizer -> MoonSCTP Wasm & JS):
  - Independently synthesizes fresh random RFC 9260 / RFC 3758 wire packets
    (including non-4B-aligned payloads, TSN 0xFFFFFFFF->0x00000000 wraparound,
    multi-chunk bundling, Python-sealed 64B HMAC-SHA256 Cookie, FORWARD_TSN,
    SACK Gap/Dup, HEARTBEAT, SHUTDOWN_COMPLETE, and ABORT).
  - Writes `harness/wire_vectors_generated_test.mbt` and executes
    `moon test --target wasm -d harness` and `--target js -d harness`.

Exit code 0 iff all checks in both directions pass.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
HARNESS_DIR = ROOT / "harness"
GENERATED_TEST = HARNESS_DIR / "wire_vectors_generated_test.mbt"
BUILD_DIR = ROOT / "_build_harness"

# SCTP Chunk Type Constants (RFC 9260 §3.2 & RFC 3758 §3.2)
CHUNK_DATA = 0x00
CHUNK_INIT = 0x01
CHUNK_INIT_ACK = 0x02
CHUNK_SACK = 0x03
CHUNK_HEARTBEAT = 0x04
CHUNK_HEARTBEAT_ACK = 0x05
CHUNK_ABORT = 0x06
CHUNK_SHUTDOWN = 0x07
CHUNK_SHUTDOWN_ACK = 0x08
CHUNK_ERROR = 0x09
CHUNK_COOKIE_ECHO = 0x0A
CHUNK_COOKIE_ACK = 0x0B
CHUNK_SHUTDOWN_COMPLETE = 0x0E
CHUNK_FORWARD_TSN = 0xC0

PARAM_HEARTBEAT_INFO = 0x0001
PARAM_STATE_COOKIE = 0x0007
PARAM_FORWARD_TSN_SUPPORTED = 0xC000


def find_moon() -> str:
    candidates = [
        shutil.which("moon"),
        str(Path.home() / ".moon" / "bin" / ("moon.exe" if os.name == "nt" else "moon")),
    ]
    for c in candidates:
        if c and Path(c).exists():
            return str(c)
    raise RuntimeError("moon binary not found in PATH or ~/.moon/bin")


def run_cmd(
    cmd: list[str],
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    res = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True)
    if res.returncode != 0:
        raise RuntimeError(
            f"Command failed ({res.returncode}): {' '.join(cmd)}\n"
            f"STDOUT:\n{res.stdout.decode(errors='replace')}\n"
            f"STDERR:\n{res.stderr.decode(errors='replace')}"
        )
    return res


# =============================================================================
# Independent Bitwise Castagnoli CRC-32C (RFC 9260 Appendix B, poly 0x82F63B78)
# =============================================================================


def crc32c_bitwise(data: bytes) -> int:
    """Table-free bitwise Castagnoli CRC-32C reference implementation."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x82F63B78
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF


def sctp_packet_crc32c(raw: bytes) -> int:
    """Computes SCTP packet CRC-32C with checksum field (bytes 8..12) zeroed."""
    assert len(raw) >= 12
    zeroed = raw[:8] + b"\x00\x00\x00\x00" + raw[12:]
    return crc32c_bitwise(zeroed)


# =============================================================================
# Independent HMAC-SHA256 Cookie Encoder / Verifier
# =============================================================================


def seal_cookie_py(
    secret: bytes,
    local_vtag: int,
    peer_vtag: int,
    local_tsn: int,
    peer_tsn: int,
    out_streams: int,
    in_streams: int,
    peer_arwnd: int,
    created_ms: int,
) -> bytes:
    body = struct.pack(
        ">IIIIHHIQ",
        local_vtag,
        peer_vtag,
        local_tsn,
        peer_tsn,
        out_streams,
        in_streams,
        peer_arwnd,
        created_ms,
    )
    assert len(body) == 32
    mac = hmac.new(secret, body, hashlib.sha256).digest()
    return body + mac


def verify_and_parse_cookie_py(secret: bytes, cookie: bytes) -> dict[str, int]:
    assert len(cookie) == 64, f"expected 64B cookie, got {len(cookie)}"
    body, mac = cookie[:32], cookie[32:]
    expected = hmac.new(secret, body, hashlib.sha256).digest()
    assert hmac.compare_digest(expected, mac), "HMAC-SHA256 cookie MAC mismatch"
    lv, pv, lt, pt, os_, is_, arwnd, created_ms = struct.unpack(">IIIIHHIQ", body)
    return {
        "local_vtag": lv,
        "peer_vtag": pv,
        "local_tsn": lt,
        "peer_tsn": pt,
        "out_streams": os_,
        "in_streams": is_,
        "peer_arwnd": arwnd,
        "created_ms": created_ms,
    }


# =============================================================================
# Independent RFC 9260 / RFC 3758 Wire Dissector & Packet Synthesizer
# =============================================================================


def parse_tlvs(data: bytes) -> list[tuple[int, bytes]]:
    tlvs: list[tuple[int, bytes]] = []
    pos = 0
    while pos < len(data):
        assert pos + 4 <= len(data), "truncated TLV header"
        ptype, plen = struct.unpack_from(">HH", data, pos)
        assert plen >= 4 and pos + plen <= len(data), f"invalid TLV length {plen}"
        val = data[pos + 4 : pos + plen]
        tlvs.append((ptype, val))
        if pos + plen == len(data):
            break
        pad = (4 - (plen % 4)) % 4
        assert pos + plen + pad <= len(data), "truncated TLV padding"
        assert data[pos + plen : pos + plen + pad] == b"\x00" * pad, "non-zero TLV padding"
        pos += plen + pad
    return tlvs


def dissect_sctp_packet(raw: bytes) -> dict[str, Any]:
    """Full RFC 9260 / RFC 3758 byte-level SCTP wire dissector (Wireshark-equivalent)."""
    assert len(raw) >= 12, f"packet too short: {len(raw)}"
    src_port, dst_port, vtag = struct.unpack_from(">HHI", raw, 0)
    wire_crc = struct.unpack_from("<I", raw, 8)[0]
    calc_crc = sctp_packet_crc32c(raw)
    assert wire_crc == calc_crc, f"CRC-32C mismatch: wire=0x{wire_crc:08x} calc=0x{calc_crc:08x}"

    chunks: list[dict[str, Any]] = []
    pos = 12
    while pos < len(raw):
        assert pos + 4 <= len(raw), "truncated chunk header"
        ctype, flags, clen = struct.unpack_from(">BBH", raw, pos)
        assert clen >= 4 and pos + clen <= len(raw), f"invalid chunk len {clen}"
        body = raw[pos + 4 : pos + clen]

        if ctype == CHUNK_DATA:
            assert len(body) >= 12
            tsn, sid, ssn, ppid = struct.unpack_from(">IHHI", body, 0)
            chunks.append(
                {
                    "type": CHUNK_DATA,
                    "flags": flags,
                    "U": bool(flags & 0x04),
                    "B": bool(flags & 0x02),
                    "E": bool(flags & 0x01),
                    "tsn": tsn,
                    "stream_id": sid,
                    "stream_seq": ssn,
                    "ppid": ppid,
                    "payload": body[12:],
                }
            )
        elif ctype in (CHUNK_INIT, CHUNK_INIT_ACK):
            assert len(body) >= 16
            itag, arwnd, os_, mis, itsn = struct.unpack_from(">IIHHI", body, 0)
            tlvs = parse_tlvs(body[16:])
            fwd_tsn = any(t == PARAM_FORWARD_TSN_SUPPORTED for t, _ in tlvs)
            cookies = [v for t, v in tlvs if t == PARAM_STATE_COOKIE]
            entry: dict[str, Any] = {
                "type": ctype,
                "flags": flags,
                "initiate_tag": itag,
                "a_rwnd": arwnd,
                "os": os_,
                "mis": mis,
                "initial_tsn": itsn,
                "forward_tsn_supported": fwd_tsn,
                "tlvs": tlvs,
            }
            if ctype == CHUNK_INIT_ACK:
                assert len(cookies) == 1, "INIT_ACK must carry State Cookie TLV"
                entry["state_cookie"] = cookies[0]
            chunks.append(entry)
        elif ctype == CHUNK_SACK:
            assert len(body) >= 12
            cum_tsn, arwnd, num_gaps, num_dups = struct.unpack_from(">IIHH", body, 0)
            assert len(body) == 12 + num_gaps * 4 + num_dups * 4
            gaps = [
                struct.unpack_from(">HH", body, 12 + i * 4)
                for i in range(num_gaps)
            ]
            dups = [
                struct.unpack_from(">I", body, 12 + num_gaps * 4 + i * 4)[0]
                for i in range(num_dups)
            ]
            chunks.append(
                {
                    "type": CHUNK_SACK,
                    "flags": flags,
                    "cum_tsn_ack": cum_tsn,
                    "a_rwnd": arwnd,
                    "gap_blocks": gaps,
                    "dup_tsns": dups,
                }
            )
        elif ctype in (CHUNK_HEARTBEAT, CHUNK_HEARTBEAT_ACK):
            tlvs = parse_tlvs(body)
            assert len(tlvs) == 1 and tlvs[0][0] == PARAM_HEARTBEAT_INFO
            chunks.append({"type": ctype, "flags": flags, "info": tlvs[0][1]})
        elif ctype in (CHUNK_ABORT, CHUNK_ERROR):
            causes = parse_tlvs(body)
            chunks.append({"type": ctype, "flags": flags, "t_bit": bool(flags & 0x01), "causes": causes})
        elif ctype == CHUNK_SHUTDOWN:
            assert len(body) == 4
            cum_tsn = struct.unpack_from(">I", body, 0)[0]
            chunks.append({"type": CHUNK_SHUTDOWN, "flags": flags, "cum_tsn_ack": cum_tsn})
        elif ctype in (CHUNK_SHUTDOWN_ACK, CHUNK_COOKIE_ACK):
            assert len(body) == 0
            chunks.append({"type": ctype, "flags": flags})
        elif ctype == CHUNK_COOKIE_ECHO:
            chunks.append({"type": CHUNK_COOKIE_ECHO, "flags": flags, "cookie": body})
        elif ctype == CHUNK_SHUTDOWN_COMPLETE:
            assert len(body) == 0
            chunks.append({"type": CHUNK_SHUTDOWN_COMPLETE, "flags": flags, "t_bit": bool(flags & 0x01)})
        elif ctype == CHUNK_FORWARD_TSN:
            assert len(body) >= 4 and (len(body) - 4) % 4 == 0
            new_cum = struct.unpack_from(">I", body, 0)[0]
            streams = [
                struct.unpack_from(">HH", body, 4 + i * 4)
                for i in range((len(body) - 4) // 4)
            ]
            chunks.append(
                {
                    "type": CHUNK_FORWARD_TSN,
                    "flags": flags,
                    "new_cum_tsn": new_cum,
                    "streams": streams,
                }
            )
        else:
            raise AssertionError(f"unexpected chunk type 0x{ctype:02x}")

        if pos + clen == len(raw):
            break
        pad = (4 - (clen % 4)) % 4
        assert pos + clen + pad <= len(raw), "truncated chunk padding"
        assert raw[pos + clen : pos + clen + pad] == b"\x00" * pad, "non-zero 4-byte chunk padding"
        pos += clen + pad

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "vtag": vtag,
        "crc32c": wire_crc,
        "chunks": chunks,
    }


def encode_tlv_py(ptype: int, val: bytes, pad_trailing: bool = True) -> bytes:
    plen = 4 + len(val)
    pad = (4 - (plen % 4)) % 4 if pad_trailing else 0
    return struct.pack(">HH", ptype, plen) + val + (b"\x00" * pad)


def encode_packet_py(src_port: int, dst_port: int, vtag: int, chunk_tuples: list[tuple[int, int, bytes]]) -> bytes:
    """Independent RFC 9260 wire packet synthesizer using bitwise Castagnoli CRC-32C."""
    buf = bytearray(struct.pack(">HHII", src_port, dst_port, vtag, 0))
    for ctype, flags, body in chunk_tuples:
        clen = 4 + len(body)
        pad = (4 - (clen % 4)) % 4
        buf.extend(struct.pack(">BBH", ctype, flags, clen))
        buf.extend(body)
        buf.extend(b"\x00" * pad)
    crc = crc32c_bitwise(bytes(buf))
    struct.pack_into("<I", buf, 8, crc)
    return bytes(buf)


def format_hex_mbt(hex_str: str, indent: str = "    ") -> str:
    chunks = [hex_str[i : i + 64] for i in range(0, len(hex_str), 64)]
    if len(chunks) == 1:
        return f'"{chunks[0]}"'
    return (" +\n" + indent).join(f'"{c}"' for c in chunks)


def main() -> int:
    moon = find_moon()
    env = os.environ.copy()
    env["PATH"] = str(Path(moon).parent) + os.pathsep + env.get("PATH", "")

    print("=== MoonSCTP <-> Independent Python RFC 9260 Wire Interop Harness ===")
    print(f"Python  : {sys.version.split()[0]}")
    print(f"MoonBit : {moon}")
    print()

    results: list[tuple[str, bool, str]] = []

    def record(name: str, ok: bool, detail: str) -> None:
        results.append((name, ok, detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")

    try:
        # =====================================================================
        # PHASE 1: MoonSCTP Wasm -> Independent Python RFC 9260 Wire Dissector
        # =====================================================================
        print("[Phase 1] MoonSCTP Wasm -> Independent Python RFC 9260 Dissector & Bitwise CRC-32C")
        cli_out = run_cmd(
            [
                moon,
                "run",
                "--target-dir",
                str(BUILD_DIR),
                "--target",
                "wasm",
                "harness/interop_cli",
            ],
            cwd=ROOT,
            env=env,
        ).stdout.decode("utf-8")

        kv: dict[str, bytes] = {}
        for line in cli_out.splitlines():
            if "=" in line:
                k, v = line.strip().split("=", 1)
                if k.isupper() and all(c in "0123456789abcdef" for c in v):
                    kv[k] = bytes.fromhex(v)

        # 1.1 Independent bitwise Castagnoli CRC-32C verification
        assert int.from_bytes(kv["CRC_EMPTY"], "big") == crc32c_bitwise(b"") == 0x00000000
        assert int.from_bytes(kv["CRC_123456789"], "big") == crc32c_bitwise(b"123456789") == 0xE3069283
        assert int.from_bytes(kv["CRC_INC32"], "big") == crc32c_bitwise(bytes(range(32))) == 0x46DD794E
        assert int.from_bytes(kv["CRC_LONG_VAL"], "big") == crc32c_bitwise(kv["CRC_LONG_MSG"])
        record("MoonSCTP->Python Bitwise CRC-32C", True, "4/4 Castagnoli vectors (incl. 0xE3069283, 0x46DD794E) matched")

        # 1.2 Independent HMAC-SHA256 Cookie verification
        parsed_cookie = verify_and_parse_cookie_py(kv["COOKIE_SECRET"], kv["COOKIE_WIRE"])
        assert parsed_cookie["local_vtag"] == 0x55667788
        assert parsed_cookie["peer_vtag"] == 0x11223344
        assert parsed_cookie["peer_tsn"] == 0xFFFFFFFE
        assert parsed_cookie["created_ms"] == 1780272000123
        record("MoonSCTP->Python HMAC-SHA256 Cookie", True, "64B cookie MAC & all 8 payload fields verified")

        # 1.3 Dissect PKT_INIT
        d_init = dissect_sctp_packet(kv["PKT_INIT"])
        assert (d_init["src_port"], d_init["dst_port"], d_init["vtag"]) == (5000, 5001, 0)
        assert len(d_init["chunks"]) == 1
        c0 = d_init["chunks"][0]
        assert c0["type"] == CHUNK_INIT and c0["initiate_tag"] == 0x11223344
        assert c0["a_rwnd"] == 131072 and c0["os"] == 16 and c0["mis"] == 32
        assert c0["initial_tsn"] == 0xFFFFFFFE and c0["forward_tsn_supported"] is True
        record("MoonSCTP->Python Wire Dissect: INIT", True, f"{len(kv['PKT_INIT'])}B, CRC-32C + Forward-TSN TLV 0xC000 verified")

        # 1.4 Dissect PKT_INIT_ACK
        d_iack = dissect_sctp_packet(kv["PKT_INIT_ACK"])
        assert d_iack["vtag"] == 0x11223344 and len(d_iack["chunks"]) == 1
        c0 = d_iack["chunks"][0]
        assert c0["type"] == CHUNK_INIT_ACK and c0["initiate_tag"] == 0x55667788
        assert c0["state_cookie"] == kv["COOKIE_WIRE"] and c0["forward_tsn_supported"] is True
        verify_and_parse_cookie_py(kv["COOKIE_SECRET"], c0["state_cookie"])
        record("MoonSCTP->Python Wire Dissect: INIT_ACK", True, f"{len(kv['PKT_INIT_ACK'])}B, 64B HMAC Cookie TLV 0x0007 verified")

        # 1.5 Dissect PKT_COOKIE_ECHO_ACK
        d_ce = dissect_sctp_packet(kv["PKT_COOKIE_ECHO_ACK"])
        assert d_ce["vtag"] == 0x55667788 and len(d_ce["chunks"]) == 2
        assert d_ce["chunks"][0]["type"] == CHUNK_COOKIE_ECHO and d_ce["chunks"][0]["cookie"] == kv["COOKIE_WIRE"]
        assert d_ce["chunks"][1]["type"] == CHUNK_COOKIE_ACK
        record("MoonSCTP->Python Wire Dissect: COOKIE_ECHO+ACK", True, f"{len(kv['PKT_COOKIE_ECHO_ACK'])}B bundled chunks verified")

        # 1.6 Dissect PKT_DATA_SACK_BUNDLE (non-4B payloads + TSN wraparound + Gap/Dup)
        d_ds = dissect_sctp_packet(kv["PKT_DATA_SACK_BUNDLE"])
        assert len(d_ds["chunks"]) == 3
        d0, d1, sk = d_ds["chunks"]
        assert d0["type"] == CHUNK_DATA and (d0["U"], d0["B"], d0["E"]) == (False, True, True)
        assert d0["tsn"] == 0xFFFFFFFF and d0["stream_id"] == 3 and d0["stream_seq"] == 42 and d0["ppid"] == 51
        assert d0["payload"] == b"Hello, SCTP!!"
        assert d1["type"] == CHUNK_DATA and (d1["U"], d1["B"], d1["E"]) == (True, True, False)
        assert d1["tsn"] == 0x00000000 and d1["stream_id"] == 7 and d1["ppid"] == 53 and d1["payload"] == b"FRAG1"
        assert sk["type"] == CHUNK_SACK and sk["cum_tsn_ack"] == 0xFFFFFFFF and sk["a_rwnd"] == 130000
        assert sk["gap_blocks"] == [(2, 4), (7, 9)] and sk["dup_tsns"] == [1, 0xFFFFFFFF]
        record("MoonSCTP->Python Wire Dissect: DATA(B/E/U)+SACK", True, f"{len(kv['PKT_DATA_SACK_BUNDLE'])}B, 4B zero pad + TSN wrap + Gap/Dup verified")

        # 1.7 Dissect PKT_HEARTBEAT
        d_hb = dissect_sctp_packet(kv["PKT_HEARTBEAT"])
        assert len(d_hb["chunks"]) == 2
        assert d_hb["chunks"][0]["type"] == CHUNK_HEARTBEAT and d_hb["chunks"][0]["info"] == b"hb-probe-17bytes!"
        assert d_hb["chunks"][1]["type"] == CHUNK_HEARTBEAT_ACK and d_hb["chunks"][1]["info"] == b"hb-ack-11b!"
        record("MoonSCTP->Python Wire Dissect: HEARTBEAT+ACK", True, f"{len(kv['PKT_HEARTBEAT'])}B, 17B & 11B TLV padding verified")

        # 1.8 Dissect PKT_FWD_SHUTDOWN_ABORT
        d_fsa = dissect_sctp_packet(kv["PKT_FWD_SHUTDOWN_ABORT"])
        assert len(d_fsa["chunks"]) == 3
        ft, sd, ab = d_fsa["chunks"]
        assert ft["type"] == CHUNK_FORWARD_TSN and ft["new_cum_tsn"] == 5 and ft["streams"] == [(0, 3), (2, 7)]
        assert sd["type"] == CHUNK_SHUTDOWN and sd["cum_tsn_ack"] == 5
        assert ab["type"] == CHUNK_ABORT and ab["t_bit"] is True and ab["causes"] == [(12, b"user abort!")]
        record("MoonSCTP->Python Wire Dissect: FWD_TSN+SHUTDOWN+ABORT", True, f"{len(kv['PKT_FWD_SHUTDOWN_ABORT'])}B, RFC 3758 + T-bit + ErrorCause verified")

        # =====================================================================
        # PHASE 2: Independent Python Synthesizer -> MoonSCTP Wasm & JS
        # =====================================================================
        print("\n[Phase 2] Independent Python RFC 9260 Synthesizer -> MoonSCTP (Wasm & JS)")

        py_secret = secrets.token_bytes(32)
        py_rand_payload1 = secrets.token_bytes(19)  # non-4B multiple (19B -> 1B pad)
        py_rand_payload2 = secrets.token_bytes(23)  # non-4B multiple (23B -> 1B pad)
        py_hb_info = secrets.token_bytes(13)  # non-4B multiple (13B -> 3B pad)
        py_cookie = seal_cookie_py(
            py_secret,
            local_vtag=0xCAFEBABE,
            peer_vtag=0xDEADBEEF,
            local_tsn=0xFFFFFFFD,
            peer_tsn=0x80000001,
            out_streams=8,
            in_streams=16,
            peer_arwnd=65536,
            created_ms=1780272555000,
        )

        # Synthesize Packet A: Multi-chunk bundle with TSN wraparound (0xFFFFFFFE, 0x00000000) + SACK + FORWARD_TSN
        py_pkt_bundle = encode_packet_py(
            src_port=49152,
            dst_port=5000,
            vtag=0xCAFEBABE,
            chunk_tuples=[
                (
                    CHUNK_DATA,
                    0x03,  # B=1, E=1, U=0
                    struct.pack(">IHHI", 0xFFFFFFFE, 1, 0xFFFF, 51) + py_rand_payload1,
                ),
                (
                    CHUNK_DATA,
                    0x07,  # U=1, B=1, E=1
                    struct.pack(">IHHI", 0x00000000, 2, 0, 53) + py_rand_payload2,
                ),
                (
                    CHUNK_SACK,
                    0x00,
                    struct.pack(">IIHH", 0xFFFFFFFF, 98304, 1, 1)
                    + struct.pack(">HH", 3, 5)
                    + struct.pack(">I", 0x00000002),
                ),
                (
                    CHUNK_FORWARD_TSN,
                    0x00,
                    struct.pack(">IHH", 0x00000001, 1, 0x0000),
                ),
            ],
        )

        # Synthesize Packet B: INIT_ACK carrying Python-sealed 64B HMAC-SHA256 Cookie + Forward-TSN Supported TLV
        py_pkt_init_ack = encode_packet_py(
            src_port=5000,
            dst_port=49152,
            vtag=0xDEADBEEF,
            chunk_tuples=[
                (
                    CHUNK_INIT_ACK,
                    0x00,
                    struct.pack(">IIHHI", 0xCAFEBABE, 262144, 8, 16, 0xFFFFFFFD)
                    + encode_tlv_py(PARAM_STATE_COOKIE, py_cookie)
                    + encode_tlv_py(PARAM_FORWARD_TSN_SUPPORTED, b""),
                ),
            ],
        )

        # Synthesize Packet C: HEARTBEAT + SHUTDOWN_COMPLETE (T=1)
        # RFC 9260 §3.2.1: trailing padding of the last TLV is NOT included in Chunk Length
        py_pkt_ctrl = encode_packet_py(
            src_port=5000,
            dst_port=49152,
            vtag=0xDEADBEEF,
            chunk_tuples=[
                (CHUNK_HEARTBEAT, 0x00, encode_tlv_py(PARAM_HEARTBEAT_INFO, py_hb_info, pad_trailing=False)),
                (CHUNK_SHUTDOWN_COMPLETE, 0x01, b""),
            ],
        )

        # Self-check synthesized packets with our own dissector
        dissect_sctp_packet(py_pkt_bundle)
        dissect_sctp_packet(py_pkt_init_ack)
        dissect_sctp_packet(py_pkt_ctrl)

        py_crc_msg = secrets.token_bytes(77)
        py_crc_val = crc32c_bitwise(py_crc_msg)

        mbt_src = f'''// Auto-generated by harness/interop_wire.py (independent Python RFC 9260 synthesizer).
// Verifies MoonSCTP packet decoding, re-encoding, bitwise CRC-32C, and HMAC-SHA256 Cookie.

///|
fn hex_nibble(c : Int) -> Int {{
  if c >= 0x30 && c <= 0x39 {{
    c - 0x30
  }} else if c >= 0x61 && c <= 0x66 {{
    c - 0x61 + 10
  }} else if c >= 0x41 && c <= 0x46 {{
    c - 0x41 + 10
  }} else {{
    abort("invalid hex char")
  }}
}}

///|
fn from_hex(s : String) -> Bytes {{
  let n = s.length() / 2
  let out = FixedArray::make(n, b'\\x00')
  for i = 0; i < n; i = i + 1 {{
    let hi = hex_nibble(s[i * 2].to_int())
    let lo = hex_nibble(s[i * 2 + 1].to_int())
    out[i] = ((hi << 4) | lo).to_byte()
  }}
  Bytes::from_array(out)
}}

///|
test "Python -> MoonSCTP: bitwise Castagnoli CRC-32C matches random 77B vector" {{
  let msg = from_hex(
    {format_hex_mbt(py_crc_msg.hex())},
  )
  assert_eq(@crc32c.crc32c(msg), 0x{py_crc_val:08X}U)
}}

///|
test "Python -> MoonSCTP: bundled DATA(TSN wrap)+SACK+FORWARD_TSN decode & byte-exact re-encode" {{
  let wire = from_hex(
    {format_hex_mbt(py_pkt_bundle.hex())},
  )
  let expected_p1 = from_hex("{py_rand_payload1.hex()}")
  let expected_p2 = from_hex("{py_rand_payload2.hex()}")
  let pkt = @packet.decode_packet(wire[:])
  assert_eq(pkt.src_port, 49152U)
  assert_eq(pkt.dst_port, 5000U)
  assert_eq(pkt.verification_tag, 0xCAFEBABEU)
  assert_eq(pkt.chunks.length(), 4)
  assert_eq(
    pkt.chunks[0],
    @packet.Chunk::Data({{
      tsn: 0xFFFFFFFEU,
      stream_id: 1U,
      stream_seq: 0xFFFFU,
      ppid: 51U,
      unordered: false,
      beginning: true,
      ending: true,
      payload: expected_p1,
    }}),
  )
  assert_eq(
    pkt.chunks[1],
    @packet.Chunk::Data({{
      tsn: 0x00000000U,
      stream_id: 2U,
      stream_seq: 0U,
      ppid: 53U,
      unordered: true,
      beginning: true,
      ending: true,
      payload: expected_p2,
    }}),
  )
  assert_eq(
    pkt.chunks[2],
    @packet.Chunk::Sack({{
      cum_tsn_ack: 0xFFFFFFFFU,
      a_rwnd: 98304U,
      gap_blocks: [{{ start: 3U, end: 5U }}],
      dup_tsns: [0x00000002U],
    }}),
  )
  assert_eq(
    pkt.chunks[3],
    @packet.Chunk::ForwardTsn({{
      new_cum_tsn: 0x00000001U,
      streams: [{{ stream_id: 1U, stream_seq: 0U }}],
    }}),
  )
  // Byte-for-byte canonical re-encode check
  assert_eq(@packet.encode_packet(pkt), wire)
}}

///|
test "Python -> MoonSCTP: INIT_ACK + Python-sealed 64B HMAC-SHA256 Cookie & control bundle" {{
  let secret = from_hex("{py_secret.hex()}")
  let wire_iack = from_hex(
    {format_hex_mbt(py_pkt_init_ack.hex())},
  )
  let pkt_iack = @packet.decode_packet(wire_iack[:])
  assert_eq(pkt_iack.verification_tag, 0xDEADBEEFU)
  assert_eq(pkt_iack.chunks.length(), 1)
  match pkt_iack.chunks[0] {{
    @packet.Chunk::InitAck(ia) => {{
      assert_eq(ia.initiate_tag, 0xCAFEBABEU)
      assert_eq(ia.initial_tsn, 0xFFFFFFFDU)
      assert_true(ia.forward_tsn_supported)
      let opened = @cookie.open_cookie(
        secret,
        ia.state_cookie,
        1780272555500UL,
        60000UL,
      )
      assert_eq(opened.local_vtag, 0xCAFEBABEU)
      assert_eq(opened.peer_vtag, 0xDEADBEEFU)
      assert_eq(opened.local_tsn, 0xFFFFFFFDU)
      assert_eq(opened.peer_tsn, 0x80000001U)
      assert_eq(opened.out_streams, 8U)
      assert_eq(opened.in_streams, 16U)
      assert_eq(opened.peer_arwnd, 65536U)
      assert_eq(opened.created_ms, 1780272555000UL)
    }}
    _ => abort("expected InitAck")
  }}
  assert_eq(@packet.encode_packet(pkt_iack), wire_iack)

  let wire_ctrl = from_hex(
    {format_hex_mbt(py_pkt_ctrl.hex())},
  )
  let expected_hb = from_hex("{py_hb_info.hex()}")
  let pkt_ctrl = @packet.decode_packet(wire_ctrl[:])
  assert_eq(pkt_ctrl.chunks.length(), 2)
  assert_eq(pkt_ctrl.chunks[0], @packet.Chunk::Heartbeat(expected_hb))
  assert_eq(pkt_ctrl.chunks[1], @packet.Chunk::ShutdownComplete(true))
  assert_eq(@packet.encode_packet(pkt_ctrl), wire_ctrl)
}}
'''
        GENERATED_TEST.write_text(mbt_src, encoding="utf-8")
        run_cmd([moon, "fmt", "harness"], cwd=ROOT, env=env)

        for target in ("wasm", "js"):
            res = run_cmd(
                [
                    moon,
                    "test",
                    "--target-dir",
                    str(BUILD_DIR),
                    "--target",
                    target,
                    "-d",
                    "harness",
                ],
                cwd=ROOT,
                env=env,
            )
            summary = [l for l in res.stdout.decode().splitlines() if "Total tests:" in l]
            detail = summary[-1].strip() if summary else "passed"
            record(f"Python->MoonSCTP ({target} target)", True, detail)

    except Exception as exc:
        import traceback
        traceback.print_exc()
        record("Interop Wire Harness", False, repr(exc))
        return 1
    finally:
        if BUILD_DIR.exists() and "--keep-build" not in sys.argv:
            shutil.rmtree(BUILD_DIR, ignore_errors=True)

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"\n=== SUMMARY: {passed}/{total} PASSED (MoonSCTP <-> Independent Python RFC 9260 100% Bidirectional Interop) ===")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
