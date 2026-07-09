"""
Honda Keihin K-Line ECU interface.

Reworked for reverse-engineering an undocumented ECU (Honda CBR150R K45A,
Indonesian market). Since there is no factory spec to confirm the wake-up
protocol, this module supports SEVERAL candidate init strategies and gives
raw on-the-wire visibility (--debug logging) so you can empirically figure
out which one the ECU actually responds to, rather than betting everything
on a single hardcoded sequence.

Supported init modes (see InitMode):
    fast_keihin     - "Fast Init" break low 70ms / high 120ms (common in
                       aftermarket Keihin K-line tools / clone cables)
    fast_iso14230   - Standard ISO14230 Fast Init: low 25ms / high 25ms
    slow_5baud      - ISO9141-2 style 5-baud slow init: bit-bang address
                       byte 0x10 at 5 baud, then look for sync (0x55) +
                       2 key bytes
    passive_sniff   - No init at all. Just open the port and log whatever
                       the ECU/bus does on its own.
    two_phase       - Confirmed K45A sequence:
                       P1: break 25/25ms + 0x33 -> 0x31 ack
                       P2a: burst FE 04 72 8C -> ECU wake ack
                       P2b: burst 72 05 00 F0 99 -> ECU ready ack
"""

import logging
import time
from enum import Enum

import serial

logger = logging.getLogger("honda_reader.ecu")

HEADER_REQUEST  = 0x72
HEADER_RESPONSE = 0x02
MODE_QUERY      = 0x71
MODE_HANDSHAKE  = 0x0F

HANDSHAKE_REQUEST = [0x72, 0x05, 0x0F, 0xF0]
SLOW_INIT_ADDRESS = 0x10


class InitMode(str, Enum):
    FAST_KEIHIN   = "fast_keihin"
    FAST_ISO14230 = "fast_iso14230"
    SLOW_5BAUD    = "slow_5baud"
    PASSIVE_SNIFF = "passive_sniff"
    TWO_PHASE     = "two_phase"


FAST_INIT_TIMINGS = {
    InitMode.FAST_KEIHIN:   {"low_ms": 70,  "high_ms": 120},
    InitMode.FAST_ISO14230: {"low_ms": 25,  "high_ms": 25},
}


# ---------------------------------------------------------------------------
# Checksum / packet helpers
# ---------------------------------------------------------------------------

def calculate_checksum(packet: list) -> int:
    """Standard Keihin 8-bit subtraction checksum."""
    return (0x100 - (sum(packet) & 0xFF)) & 0xFF


def verify_checksum(packet: list) -> bool:
    if len(packet) < 2:
        return False
    data_sum  = sum(packet[:-1]) & 0xFF
    expected  = (0x100 - data_sum) & 0xFF
    return packet[-1] == expected


def build_packet(mode: int, table_id: int, data_bytes: list | None = None) -> list:
    data    = data_bytes or []
    payload = [HEADER_REQUEST, 0, mode, table_id] + data
    payload[1] = len(payload) + 1
    return payload + [calculate_checksum(payload)]


# ---------------------------------------------------------------------------
# Raw-byte logging helpers
# ---------------------------------------------------------------------------

def _hex(data) -> str:
    return " ".join(f"{b:02X}" for b in data) if data else "(none)"

def _log_tx(label: str, data) -> None:
    logger.debug("TX [%s]: %s", label, _hex(data))

def _log_rx(label: str, data) -> None:
    logger.debug("RX [%s]: %s", label, _hex(data))


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------

def open_connection(port: str, baudrate: int, timeout: float) -> serial.Serial:
    return serial.Serial(
        port=port,
        baudrate=baudrate,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=timeout,
    )

def _reopen_baud(ser: serial.Serial, baudrate: int) -> None:
    ser.baudrate = baudrate
    ser.reset_input_buffer()
    ser.reset_output_buffer()


# ---------------------------------------------------------------------------
# Core send+capture primitive
# Used everywhere we need to see raw wire bytes without echo filtering.
# Sends the packet as a single burst, then reads everything on the wire
# for window_s seconds and returns ALL bytes (our echo + ECU response).
# Callers strip the echo by slicing off len(packet) bytes from the front.
# ---------------------------------------------------------------------------

def _send_and_capture(ser: serial.Serial, packet: list, label: str,
                      window_s: float = 2.0) -> list:
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    _log_tx(label, packet)
    ser.write(bytearray(packet))

    ser.timeout = 0.05
    raw      = bytearray()
    deadline = time.time() + window_s
    while time.time() < deadline:
        chunk = ser.read(64)
        if chunk:
            raw.extend(chunk)
    ser.timeout = 1.0

    _log_rx(f"{label}_raw", list(raw))
    return list(raw)


# ---------------------------------------------------------------------------
# Init Mode 1 & 2: Fast Init (break-pulse based)
# ---------------------------------------------------------------------------

def _fast_init_pulse(ser: serial.Serial, low_ms: int, high_ms: int) -> None:
    ser.break_condition = True
    time.sleep(low_ms / 1000.0)
    ser.break_condition = False
    time.sleep(high_ms / 1000.0)
    ser.reset_input_buffer()
    ser.reset_output_buffer()


def _read_with_echo_cancel(ser: serial.Serial, sent_packet: list,
                            n_response_bytes: int):
    first_byte = ser.read(1)
    if not first_byte:
        return None
    first_val = first_byte[0]

    if first_val == sent_packet[0]:
        remaining_echo = len(sent_packet) - 1
        echoed = ser.read(remaining_echo) if remaining_echo > 0 else b""
        _log_rx("echo", bytes([first_val]) + echoed)
        first_byte = ser.read(1)
        if not first_byte:
            return None
        first_val = first_byte[0]

    rest     = ser.read(max(n_response_bytes - 1, 0))
    response = [first_val] + list(rest)
    _log_rx("response", response)
    return response


def fast_init_handshake(ser: serial.Serial,
                         mode: InitMode = InitMode.FAST_KEIHIN) -> dict:
    timing = FAST_INIT_TIMINGS[mode]
    logger.debug("Fast init (%s): low=%dms high=%dms",
                 mode.value, timing["low_ms"], timing["high_ms"])
    _fast_init_pulse(ser, timing["low_ms"], timing["high_ms"])

    cs     = calculate_checksum(HANDSHAKE_REQUEST)
    packet = HANDSHAKE_REQUEST + [cs]
    _log_tx(mode.value, packet)
    ser.write(bytearray(packet))

    response = _read_with_echo_cancel(ser, packet, n_response_bytes=5)

    result = {
        "mode":     mode.value,
        "sent":     packet,
        "received": response,
        "success":  False,
        "reason":   None,
    }

    if response is None:
        result["reason"] = "timeout_no_response"
        return result
    if response[0] != HEADER_RESPONSE:
        result["reason"] = f"unexpected_header_0x{response[0]:02X}"
        return result
    if len(response) < 5:
        result["reason"] = "short_response"
        return result
    if not verify_checksum(response):
        result["reason"] = "checksum_mismatch"
        return result

    result["success"] = response[2] == 0x0F and response[3] == 0xF0
    if not result["success"]:
        result["reason"] = "unexpected_payload"
    return result


# ---------------------------------------------------------------------------
# Init Mode 3: ISO9141-2 5-baud slow init
# ---------------------------------------------------------------------------

def _send_bit_banged_byte(ser: serial.Serial, byte_val: int,
                           bit_ms: float) -> None:
    bits  = [0]
    bits += [(byte_val >> i) & 1 for i in range(8)]
    bits += [1]
    for bit in bits:
        ser.break_condition = (bit == 0)
        time.sleep(bit_ms / 1000.0)
    ser.break_condition = False


def slow_init_handshake(ser: serial.Serial,
                         address: int   = SLOW_INIT_ADDRESS,
                         target_baud: int = 10400,
                         key_wait_s: float = 2.0) -> dict:
    logger.debug("Slow init: address=0x%02X bit_time=200ms", address)
    _send_bit_banged_byte(ser, address, bit_ms=200.0)
    _reopen_baud(ser, target_baud)

    result = {
        "mode":          InitMode.SLOW_5BAUD.value,
        "address_sent":  address,
        "sync_byte":     None,
        "key_bytes":     None,
        "echo_response": None,
        "success":       False,
        "reason":        None,
    }

    sync = ser.read(1)
    _log_rx("sync_byte", sync)
    if not sync:
        result["reason"] = "no_sync_byte"
        return result
    result["sync_byte"] = sync[0]

    key_bytes = ser.read(2)
    _log_rx("key_bytes", key_bytes)
    if len(key_bytes) < 2:
        result["reason"] = "incomplete_key_bytes"
        return result
    result["key_bytes"] = list(key_bytes)

    complement = (~key_bytes[1]) & 0xFF
    _log_tx("complement_of_kb2", [complement])
    ser.write(bytes([complement]))

    echo = ser.read(1)
    _log_rx("echo_of_complement_addr", echo)
    result["echo_response"] = echo[0] if echo else None

    if echo and echo[0] == ((~address) & 0xFF):
        result["success"] = True
    else:
        result["reason"] = "no_or_unexpected_address_complement_echo"
    return result


# ---------------------------------------------------------------------------
# Init Mode 4: Passive sniff
# ---------------------------------------------------------------------------

def passive_sniff(ser: serial.Serial, duration_s: float = 5.0) -> list:
    ser.reset_input_buffer()
    captured = bytearray()
    end = time.time() + duration_s
    while time.time() < end:
        chunk = ser.read(64)
        if chunk:
            captured.extend(chunk)
            _log_rx("sniff", chunk)
    return list(captured)


# ---------------------------------------------------------------------------
# Init Mode 5: Two-phase (confirmed K45A sequence)
#
# Phase 1  : break 25/25ms  ->  send 0x33  ->  expect 0x31
# Phase 2a : burst FE 04 72 8C  ->  ECU wake ack (expect 0E 04 72 7C)
# Phase 2b : burst 72 05 00 F0 99  ->  ECU ready ack (expect 02 04 00 FA)
#
# All ECU response bytes are captured raw (burst send + window read) so
# the per-byte collision / interleaving problem from the slow sender is gone.
# ---------------------------------------------------------------------------

def two_phase_handshake(ser: serial.Serial) -> dict:
    result = {
        "mode":        InitMode.TWO_PHASE.value,
        "phase1_sent": None,
        "phase1_recv": None,
        "phase2_sent": None,
        "phase2_recv": None,
        "success":     False,
        "reason":      None,
    }

    # ------------------------------------------------------------------
    # Phase 1 — break pulse + address byte
    # ------------------------------------------------------------------
    logger.debug("Two-phase P1: break low=25ms high=25ms, address=0x33")
    _fast_init_pulse(ser, low_ms=25, high_ms=25)

    addr_packet = [0x33]
    _log_tx("two_phase_p1", addr_packet)
    ser.write(bytearray(addr_packet))

    # consume our own TX echo of 0x33
    echo = ser.read(1)
    if echo and echo[0] == 0x33:
        _log_rx("two_phase_p1_echo", echo)
        ack = ser.read(1)
    else:
        ack = echo  # no echo present, already the ECU response

    result["phase1_sent"] = addr_packet
    result["phase1_recv"] = list(ack) if ack else []
    _log_rx("two_phase_p1_ack", ack)

    if not ack or ack[0] != 0x31:
        result["reason"] = f"phase1_no_ack (got 0x{ack[0]:02X if ack else 'nothing'})"
        return result

    # drain any additional bytes the ECU sends after 0x31
    ser.timeout = 0.2
    phase1_extra = []
    while True:
        b = ser.read(1)
        if not b:
            break
        phase1_extra.append(b[0])
    ser.timeout = 1.0

    if phase1_extra:
        _log_rx("two_phase_p1_extra", phase1_extra)
        logger.debug("ECU phase1 full response: 31 %s",
                     " ".join(f"{b:02X}" for b in phase1_extra))
    else:
        logger.debug("ECU phase1 response was single byte 0x31 only")

    result["phase1_recv"] = [0x31] + phase1_extra
    logger.debug("Phase 1 complete — bus quiet, proceeding to phase 2")
    time.sleep(0.05)

    # ------------------------------------------------------------------
    # Phase 2 — init packet (burst send, raw capture)
    # K45A goes directly to init after phase 1 -- no separate wake packet
    # needed unlike K25 which uses FE 04 72 8C first.
    # 72 05 0F F0 8A is the confirmed K45A init packet from brute-force.
    # ------------------------------------------------------------------
    init_packet = [0x72, 0x05, 0x0F, 0xF0, calculate_checksum([0x72, 0x05, 0x0F, 0xF0])]
    p2_raw      = _send_and_capture(ser, init_packet, "p2_init", window_s=2.0)

    # strip our TX echo (first len(init_packet) bytes)
    p2_ecu = p2_raw[len(init_packet):]
    _log_rx("p2_ecu_response", p2_ecu)
    logger.debug("P2 ECU response: %s",
                 " ".join(f"{b:02X}" for b in p2_ecu) if p2_ecu else "(none)")

    result["phase2_sent"] = init_packet
    result["phase2_recv"] = p2_ecu
    result["success"]     = True
    result["reason"]      = "p2_complete"
    return result

# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------

def perform_handshake(ser: serial.Serial,
                       mode: InitMode = InitMode.FAST_KEIHIN,
                       **kwargs) -> dict:
    if mode in (InitMode.FAST_KEIHIN, InitMode.FAST_ISO14230):
        return fast_init_handshake(ser, mode=mode)
    if mode == InitMode.SLOW_5BAUD:
        return slow_init_handshake(ser, **kwargs)
    if mode == InitMode.TWO_PHASE:
        return two_phase_handshake(ser)
    if mode == InitMode.PASSIVE_SNIFF:
        captured = passive_sniff(ser, **kwargs)
        return {
            "mode":     mode.value,
            "captured": captured,
            "success":  len(captured) > 0,
            "reason":   None if captured else "no_bytes_observed",
        }
    raise ValueError(f"Unknown init mode: {mode}")


def sweep_init_modes(port: str, baudrate: int, timeout: float,
                      delay_between_s: float = 1.0) -> dict:
    results = {}
    for mode in (InitMode.FAST_KEIHIN, InitMode.FAST_ISO14230, InitMode.SLOW_5BAUD):
        ser = open_connection(port, baudrate, timeout)
        try:
            results[mode.value] = perform_handshake(ser, mode=mode)
        except Exception as exc:
            results[mode.value] = {
                "mode": mode.value, "success": False,
                "reason": f"exception: {exc}",
            }
        finally:
            ser.close()
        time.sleep(delay_between_s)
    return results


# ---------------------------------------------------------------------------
# Table query
#
# Sent as a single burst. ECU response starts immediately after it receives
# the first byte, so by the time our burst finishes, the ECU response is
# already on the wire. We capture everything in a raw window, then strip
# our own TX echo (first len(packet) bytes) to get the clean ECU frame.
# ---------------------------------------------------------------------------

def query_table(ser: serial.Serial, table_id: int) -> list | None:
    """
    Combined strategy:
      Plan A - extended response window (8s instead of 2s)
      Plan E - tiny keep-alive ping before the real query
      Plan B - try alternate query formats if standard one gives only ACK
    """
    # Plan E: keep-alive ping -- single 0x00 byte, ignore response,
    # just to keep the ECU session alive before the real query
    ser.write(bytes([0x00]))
    time.sleep(0.02)
    ser.reset_input_buffer()

    candidates = [
        ("standard_71", build_packet(MODE_QUERY, table_id)),
        ("single_byte_table", [table_id]),
        ("single_byte_71", [MODE_QUERY]),
        ("no_checksum", [HEADER_REQUEST, 0x04, MODE_QUERY, table_id]),
    ]

    for label, packet in candidates:
        ser.reset_input_buffer()
        ser.reset_output_buffer()

        _log_tx(f"query_table 0x{table_id:02X} [{label}]", packet)
        ser.write(bytearray(packet))

        # Plan A: extended window, 8 seconds
        ser.timeout = 0.05
        everything = bytearray()
        deadline = time.time() + 8.0
        while time.time() < deadline:
            chunk = ser.read(64)
            if chunk:
                everything.extend(chunk)
                # if we've gone quiet for a bit after getting something, stop early
                if len(everything) > len(packet):
                    quiet_deadline = time.time() + 0.3
                    while time.time() < quiet_deadline:
                        more = ser.read(64)
                        if more:
                            everything.extend(more)
                            quiet_deadline = time.time() + 0.3
                    break
        ser.timeout = 1.0

        _log_rx(f"query_everything 0x{table_id:02X} [{label}]", list(everything))

        if not everything:
            continue

        # Extract ECU bytes: anything beyond our TX length, plus any byte
        # that differs from what we sent within TX length
        ecu_bytes = bytearray()
        for i in range(len(everything)):
            if i >= len(packet):
                ecu_bytes.append(everything[i])
            elif everything[i] != packet[i]:
                ecu_bytes.append(everything[i])

        _log_rx(f"query_ecu_extracted 0x{table_id:02X} [{label}]", list(ecu_bytes))

        # If we got MORE than just a 1-byte ACK-flip, this is real data
        if len(ecu_bytes) > 1:
            logger.debug("*** REAL DATA [%s]: %s", label,
                        " ".join(f"{b:02X}" for b in ecu_bytes))
            if ecu_bytes and ecu_bytes[0] != 0xFF:
                return list(ecu_bytes)

        time.sleep(0.1)

    return None


# ---------------------------------------------------------------------------
# Table probe sweep
# ---------------------------------------------------------------------------

def probe_tables(ser: serial.Serial,
                  start: int = 0x00,
                  end:   int = 0xFF) -> dict:
    results = {}
    for table_id in range(start, end + 1):
        try:
            resp = query_table(ser, table_id)
            if resp is None:
                results[table_id] = {"status": "INACTIVE"}
            else:
                results[table_id] = {
                    "status":    "ACTIVE",
                    "length":    len(resp),
                    "raw_bytes": resp,
                }
        except Exception:
            results[table_id] = {"status": "ERROR"}
    return results
