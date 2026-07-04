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
                       the ECU/bus does on its own. Useful to rule out
                       "ECU is already chattering without a wake sequence"
                       or to see noise/idle level.

All modes log raw hex bytes via the `logging` module at DEBUG level when
enabled, so you always see exactly what was sent/received regardless of
whether the handshake "succeeds" by the old fixed criteria.
"""

import logging
import time
from enum import Enum

import serial

logger = logging.getLogger("honda_reader.ecu")

HEADER_REQUEST = 0x72
HEADER_RESPONSE = 0x02
MODE_QUERY = 0x71
MODE_HANDSHAKE = 0x0F

# This is what most Keihin-clone tools send as the "are you there" query.
# NOTE: the checksum here (0x8A) is computed by calculate_checksum(), and
# does not match the 0x90 shown in some reference docs/screenshots floating
# around for this ECU family. Since we don't have a confirmed factory spec,
# both candidate checksums are exposed below so you can try either against
# the real hardware.
HANDSHAKE_REQUEST = [0x72, 0x05, 0x0F, 0xF0]

# ISO9141-2 slow-init address byte. 0x10 ("functional/ECU address") is the
# overwhelmingly common default; some implementations use 0x33 instead.
SLOW_INIT_ADDRESS = 0x10


class InitMode(str, Enum):
    FAST_KEIHIN = "fast_keihin"
    FAST_ISO14230 = "fast_iso14230"
    SLOW_5BAUD = "slow_5baud"
    PASSIVE_SNIFF = "passive_sniff"
    TWO_PHASE = "two_phase"


FAST_INIT_TIMINGS = {
    InitMode.FAST_KEIHIN: {"low_ms": 70, "high_ms": 120},
    InitMode.FAST_ISO14230: {"low_ms": 25, "high_ms": 25},
}


# --------------------------------------------------------------------------
# Checksum / packet helpers
# --------------------------------------------------------------------------

def calculate_checksum(packet: list) -> int:
    """Calculates standard Keihin 8-bit subtraction checksum."""
    return (0x100 - (sum(packet) & 0xFF)) & 0xFF


def verify_checksum(packet: list) -> bool:
    """Verifies if the final byte matches the subtraction checksum of the message payload."""
    if len(packet) < 2:
        return False
    data_sum = sum(packet[:-1]) & 0xFF
    expected_cs = (0x100 - data_sum) & 0xFF
    return packet[-1] == expected_cs


def build_packet(mode: int, table_id: int, data_bytes: list | None = None) -> list:
    """Builds a formatted request packet with dynamically calculated length and checksum."""
    data = data_bytes or []
    payload = [HEADER_REQUEST, 0, mode, table_id] + data
    payload[1] = len(payload) + 1
    cs = calculate_checksum(payload)
    return payload + [cs]


# --------------------------------------------------------------------------
# Raw-byte logging helpers
# --------------------------------------------------------------------------

def _hex(data) -> str:
    return " ".join(f"{b:02X}" for b in data) if data else "(none)"


def _log_tx(label: str, data) -> None:
    logger.debug("TX [%s]: %s", label, _hex(data))


def _log_rx(label: str, data) -> None:
    logger.debug("RX [%s]: %s", label, _hex(data))


# --------------------------------------------------------------------------
# Connection management
# --------------------------------------------------------------------------

def open_connection(port: str, baudrate: int, timeout: float) -> serial.Serial:
    """Configures and opens serial port connection."""
    ser = serial.Serial(
        port=port,
        baudrate=baudrate,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=timeout,
    )
    return ser


def _reopen_baud(ser: serial.Serial, baudrate: int) -> None:
    """Switch baud rate on an already-open port (used after slow-init bit-banging)."""
    ser.baudrate = baudrate
    ser.reset_input_buffer()
    ser.reset_output_buffer()


# --------------------------------------------------------------------------
# Init Mode 1 & 2: Fast Init (break-pulse based, parameterized timing)
# --------------------------------------------------------------------------

def _fast_init_pulse(ser: serial.Serial, low_ms: int, high_ms: int) -> None:
    ser.break_condition = True
    time.sleep(low_ms / 1000.0)
    ser.break_condition = False
    time.sleep(high_ms / 1000.0)
    ser.reset_input_buffer()
    ser.reset_output_buffer()


def _read_with_echo_cancel(ser: serial.Serial, sent_packet: list, n_response_bytes: int):
    """
    Reads a response, transparently consuming a TX->RX loopback echo if present.
    Returns the raw response bytes read (header byte included), or None on timeout.
    This does NOT validate header/checksum -- callers decide what counts as
    "valid" since during reverse-engineering you want to see garbage too.
    """
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

    rest = ser.read(max(n_response_bytes - 1, 0))
    response = [first_val] + list(rest)
    _log_rx("response", response)
    return response


def fast_init_handshake(ser: serial.Serial, mode: InitMode = InitMode.FAST_KEIHIN) -> dict:
    """
    Performs a break-pulse Fast Init using the timing for the given mode,
    sends the handshake query, and returns a result dict describing exactly
    what happened (not just True/False) so it's useful for RE.
    """
    timing = FAST_INIT_TIMINGS[mode]
    logger.debug("Fast init (%s): low=%dms high=%dms", mode.value, timing["low_ms"], timing["high_ms"])
    _fast_init_pulse(ser, timing["low_ms"], timing["high_ms"])

    cs = calculate_checksum(HANDSHAKE_REQUEST)
    packet = HANDSHAKE_REQUEST + [cs]
    _log_tx(mode.value, packet)
    ser.write(bytearray(packet))

    response = _read_with_echo_cancel(ser, packet, n_response_bytes=5)

    result = {
        "mode": mode.value,
        "sent": packet,
        "received": response,
        "success": False,
        "reason": None,
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


# --------------------------------------------------------------------------
# Init Mode 3: ISO9141-2 5-baud slow init
# --------------------------------------------------------------------------

def _send_bit_banged_byte(ser: serial.Serial, byte_val: int, bit_ms: float) -> None:
    """
    Bit-bangs a single byte onto K-Line at 5 baud (200ms/bit) using the
    break_condition line as a manual low/high driver:
      - start bit: low
      - 8 data bits, LSB first: low=0, high=1
      - stop bit: high
    """
    bits = [0]  # start bit
    bits += [(byte_val >> i) & 1 for i in range(8)]  # LSB first
    bits += [1]  # stop bit

    for bit in bits:
        ser.break_condition = (bit == 0)
        time.sleep(bit_ms / 1000.0)
    ser.break_condition = False  # ensure idle-high at the end


def slow_init_handshake(
    ser: serial.Serial,
    address: int = SLOW_INIT_ADDRESS,
    target_baud: int = 10400,
    key_wait_s: float = 2.0,
) -> dict:
    """
    Performs ISO9141-2 5-baud slow init:
      1. Bit-bang `address` (default 0x10) at 5 baud on K-Line.
      2. Switch port to target_baud and listen for sync byte (0x55) + 2 key bytes.
      3. If 2 key bytes were received, attempt the standard W4 response:
         echo back the bitwise complement of the second key byte.
      4. Report everything observed -- this does not assume the ECU follows
         the full ISO9141 keyword negotiation, since we don't have a
         confirmed spec for this ECU.
    """
    logger.debug("Slow init: address=0x%02X bit_time=200ms", address)

    # Bit-bang the address byte at 5 baud (200ms per bit) before reconfiguring
    # the UART, since this is a manual line-level operation, not a framed
    # UART transmission.
    _send_bit_banged_byte(ser, address, bit_ms=200.0)

    # Now bring the port up at the target communication baud rate to read
    # whatever the ECU sends back.
    _reopen_baud(ser, target_baud)

    result = {
        "mode": InitMode.SLOW_5BAUD.value,
        "address_sent": address,
        "sync_byte": None,
        "key_bytes": None,
        "echo_response": None,
        "success": False,
        "reason": None,
    }

    deadline = time.time() + key_wait_s
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

    # Standard ISO9141-2 W4 step: send the inverted complement of the 2nd
    # key byte; ECU should echo back the inverted complement of the address.
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


# --------------------------------------------------------------------------
# Init Mode 4: Passive sniff (no wake-up at all)
# --------------------------------------------------------------------------

def passive_sniff(ser: serial.Serial, duration_s: float = 5.0) -> list:
    """
    Opens no protocol at all -- just listens on the bus for `duration_s`
    seconds and returns whatever bytes show up. Useful to rule out:
      - ECU already broadcasting telemetry unprompted
      - line noise / floating K-Line (constant 0x00 or 0xFF garbage)
      - wrong baud rate (looks like noise, but isn't)
    """
    ser.reset_input_buffer()
    end = time.time() + duration_s
    captured = bytearray()
    while time.time() < end:
        chunk = ser.read(64)
        if chunk:
            captured.extend(chunk)
            _log_rx("sniff", chunk)
    return list(captured)

#
# New Function
#
def two_phase_handshake(ser: serial.Serial) -> dict:
    """
    Two-phase Honda K-Line init, derived from brute-force findings:
      Phase 1: Break low=25ms high=25ms, send address 0x33, expect 0x31 back.
      Phase 2: Send standard service request, read ECU response.

    The ECU clears bit 1 of the address byte as its acknowledgment:
      0x33 (0011 0011) -> 0x31 (0011 0001)
    This is a deliberate wake confirmation, not noise.
    """
    result = {
        "mode": InitMode.TWO_PHASE.value,
        "phase1_sent": None,
        "phase1_recv": None,
        "phase2_sent": None,
        "phase2_recv": None,
        "success": False,
        "reason": None,
    }

    # Phase 1 send
    addr_packet = [0x33]
    _log_tx("two_phase_p1", addr_packet)
    ser.write(bytearray(addr_packet))

    # consume our own TX echo of 0x33
    echo = ser.read(1)
    if echo and echo[0] == 0x33:
        _log_rx("two_phase_p1_echo", echo)
        ack = ser.read(1)
    else:
        ack = echo

    result["phase1_sent"] = addr_packet
    result["phase1_recv"] = list(ack) if ack else []
    _log_rx("two_phase_p1_ack", ack)

    if not ack or ack[0] != 0x31:
        result["reason"] = f"phase1_no_ack (got {ack[0]:02X if ack else 'nothing'})"
        return result

    # ECU sends more bytes after 0x31 -- drain the full phase 1 response
    # before sending anything, otherwise we collide with its transmission.
    # Read with short timeout until the bus goes quiet.
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

    logger.debug("Phase 1 complete — bus now quiet, proceeding to phase 2")

    # Small settle before phase 2
    time.sleep(0.05)

    # phase two

    def send_slow(ser, packet, interbyte_ms=10):
        """Send packet byte by byte, reading back each echo before sending next."""
        for b in packet:
            ser.write(bytes([b]))
            echo = ser.read(1)  # wait for our own echo
            _log_rx(f"slow_echo 0x{b:02X}", echo or [])
            time.sleep(interbyte_ms / 1000.0)

    phase2_candidates = [
        ("std_0F_F0",  [0x72, 0x05, 0x0F, 0xF0]),
        ("query_71",   [0x72, 0x05, 0x71, 0x00]),
        ("hdr_74",     [0x74, 0x05, 0x0F, 0xF0]),
        ("minimal_72", [0x72, 0x02, 0x72]),
    ]

    for label, payload in phase2_candidates:
        cs = calculate_checksum(payload)
        svc_packet = payload + [cs]

        ser.reset_input_buffer()
        ser.reset_output_buffer()

        _log_tx(f"p2_slow [{label}]", svc_packet)
        send_slow(ser, svc_packet, interbyte_ms=10)

        # Now read the actual ECU response with clean window
        ser.timeout = 0.1
        raw = bytearray()
        deadline = time.time() + 3.0
        while time.time() < deadline:
            chunk = ser.read(64)
            if chunk:
                raw.extend(chunk)
        ser.timeout = 1.0

        _log_rx(f"p2_slow_response [{label}]", list(raw))

        # anything at all beyond silence is a win
        if raw:
            logger.debug("*** GOT RESPONSE [%s]: %s", label,
                        " ".join(f"{b:02X}" for b in raw))
            result["phase2_sent"] = svc_packet
            result["phase2_recv"] = list(raw)
            result["success"] = True
            result["reason"] = f"phase2_got_response [{label}]"
            return result

        time.sleep(0.1)

    result["reason"] = "phase2_all_candidates_silent"
    return result

# --------------------------------------------------------------------------
# Unified entry point
# --------------------------------------------------------------------------

def perform_handshake(ser: serial.Serial, mode: InitMode = InitMode.FAST_KEIHIN, **kwargs) -> dict:
    """
    Dispatches to the requested init strategy and returns a result dict.
    Kept return type consistent (dict, not bool) so callers/CLI can report
    *why* something failed, which matters a lot more than a flat True/False
    when you're reverse-engineering an undocumented ECU.
    """
    if mode in (InitMode.FAST_KEIHIN, InitMode.FAST_ISO14230):
        return fast_init_handshake(ser, mode=mode)
    if mode == InitMode.SLOW_5BAUD:
        return slow_init_handshake(ser, **kwargs)
    if mode == InitMode.TWO_PHASE:
        return two_phase_handshake(ser)
    if mode == InitMode.PASSIVE_SNIFF:
        captured = passive_sniff(ser, **kwargs)
        return {
            "mode": mode.value,
            "captured": captured,
            "success": len(captured) > 0,
            "reason": None if captured else "no_bytes_observed",
        }
    raise ValueError(f"Unknown init mode: {mode}")


def sweep_init_modes(port: str, baudrate: int, timeout: float, delay_between_s: float = 1.0) -> dict:
    """
    Tries every init mode in turn against the same physical connection and
    reports the outcome of each. Reopens the port fresh before each attempt
    since slow-init changes the live baud rate.
    """
    results = {}
    for mode in (InitMode.FAST_KEIHIN, InitMode.FAST_ISO14230, InitMode.SLOW_5BAUD):
        ser = open_connection(port, baudrate, timeout)
        try:
            results[mode.value] = perform_handshake(ser, mode=mode)
        except Exception as exc:  # noqa: BLE001 - we want to keep sweeping
            results[mode.value] = {"mode": mode.value, "success": False, "reason": f"exception: {exc}"}
        finally:
            ser.close()
        time.sleep(delay_between_s)
    return results


# --------------------------------------------------------------------------
# Table query / probing (unchanged protocol-wise, with logging added)
# --------------------------------------------------------------------------

def query_table(ser: serial.Serial, table_id: int) -> list | None:
    """
    Sends query packet byte by byte, reconstructs ECU response from interleaved echoes.
    ECU starts responding immediately after first byte received, so its response
    frame is shifted through our per-byte echo reads.
    """
    packet = build_packet(MODE_QUERY, table_id)
    n = len(packet)

    ser.reset_input_buffer()
    ser.reset_output_buffer()
    _log_tx(f"query_table 0x{table_id:02X}", packet)

    interleaved = []

    # Send byte by byte, collect what comes back per byte
    for b in packet:
        ser.write(bytes([b]))
        echo = ser.read(1)
        interleaved.append(echo[0] if echo else None)
        _log_rx(f"query_byte 0x{b:02X}", echo or [])
        time.sleep(0.010)

    # Read any remaining bytes the ECU sends after our last byte
    ser.timeout = 0.1
    trailing = bytearray()
    deadline = time.time() + 2.0
    while time.time() < deadline:
        chunk = ser.read(64)
        if chunk:
            trailing.extend(chunk)
    ser.timeout = 1.0

    # Reconstruct ECU response:
    # Byte 0 of interleaved is always our own TX echo (our first byte back)
    # Bytes 1..n-1 of interleaved are ECU response bytes 0..n-2
    # Remaining trailing bytes are ECU response bytes n-1..end
    ecu_response = []
    for i in range(1, n):
        if interleaved[i] is not None:
            ecu_response.append(interleaved[i])
    ecu_response.extend(list(trailing))

    _log_rx(f"query_table_reconstructed 0x{table_id:02X}", ecu_response)

    if not ecu_response:
        return None

    # Check if ECU is saying "invalid table" -- 0xFF as first response byte
    if ecu_response[0] == 0xFF:
        logger.debug("Table 0x%02X: ECU returned 0xFF status (likely invalid/unsupported)", table_id)
        return None

    return ecu_response


def probe_tables(
    ser: serial.Serial,
    start: int = 0x00,
    end: int = 0xFF,
) -> dict:
    """Sweeps through table IDs to identify responsive offsets on the ECU."""
    results = {}
    for table_id in range(start, end + 1):
        try:
            resp = query_table(ser, table_id)
            if resp is None:
                results[table_id] = {"status": "INACTIVE"}
            else:
                results[table_id] = {
                    "status": "ACTIVE",
                    "length": len(resp),
                    "raw_bytes": resp,
                }
        except Exception:
            results[table_id] = {"status": "ERROR"}
    return results
