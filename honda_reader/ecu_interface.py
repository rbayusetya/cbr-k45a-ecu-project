"""
Honda Keihin K-Line ECU interface — rewritten against CONFIRMED protocol.

Prior versions of this module were built through brute-force reverse
engineering with no reference. We have since obtained:
  1. Real source from eculib/honda.py (Ryan Hope's original HondaECU project,
     GPL-3, later commercialized by MCU Innovations) -- confirms message
     framing, checksum algorithm, and the send/receive pattern.
  2. A Scribd-hosted "Honda Kline Command Protocol Guide" table showing
     exact confirmed request/response byte sequences for WAKEUP, VIN,
     LIVE DATA (table 0x17), READ DTC, and CLEAR DTC.

Both sources agree byte-for-byte once decoded, and this rewrite is built
directly from that confirmed spec rather than guesswork. Notably:
  - Our earlier init packet used mode byte 0x0F, which was NEVER confirmed
    and never worked -- the real init mode byte is 0x00.
  - Our earlier default table (0x11) was invalid on this ECU family --
    the real live-data table is 0x17.
  - The "bit-flip collision" we spent a long time chasing was very likely
    an artifact of our OWN per-byte send/read interleaving, not real bus
    contention. The real protocol drains the full TX echo as one distinct
    phase, THEN does a separate read for the actual ECU response -- there
    is no byte-level race if done this way.

One thing NOT in the reference source: our own hardware/ECU empirically
required an extra address handshake (send 0x33, expect 0x31) before the
break-pulse + wake + init sequence would do anything at all. This isn't
documented anywhere we've found, so it's kept here as an optional,
clearly-labeled prefix step (`do_address_prestep`) rather than assumed
universal. Toggle it off to test whether it was ever really necessary now
that the echo-draining bug is fixed -- it's possible it was compensating
for the same collision bug elsewhere in the old code, not a real protocol
requirement.
"""

import logging
import time
from enum import Enum

import serial

logger = logging.getLogger("honda_reader.ecu")


# ---------------------------------------------------------------------------
# Confirmed protocol constants
# ---------------------------------------------------------------------------

# Known-good table IDs, confirmed from eculib/honda.py probe_tables() default list.
KNOWN_TABLES = [0x10, 0x11, 0x17, 0x20, 0x21, 0x60, 0x61, 0x67, 0x70, 0x71, 0xD0, 0xD1]

# Live telemetry table -- confirmed via Scribd capture AND matches the
# AutotronicCommunity K25 reference. Our old default of 0x11 was wrong.
LIVE_DATA_TABLE = 0x17

# VIN is read the same way as any other table, at table ID 0x00.
VIN_TABLE = 0x00

# DTC code lookup, ported from eculib/honda.py
DTC = {
    "01-01": "MAP sensor circuit low voltage",
    "01-02": "MAP sensor circuit high voltage",
    "02-01": "MAP sensor performance problem",
    "07-01": "ECT sensor circuit low voltage",
    "07-02": "ECT sensor circuit high voltage",
    "08-01": "TP sensor circuit low voltage",
    "08-02": "TP sensor circuit high voltage",
    "09-01": "IAT sensor circuit low voltage",
    "09-02": "IAT sensor circuit high voltage",
    "11-01": "VS sensor no signal",
    "12-01": "No.1 primary injector circuit malfunction",
    "13-01": "No.2 primary injector circuit malfunction",
    "14-01": "No.3 primary injector circuit malfunction",
    "15-01": "No.4 primary injector circuit malfunction",
    "16-01": "No.1 secondary injector circuit malfunction",
    "17-01": "No.2 secondary injector circuit malfunction",
    "18-01": "CMP sensor no signal",
    "19-01": "CKP sensor no signal",
    "21-01": "O2 sensor malfunction",
    "23-01": "O2 sensor heater malfunction",
    "25-02": "Knock sensor circuit malfunction",
    "25-03": "Knock sensor circuit malfunction",
    "29-01": "IACV circuit malfunction",
    "33-02": "ECM EEPROM malfunction",
    "34-01": "ECV POT low voltage malfunction",
    "34-02": "ECV POT high voltage malfunction",
    "35-01": "EGCA malfunction",
    "48-01": "No.3 secondary injector circuit malfunction",
    "49-01": "No.4 secondary injector circuit malfunction",
    "51-01": "HESD linear solenoid malfunction",
    "54-01": "Bank angle sensor circuit low voltage",
    "54-02": "Bank angle sensor circuit high voltage",
    "56-01": "Knock sensor IC malfunction",
    "86-01": "Serial communication malfunction",
}


class InitMode(str, Enum):
    """
    Only two modes remain after cleanup:
      TWO_PHASE     - the real, confirmed protocol (optionally prefixed
                       with our empirically-required address handshake)
      PASSIVE_SNIFF - listen-only, no transmission, useful for diagnostics
                       or capturing a real tool's session on a Y-tap
    Older speculative modes (fast_iso14230, slow_5baud, and the old
    fast_keihin using an unconfirmed 0x0F init byte) have been removed --
    they were guesses made before we had any real reference, and keeping
    them around no longer serves a purpose now that the real protocol
    is confirmed.
    """
    TWO_PHASE = "two_phase"
    PASSIVE_SNIFF = "passive_sniff"


# ---------------------------------------------------------------------------
# Checksum / message framing -- ported from eculib/honda.py, verified by
# hand against every confirmed capture we have (wake, init, VIN, live data,
# read/clear DTC all check out byte-for-byte).
# ---------------------------------------------------------------------------

def checksum(data: list) -> int:
    return (0x100 - (sum(data) & 0xFF)) & 0xFF

def message_is_valid(full_message: list) -> bool:
    return checksum(full_message) == 0

def format_message(mtype: list, data: list) -> list:
    """Builds a complete message: mtype + [length] + data + [checksum]."""
    ml = len(mtype)
    dl = len(data)
    msgsize = 2 + ml + dl
    msg = mtype + [msgsize] + data
    msg = msg + [checksum(msg)]
    return msg

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


def _read_exact(ser: serial.Serial, n: int, deadline: float):
    """
    Reads exactly n bytes, polling until the deadline. Returns bytes if
    successful, or None if the deadline passes with fewer than n bytes
    collected. This is the building block for correctly separating
    "our own echo" from "the ECU's actual response" as two distinct,
    sequential phases -- the key fix from the old collision-prone code.
    """
    buf = bytearray()
    while len(buf) < n and time.time() < deadline:
        chunk = ser.read(n - len(buf))
        if chunk:
            buf.extend(chunk)
    if len(buf) < n:
        return None
    return bytes(buf)


# ---------------------------------------------------------------------------
# Core send/receive primitive
#
# Confirmed two-phase pattern from eculib.honda.HondaECU.send():
#   1. Write the full message.
#   2. Read and discard EXACTLY len(message) bytes as our own TX echo --
#      as one distinct, complete phase, not interleaved byte-by-byte.
#   3. THEN, as a separate read, get the response header + length byte.
#   4. Read the remaining bytes (data + checksum) based on the length byte.
#   5. Validate checksum and response header.
#
# There is no byte-level race in this pattern -- the old "bit-flip
# collision" we spent so long chasing was very likely an artifact of our
# own flawed per-byte interleaved send/read logic, not real ECU behavior.
# ---------------------------------------------------------------------------

def send_and_receive(ser: serial.Serial, mtype: list, data: list,
                     timeout: float = 2.0, label: str = "",
                     inter_byte_delay_ms: float = 0.0) -> list | None:
    msg = format_message(mtype, data)
    ml = len(mtype)
    label = label or f"cmd_0x{mtype[0]:02X}"

    ser.reset_input_buffer()
    ser.reset_output_buffer()

    _log_tx(label, msg)
    if inter_byte_delay_ms > 0:
        for b in msg:
            ser.write(bytes([b]))
            time.sleep(inter_byte_delay_ms / 1000.0)
    else:
        ser.write(bytearray(msg))

    deadline = time.time() + timeout

    # Phase 1: drain our own TX echo
    echo = _read_exact(ser, len(msg), deadline)
    if echo is None:
        logger.debug("%s: no echo received (timeout)", label)
        return None
    _log_rx(f"{label}_echo", list(echo))

    # Phase 2: read response header + length byte.
    header = _read_exact(ser, ml + 1, deadline)
    if header is None:
        logger.debug("%s: no response header (timeout)", label)
        return None

    length_byte = header[ml]
    remaining = length_byte - ml - 1
    if remaining <= 0:
        logger.debug("%s: implausible length byte 0x%02X", label, length_byte)
        return None

    rest = _read_exact(ser, remaining, deadline)
    if rest is None:
        logger.debug("%s: incomplete response body (timeout)", label)
        return None

    full_response = list(header) + list(rest)
    _log_rx(f"{label}_response", full_response)

    if not message_is_valid(full_response):
        logger.debug("%s: checksum mismatch: %s", label, _hex(full_response))
        return None

    expected_header = [(b & 0x0F) for b in mtype]
    if full_response[:ml] != expected_header:
        logger.debug("%s: unexpected header %s (expected %s)",
                     label, _hex(full_response[:ml]), _hex(expected_header))
        return None

    rdata = full_response[ml + 1:-1]
    return rdata


# ---------------------------------------------------------------------------
# Break pulse (physical wake-up line toggle)
# ---------------------------------------------------------------------------

def _break_pulse(ser: serial.Serial, low_ms: float, high_ms: float) -> None:
    # Bulletproof K-Line low pulse: spam 0x00 bytes to hold the line low.
    baud = ser.baudrate
    byte_time_ms = (10.0 / baud) * 1000.0  # 10 bits per byte
    num_bytes = int(low_ms / byte_time_ms)

    ser.write(b'\x00' * num_bytes)
    # Give the adapter a moment to flush the TX buffer
    time.sleep(0.05)

    # Clear the RX buffer (the ECU might echo the 0x00s or glitch)
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    # Wait for the high/idle time
    time.sleep(high_ms / 1000.0)


# ---------------------------------------------------------------------------
# ISO9141-2 5-baud init -- NEW, separate experimental path
#
# Our confirmed working "address pre-step" (send 0x33 as a normal fast
# UART byte after a 25ms break, get 0x31 back) is NOT the same mechanism
# as a real 5-baud init, despite sharing the 0x33 byte value by
# coincidence. A genuine 5-baud init means bit-banging the address byte
# at 200ms per bit (~1.8 seconds total) -- a completely different
# physical event on the wire. We built this once before, but only ever
# tested it with address 0x10 (a common generic default), never 0x33
# specifically, and never with correct inter-byte timing on the
# handshake response. This is a from-scratch, careful rebuild.
#
# Sequence (per ISO9141-2, cross-checked against a separate independent
# description of the same spec):
#   1. Bit-bang the address byte (0x33) at 5 baud (200ms/bit): start bit
#      (low), 8 data bits LSB-first, stop bit (high).
#   2. Immediately switch the UART to 10400 baud.
#   3. Wait up to 50ms, then read whatever the ECU sends. Expected: 4
#      bytes -- keyword byte 1 (KB1), keyword byte 2 (KB2), then their
#      bitwise complements (~KB1, ~KB2) sent by the ECU itself. (This
#      differs from the textbook single sync-byte-then-2-keywords
#      description -- built to match what was actually observed/reported
#      for this specific implementation, not assumed from a textbook.)
#   4. Send byte 3 (~KB1) back to the ECU, wait 5ms, then send byte 4
#      (~KB2) back. This appears to be an echo-style acknowledgment
#      rather than the classic "compute and send ~KB2 only" W4 step --
#      again, built from the specific description we have for this ECU
#      rather than the general ISO9141-2 textbook procedure.
#   5. From here, the confirmed 0x72-prefixed Keihin message layer
#      (send_and_receive, query_table, etc.) should be usable.
#
# Timing matters: too fast between steps has been reported to fail, so
# explicit delays are used rather than firing everything back-to-back.
# ---------------------------------------------------------------------------

def _send_bit_banged_byte(ser: serial.Serial, byte_val: int, bit_ms: float = 200.0) -> None:
    """
    Bit-bangs a single byte onto K-Line at 5 baud (200ms/bit) using the
    break_condition line as a manual low/high driver:
      - start bit: low
      - 8 data bits, LSB first: low=0, high=1
      - stop bit: high
    """
    bits = [0]
    bits += [(byte_val >> i) & 1 for i in range(8)]
    bits += [1]

    for bit in bits:
        ser.break_condition = (bit == 0)
        time.sleep(bit_ms / 1000.0)
    ser.break_condition = False


def iso_5baud_handshake(ser: serial.Serial, port: str, baudrate: int, timeout: float,
                         address: int = 0x33,
                         keyword_wait_s: float = 0.05,
                         interbyte_delay_s: float = 0.005) -> dict:
    """
    Performs the full 4-phase ISO9141-2 5-baud init described above.
    Returns a diagnostic dict with everything observed at each phase --
    this is written for exploration, not to silently hide partial
    failures, since we don't yet know for certain this sequence is
    correct for this specific ECU either.

    NOTE: this reopens the serial port at a different baud partway
    through (5-baud bit-banging happens at whatever baud the port is
    already at via break_condition toggling, which is baud-independent;
    but we still need port/baudrate/timeout to correctly REOPEN at
    10400 for the keyword exchange phase).
    """
    result = {
        "mode": "iso_5baud",
        "address_sent": address,
        "keyword_bytes_captured": [],
        "sent_byte3": None,
        "sent_byte4": None,
        "success": False,
        "reason": None,
    }

    # --- Phase 1: bit-bang the address byte at true 5 baud ---
    logger.debug("ISO 5-baud Phase 1: bit-banging address 0x%02X at 200ms/bit "
                 "(this takes ~1.8s)", address)
    _send_bit_banged_byte(ser, address, bit_ms=200.0)

    # --- Phase 2: switch to 10400 baud immediately ---
    logger.debug("ISO 5-baud Phase 2: switching to %d baud", baudrate)
    ser.baudrate = baudrate
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    # --- Phase 3: wait up to 50ms, capture whatever the ECU sends ---
    logger.debug("ISO 5-baud Phase 3: listening up to %.0fms for keyword bytes",
                 keyword_wait_s * 1000)
    captured = []
    start = time.time()
    deadline = start + keyword_wait_s
    while time.time() < deadline:
        chunk = ser.read(1)
        if chunk:
            elapsed_ms = (time.time() - start) * 1000.0
            captured.append((chunk[0], elapsed_ms))

    result["keyword_bytes_captured"] = captured
    formatted = " ".join(f"{b:02X}@{t:.2f}ms" for b, t in captured) if captured else "(none)"
    logger.debug("ISO 5-baud Phase 3 result: %s", formatted)

    if len(captured) < 4:
        result["reason"] = f"expected_4_keyword_bytes_got_{len(captured)}"
        return result

    kb1, kb2, inv_kb1, inv_kb2 = (captured[0][0], captured[1][0],
                                   captured[2][0], captured[3][0])

    # Sanity-check the complement relationship, but log rather than hard-fail --
    # we want to see what's really happening even if it doesn't match exactly.
    if inv_kb1 != ((~kb1) & 0xFF):
        logger.debug("ISO 5-baud: byte3 (0x%02X) is NOT the bitwise complement "
                     "of byte1 (0x%02X) -- expected 0x%02X",
                     inv_kb1, kb1, (~kb1) & 0xFF)
    if inv_kb2 != ((~kb2) & 0xFF):
        logger.debug("ISO 5-baud: byte4 (0x%02X) is NOT the bitwise complement "
                     "of byte2 (0x%02X) -- expected 0x%02X",
                     inv_kb2, kb2, (~kb2) & 0xFF)

    result["kb1"] = kb1
    result["kb2"] = kb2
    result["inv_kb1"] = inv_kb1
    result["inv_kb2"] = inv_kb2

    # --- Phase 4: echo byte3, wait 5ms, echo byte4 ---
    logger.debug("ISO 5-baud Phase 4: sending byte3 (0x%02X)", inv_kb1)
    ser.write(bytes([inv_kb1]))
    result["sent_byte3"] = inv_kb1

    time.sleep(interbyte_delay_s)

    logger.debug("ISO 5-baud Phase 4: sending byte4 (0x%02X) after %.0fms delay",
                 inv_kb2, interbyte_delay_s * 1000)
    ser.write(bytes([inv_kb2]))
    result["sent_byte4"] = inv_kb2

    # Give the ECU a brief moment before anything else touches the bus.
    time.sleep(interbyte_delay_s)
    ser.reset_input_buffer()

    result["success"] = True
    result["reason"] = "keyword_exchange_complete"
    return result


# ---------------------------------------------------------------------------
# Handshake -- confirmed protocol, with optional empirical prefix.
#
# Confirmed sequence (from eculib.honda.HondaECU.init/ping/diag and
# matching the Scribd WAKEUP/table rows):
#   1. Break pulse low=70ms, high=130ms
#   2. ping():  mtype=[0xFE], data=[0x72]        -> expect header 0x0E
#   3. diag():  mtype=[0x72], data=[0x00, 0xF0]  -> expect header 0x02
#
# Empirical prefix (do_address_prestep=True, default on since it's what
# has actually worked on this bike so far): before the above, send 0x33
# and expect 0x31 back after a 25ms/25ms break pulse. This is NOT in any
# reference source we've found. Now that the collision bug in the old
# per-byte query code is understood and fixed here, it's worth testing
# with do_address_prestep=False to see if this step was ever really
# necessary, or was masking a different bug.
# ---------------------------------------------------------------------------

def two_phase_handshake(ser: serial.Serial, do_address_prestep: bool = True,
                         skip_wake: bool = False, skip_diag: bool = False,
                         no_break: bool = False) -> dict:
    """
    no_break: eculib's own detect_ecu_state() tries a table read COLD --
    before any break pulse at all -- and only calls init() (break pulse)
    if that gets no response. We had never tested that order. When
    no_break=True, do_address_prestep and skip_wake are both forced off
    (there's no break, so there's nothing to prefix or replace), and the
    handshake becomes a no-op that just confirms the connection is open --
    real communication should be attempted directly via the `raw` command
    or query_table() with no wake sequence at all.
    """
    if no_break:
        logger.debug("no_break=True: skipping ALL wake sequences (prestep, break, "
                     "wake, diag) -- testing whether the ECU responds cold, "
                     "matching eculib's detect_ecu_state() which tries "
                     "communication before any break pulse")
        return {
            "mode": InitMode.TWO_PHASE.value,
            "address_prestep_used": False,
            "address_prestep_recv": None,
            "skip_wake": True,
            "skip_diag": True,
            "no_break": True,
            "ping_recv": None,
            "diag_recv": None,
            "success": True,
            "reason": "no_break_cold_connection",
        }

    result = {
        "mode": InitMode.TWO_PHASE.value,
        "address_prestep_used": do_address_prestep,
        "address_prestep_recv": None,
        "skip_wake": skip_wake,
        "skip_diag": skip_diag,
        "ping_recv": None,
        "diag_recv": None,
        "success": False,
        "reason": None,
    }

    if do_address_prestep:
        logger.debug("Address pre-step: break low=25ms high=25ms, send 0x33")
        _break_pulse(ser, low_ms=25, high_ms=25)

        ser.write(bytes([0x33]))
        echo = ser.read(1)
        if echo and echo[0] == 0x33:
            _log_rx("prestep_echo", echo)
            ack = ser.read(1)
        else:
            ack = echo

        _log_rx("prestep_ack", ack or [])
        result["address_prestep_recv"] = list(ack) if ack else []

        if not ack or ack[0] != 0x31:
            result["reason"] = "address_prestep_no_ack"
            return result

        # Drain any trailing bytes before moving on.
        # NOTE: Do NOT use a 200ms timeout here! It will drop the K-line session.
        ser.timeout = 0.01  # MUST BE 10ms, NOT 200ms!
        while ser.read(1):
            pass
        ser.timeout = 1.0
        time.sleep(0.05)

    if do_address_prestep:
        # The prestep's own break pulse (25ms/25ms) already served as the
        # wake-up for this ECU historically -- a SECOND break pulse here
        # doesn't match the one sequence that has ever actually gotten a
        # response out of this bike. Skip straight to wake/diag.
        logger.debug("Address pre-step already ran -- skipping second break pulse")
    else:
        logger.debug("Break pulse: low=70ms high=130ms")
        _break_pulse(ser, low_ms=70, high_ms=130)

    if not skip_wake:
        ping_resp = send_and_receive(ser, [0xFE], [0x72], label="ping")
        result["ping_recv"] = ping_resp
        if ping_resp is None:
            result["reason"] = "ping_no_response"
            return result

    if skip_diag:
        logger.debug("skip_diag=True -- treating pre-step/wake completion as sufficient "
                     "for exploration; NOT requiring diag() to succeed")
        result["success"] = True
        result["reason"] = "handshake_partial_skip_diag"
        return result

    # Inside two_phase_handshake, replace the old diag_resp line with:
    # Honda diag session command is 0x00, 0xF0. Sender MUST be 0x02.
    diag_resp = send_and_receive(ser, [0x72], [0x00, 0xF0], label="diag")
    result["diag_recv"] = diag_resp
    if diag_resp is None:
        result["reason"] = "diag_no_response"
        return result

    result["success"] = True
    result["reason"] = "handshake_complete"
    return result


def passive_sniff(ser: serial.Serial, duration_s: float = 5.0) -> list:
    """Listen-only, no transmission. Useful for diagnostics or Y-tap capture."""
    ser.reset_input_buffer()
    captured = bytearray()
    end = time.time() + duration_s
    while time.time() < end:
        chunk = ser.read(64)
        if chunk:
            captured.extend(chunk)
            _log_rx("sniff", chunk)
    return list(captured)


def perform_handshake(ser: serial.Serial, mode: InitMode = InitMode.TWO_PHASE,
                       **kwargs) -> dict:
    if mode == InitMode.TWO_PHASE:
        return two_phase_handshake(ser, **kwargs)
    if mode == InitMode.PASSIVE_SNIFF:
        captured = passive_sniff(ser, **kwargs)
        return {
            "mode": mode.value,
            "captured": captured,
            "success": len(captured) > 0,
            "reason": None if captured else "no_bytes_observed",
        }
    raise ValueError(f"Unknown init mode: {mode}")


# ---------------------------------------------------------------------------
# Table reading
# ---------------------------------------------------------------------------

def query_table(ser: serial.Serial, table_id: int) -> list | None:
    return send_and_receive(ser, [0x72], [0x71, table_id],
                             label=f"read_table_0x{table_id:02X}")


def read_vin(ser: serial.Serial) -> list | None:
    """VIN is just table 0x00."""
    return query_table(ser, VIN_TABLE)


def read_live_data(ser: serial.Serial) -> list | None:
    """Confirmed live telemetry table."""
    return query_table(ser, LIVE_DATA_TABLE)


# ---------------------------------------------------------------------------
# Single-byte probe
#
# The corruption we see after the address pre-step doesn't change with
# byte-pacing (2ms/5ms/10ms all gave identical results), which rules out
# a millisecond-scale turnaround-timing issue. The corrupted echo also
# showed an EXTRA byte (0xFF) inserted right after our first header byte,
# shifting everything after it -- suggesting the ECU may be reacting to
# just the header byte alone, before we've sent anything else. This probe
# isolates that: send exactly one byte, then listen for a while and report
# everything observed, with nothing else in flight to confuse the picture.
# ---------------------------------------------------------------------------

def single_byte_probe(ser: serial.Serial, byte_val: int, window_s: float = 3.0) -> list:
    """
    Returns a list of (byte_value, elapsed_ms_since_tx) tuples, so we can
    see exactly when each byte arrived relative to transmission -- e.g.
    whether an echo and a real ECU reaction arrive together in the same
    instant (near-simultaneous bus event) or with a measurable gap
    (a genuine, timed ECU response).
    """
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    _log_tx("single_byte", [byte_val])
    tx_time = time.time()
    ser.write(bytes([byte_val]))

    captured = []
    deadline = tx_time + window_s
    while time.time() < deadline:
        chunk = ser.read(1)
        if chunk:
            elapsed_ms = (time.time() - tx_time) * 1000.0
            captured.append((chunk[0], elapsed_ms))

    formatted = " ".join(f"{b:02X}@{t:.2f}ms" for b, t in captured) if captured else "(none)"
    logger.debug("RX [single_byte_response]: %s", formatted)
    return captured


# ---------------------------------------------------------------------------
# VIN byte-by-byte probe
#
# single_byte_probe() showed the ECU replies with 0xFF roughly one
# byte-time after receiving just our header byte 0x72 alone -- suggesting
# it may treat a single byte as a complete short command rather than "the
# first byte of a longer message coming next." This sends the VIN request
# (72 05 71 00 18) ONE BYTE AT A TIME, listening after each individual
# byte, so we can see exactly what the ECU does at every step instead of
# guessing at the right framing. Every byte is sent regardless of what
# came back for the previous one -- this is a diagnostic tool, not yet a
# "smart" adaptive sender, since we don't know the real framing rules yet.
# ---------------------------------------------------------------------------

VIN_REQUEST_BYTES = [0x72, 0x05, 0x71, 0x00, 0x18]  # confirmed VIN request, byte by byte


def vin_probe_byte_by_byte(ser: serial.Serial, window_per_byte_s: float = 0.15) -> dict:
    """
    Sends each byte of the VIN request separately, listening for
    window_per_byte_s after each one. Returns {byte_index: [(byte, elapsed_ms), ...]}
    so you can see exactly when/what the ECU says after each byte we send.
    """
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    results = {}

    for i, b in enumerate(VIN_REQUEST_BYTES):
        _log_tx(f"vin_byte_{i}", [b])
        tx_time = time.time()
        ser.write(bytes([b]))

        captured = []
        deadline = tx_time + window_per_byte_s
        while time.time() < deadline:
            chunk = ser.read(1)
            if chunk:
                elapsed_ms = (time.time() - tx_time) * 1000.0
                captured.append((chunk[0], elapsed_ms))

        formatted = " ".join(f"{cb:02X}@{ct:.2f}ms" for cb, ct in captured) if captured else "(none)"
        logger.debug("After sending byte %d (0x%02X): %s", i, b, formatted)

        results[i] = {"sent_byte": b, "captured": captured}

    return results


def probe_known_tables(ser: serial.Serial) -> dict:
    """
    Checks only the confirmed-valid table list from eculib/honda.py,
    instead of blindly sweeping 0x00-0xFF. Much faster and grounded in
    real reference data rather than guesswork.
    """
    results = {}
    for table_id in KNOWN_TABLES:
        resp = query_table(ser, table_id)
        if resp is not None:
            results[table_id] = {"status": "ACTIVE", "length": len(resp), "raw_bytes": resp}
        else:
            results[table_id] = {"status": "INACTIVE"}
    return results


def probe_tables(ser: serial.Serial, start: int = 0x00, end: int = 0xFF) -> dict:
    """
    Full range sweep, kept as a utility for further exploration beyond the
    confirmed table list (e.g. if this ECU has extra vendor-specific tables
    not in the reference list). Much less likely to be needed now, but
    harmless to keep since it uses the corrected send_and_receive logic.
    """
    results = {}
    for table_id in range(start, end + 1):
        try:
            resp = query_table(ser, table_id)
            if resp is not None:
                results[table_id] = {"status": "ACTIVE", "length": len(resp), "raw_bytes": resp}
            else:
                results[table_id] = {"status": "INACTIVE"}
        except Exception:
            results[table_id] = {"status": "ERROR"}
    return results


# ---------------------------------------------------------------------------
# Fault codes -- ported from eculib/honda.py get_faults()
# ---------------------------------------------------------------------------

def get_faults(ser: serial.Serial) -> dict:
    """
    Reads current and past DTCs. Ported from eculib.honda.HondaECU.get_faults().
    Fault data format: response payload starts with a 3-byte echo of our own
    request tail ([0x74 or 0x73, index, our_checksum]), followed by fault
    code pairs at fixed offsets.
    """
    faults = {"past": [], "current": []}

    for i in range(1, 0x0C):
        resp = send_and_receive(ser, [0x72], [0x74, i], label=f"dtc_current_{i}")
        if resp is None:
            break
        for j in (3, 5, 7):
            if j + 1 < len(resp) and resp[j] != 0:
                faults["current"].append(f"{resp[j]:02d}-{resp[j+1]:02d}")
        if len(resp) > 2 and resp[2] == 0:
            break

    for i in range(1, 0x0C):
        resp = send_and_receive(ser, [0x72], [0x73, i], label=f"dtc_past_{i}")
        if resp is None:
            break
        for j in (3, 5, 7):
            if j + 1 < len(resp) and resp[j] != 0:
                faults["past"].append(f"{resp[j]:02d}-{resp[j+1]:02d}")
        if len(resp) > 2 and resp[2] == 0:
            break

    return faults


def clear_faults(ser: serial.Serial) -> bool:
    """Clear DTCs. Confirmed format: mtype=[0x72], data=[0x60, 0x01]."""
    resp = send_and_receive(ser, [0x72], [0x60, 0x01], label="clear_dtc")
    return resp is not None
