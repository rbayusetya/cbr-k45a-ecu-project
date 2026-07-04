"""
Honda K-Line ECU Brute Force Init Sequencer
============================================
Since we have no confirmed factory spec for the CBR150R K45A (Indonesian
market), this module systematically sweeps every meaningful variable in the
wake-up phase and logs EVERYTHING observed on the wire -- including partial,
garbled, or unexpected responses -- to a JSONL file so no finding is ever lost
between sessions.

Variables swept:
    - Break pulse low duration (ms)
    - Break pulse high/recovery duration (ms)
    - Post-break delay before sending packet (ms)
    - Init packet payload (multiple known candidates)
    - Baud rate (10400 is standard, but not confirmed for K45A)

Philosophy:
    We don't assume success/failure based on matching an expected response.
    ANY byte that comes back from the ECU after we send something is a finding.
    Even a single 0xFF is more useful than silence -- it tells us the ECU is
    alive and we're close to waking it up. So we log and score EVERYTHING.
"""

import itertools
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

import serial

logger = logging.getLogger("honda_reader.bruteforce")


# ---------------------------------------------------------------------------
# Candidate parameter space
# ---------------------------------------------------------------------------

# Break pulse low durations to try (ms)
BREAK_LOW_CANDIDATES = [25, 50, 70, 100, 200, 300]

# Break pulse high/recovery durations to try (ms)
BREAK_HIGH_CANDIDATES = [25, 50, 100, 120, 200]

# Delay between end of break pulse and sending packet (ms)
POST_BREAK_DELAYS = [0, 10, 25, 50, 100]

# Baud rates to try -- 10400 is standard Keihin, others are long shots
BAUD_CANDIDATES = [10400, 9600, 19200]

# Known candidate init packets (payload only, checksum appended at runtime).
# Each entry is (label, bytes_without_checksum).
# We try BOTH checksum algorithms for each (subtraction and plain sum).
PACKET_CANDIDATES = [
    # Standard Keihin "wake" query -- most common in clone tools
    ("keihin_standard",     [0x72, 0x05, 0x0F, 0xF0]),
    # Variant seen in some Honda HDS captures with 0xF5 instead of 0xF0
    ("keihin_f5_variant",   [0x72, 0x05, 0x0F, 0xF5]),
    # Some tools send just a 3-byte wake with no mode/table fields
    ("short_wake",          [0xFE, 0x04, 0xFF]),
    # Raw address byte only -- some ECUs respond to a single byte probe
    ("single_addr_10",      [0x10]),
    ("single_addr_33",      [0x33]),
    # Null probe -- all zeros, just to see if ECU reacts to anything
    ("null_probe",          [0x00]),
]

# How long to wait for a response after sending a packet (seconds)
RESPONSE_TIMEOUT = 1.0

# Max bytes to read as response
MAX_RESPONSE_BYTES = 16

# Minimum score to flag a result as "interesting" in summary output
INTERESTING_SCORE_THRESHOLD = 1


# ---------------------------------------------------------------------------
# Scoring -- we don't assume we know what a valid response looks like.
# We just rank how "interesting" a response is so the most promising
# candidates bubble up in the summary report.
# ---------------------------------------------------------------------------

def score_response(sent: list, received: list) -> int:
    """
    Heuristic score for how interesting a response is.
    Higher = more likely to be a real ECU response rather than noise/echo.
    0 = no response at all.
    """
    if not received:
        return 0

    score = 0

    # Any response at all is worth something
    score += 1

    # Response that is NOT just an echo of what we sent is much more interesting
    if received != sent[:len(received)]:
        score += 5

    # Response starting with 0x02 is a known Keihin response header
    if received[0] == 0x02:
        score += 10

    # Response starting with 0x04 is seen in some Honda variants
    if received[0] == 0x04:
        score += 5

    # Length byte present and plausible (2nd byte = total length, 3-16 range)
    if len(received) >= 2 and 3 <= received[1] <= 16:
        score += 3

    # Checksum valid (subtraction method)
    if len(received) >= 2:
        data_sum = sum(received[:-1]) & 0xFF
        expected_cs = (0x100 - data_sum) & 0xFF
        if received[-1] == expected_cs:
            score += 5

    # Non-trivial byte values (not all 0x00 or all 0xFF -- likely real data)
    if not all(b == 0x00 for b in received) and not all(b == 0xFF for b in received):
        score += 2

    return score


# ---------------------------------------------------------------------------
# Checksum variants
# ---------------------------------------------------------------------------

def cs_subtraction(packet: list) -> int:
    """Standard Keihin: (0x100 - sum) & 0xFF"""
    return (0x100 - (sum(packet) & 0xFF)) & 0xFF


def cs_plain_sum(packet: list) -> int:
    """Plain 8-bit sum truncated -- seen in some Honda variant docs"""
    return sum(packet) & 0xFF


def cs_xor(packet: list) -> int:
    """XOR of all bytes -- less common but worth trying"""
    result = 0
    for b in packet:
        result ^= b
    return result


CHECKSUM_VARIANTS = [
    ("subtraction", cs_subtraction),
    ("plain_sum",   cs_plain_sum),
    ("xor",         cs_xor),
    ("none",        None),  # No checksum appended at all
]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    timestamp: str
    baud: int
    break_low_ms: int
    break_high_ms: int
    post_break_delay_ms: int
    packet_label: str
    checksum_type: str
    sent: list
    received: list
    score: int
    notes: str = ""


# ---------------------------------------------------------------------------
# Core probe function -- one combination
# ---------------------------------------------------------------------------

def _probe_one(
    port: str,
    baud: int,
    break_low_ms: int,
    break_high_ms: int,
    post_break_ms: int,
    packet_label: str,
    payload: list,
    cs_label: str,
    cs_fn,
) -> ProbeResult:
    """Opens port, sends one complete wake-up attempt, returns a ProbeResult."""

    # Build packet
    if cs_fn is not None:
        packet = payload + [cs_fn(payload)]
    else:
        packet = payload[:]

    received = []
    notes = ""

    try:
        ser = serial.Serial(
            port=port,
            baudrate=baud,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=RESPONSE_TIMEOUT,
        )

        # Break pulse
        ser.break_condition = True
        time.sleep(break_low_ms / 1000.0)
        ser.break_condition = False
        time.sleep(break_high_ms / 1000.0)

        # Post-break settle delay
        if post_break_ms > 0:
            time.sleep(post_break_ms / 1000.0)

        ser.reset_input_buffer()
        ser.reset_output_buffer()

        # Send packet
        ser.write(bytearray(packet))

        logger.debug(
            "TX baud=%d low=%dms high=%dms delay=%dms pkt=%s cs=%s bytes=%s",
            baud, break_low_ms, break_high_ms, post_break_ms,
            packet_label, cs_label,
            " ".join(f"{b:02X}" for b in packet),
        )

        # Read response -- consume echo first if present
        first = ser.read(1)
        if first and first[0] == packet[0]:
            # Looks like TX echo -- consume the rest of it
            if len(packet) > 1:
                ser.read(len(packet) - 1)
            logger.debug("RX echo consumed")
            first = ser.read(1)

        if first:
            rest = ser.read(MAX_RESPONSE_BYTES - 1)
            received = list(first) + list(rest)
            logger.debug("RX: %s", " ".join(f"{b:02X}" for b in received))
        else:
            logger.debug("RX: (timeout)")

        ser.close()

    except serial.SerialException as exc:
        notes = f"serial_error: {exc}"
        logger.warning("Serial error: %s", exc)

    sc = score_response(packet, received)

    return ProbeResult(
        timestamp=datetime.now().isoformat(timespec="milliseconds"),
        baud=baud,
        break_low_ms=break_low_ms,
        break_high_ms=break_high_ms,
        post_break_delay_ms=post_break_ms,
        packet_label=packet_label,
        checksum_type=cs_label,
        sent=packet,
        received=received,
        score=sc,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Main sweep
# ---------------------------------------------------------------------------

def run_bruteforce(
    port: str,
    output_path: Path,
    baud_list: list = None,
    break_low_list: list = None,
    break_high_list: list = None,
    post_break_list: list = None,
    packet_list: list = None,
    delay_between_s: float = 0.3,
    dry_run: bool = False,
) -> list:
    """
    Sweeps all parameter combinations. Writes every result to a JSONL file
    incrementally (one JSON object per line) so results survive crashes/Ctrl-C.
    Returns list of all ProbeResult objects sorted by score descending.
    """
    baud_list       = baud_list       or BAUD_CANDIDATES
    break_low_list  = break_low_list  or BREAK_LOW_CANDIDATES
    break_high_list = break_high_list or BREAK_HIGH_CANDIDATES
    post_break_list = post_break_list or POST_BREAK_DELAYS
    packet_list     = packet_list     or PACKET_CANDIDATES

    # Build full combination list
    combos = list(itertools.product(
        baud_list,
        break_low_list,
        break_high_list,
        post_break_list,
        packet_list,
        CHECKSUM_VARIANTS,
    ))

    total = len(combos)
    logger.info("Brute force sweep: %d combinations to try", total)
    logger.info("Results will be written incrementally to: %s", output_path)

    if dry_run:
        logger.info("Dry run — listing combinations only, not sending anything")
        for i, (baud, low, high, delay, (plabel, _), (cslabel, _)) in enumerate(combos, 1):
            print(f"  [{i:04d}/{total}] baud={baud} low={low}ms high={high}ms "
                  f"delay={delay}ms pkt={plabel} cs={cslabel}")
        return []

    results = []
    interesting = []

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "a") as log_f:
        for i, (baud, low, high, delay, (plabel, payload), (cslabel, cs_fn)) in enumerate(combos, 1):
            print(
                f"\r[{i:04d}/{total}] baud={baud} low={low}ms high={high}ms "
                f"delay={delay}ms pkt={plabel} cs={cslabel}   ",
                end="", flush=True,
            )

            result = _probe_one(
                port=port,
                baud=baud,
                break_low_ms=low,
                break_high_ms=high,
                post_break_ms=delay,
                packet_label=plabel,
                payload=payload[:],
                cs_label=cslabel,
                cs_fn=cs_fn,
            )

            results.append(result)

            # Write to JSONL immediately -- don't lose data on Ctrl-C
            log_f.write(json.dumps(asdict(result)) + "\n")
            log_f.flush()

            if result.score >= INTERESTING_SCORE_THRESHOLD:
                interesting.append(result)
                print(f"\n  *** INTERESTING (score={result.score}) "
                      f"rx={' '.join(f'{b:02X}' for b in result.received)} ***")

            time.sleep(delay_between_s)

    print()  # newline after progress line
    results.sort(key=lambda r: r.score, reverse=True)
    return results


def load_results(path: Path) -> list:
    """Load previously saved JSONL results for offline analysis."""
    results = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                d = json.loads(line)
                results.append(ProbeResult(**d))
    return sorted(results, key=lambda r: r.score, reverse=True)


def print_summary(results: list, top_n: int = 20) -> None:
    """Print a ranked summary of the most interesting probe results."""
    interesting = [r for r in results if r.score > 0]
    if not interesting:
        print("No responses observed in any combination. ECU silent or wiring issue.")
        return

    print(f"\n{'='*70}")
    print(f"SUMMARY — top {min(top_n, len(interesting))} results by score")
    print(f"{'='*70}")
    for r in interesting[:top_n]:
        sent_hex = " ".join(f"{b:02X}" for b in r.sent)
        recv_hex = " ".join(f"{b:02X}" for b in r.received) if r.received else "(none)"
        print(
            f"score={r.score:>3}  baud={r.baud}  "
            f"low={r.break_low_ms}ms  high={r.break_high_ms}ms  "
            f"delay={r.post_break_delay_ms}ms\n"
            f"         pkt={r.packet_label}  cs={r.checksum_type}\n"
            f"         sent: {sent_hex}\n"
            f"         recv: {recv_hex}\n"
        )
