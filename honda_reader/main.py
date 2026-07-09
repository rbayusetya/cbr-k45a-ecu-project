"""
Honda Keihin K-Line ECU Reader & Prober -- CLI

Rewritten to match the confirmed-protocol ecu_interface.py. The old
exploratory commands (init-sweep, service-sweep, verify, diff-capture/
analyze, bruteforce/analyze) depended on functions that were intentionally
removed -- they were brute-force guessing tools for a protocol we no
longer need to guess at, now that we have a confirmed reference
(eculib/honda.py + the Scribd Honda Kline Command Protocol Guide).

Current commands:
    demo          - simulated data, no hardware needed
    handshake     - just run the handshake and report the result
    live          - stream a table continuously (default: confirmed live
                    data table 0x17)
    read-table    - one-shot read of a specific table ID
    read-vin      - one-shot VIN read (table 0x00)
    probe-known   - check only the 12 confirmed-valid table IDs
    probe-all     - full 0x00-0xFF sweep (slower, rarely needed now)
    faults        - read current/past DTCs with human-readable descriptions
    clear-faults  - clear DTCs (asks for confirmation)
    sniff         - passive listen, no transmission
"""

import argparse
import logging
import random
import sys
import time
from pathlib import Path

import yaml

from .ecu_interface import (
    DTC,
    InitMode,
    LIVE_DATA_TABLE,
    VIN_TABLE,
    clear_faults,
    get_faults,
    open_connection,
    perform_handshake,
    probe_known_tables,
    probe_tables,
    query_table,
    read_live_data,
    read_vin,
)
from .parser import parse_parameters

logger = logging.getLogger("honda_reader")


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def _normalize_table_key(key) -> int:
    if isinstance(key, str):
        return int(key, 0)
    return key


def _configure_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s.%(msecs)03d [%(name)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def _fmt(data) -> str:
    if not data:
        return "(none)"
    return " ".join(f"{b:02X}" for b in data)


def _print_handshake_result(result: dict) -> None:
    mode = result.get("mode", "?")
    if result.get("success"):
        print(f"[{mode}] Handshake OK.")
    else:
        print(f"[{mode}] Handshake FAILED -- reason: {result.get('reason')}")

    if "address_prestep_used" in result:
        print(f"    address_prestep_used: {result.get('address_prestep_used')}")
        print(f"    address_prestep_recv: {_fmt(result.get('address_prestep_recv'))}")
    if "ping_recv" in result:
        print(f"    ping_recv: {_fmt(result.get('ping_recv'))}")
    if "diag_recv" in result:
        print(f"    diag_recv: {_fmt(result.get('diag_recv'))}")
    if "captured" in result:
        print(f"    captured ({len(result.get('captured') or [])} bytes): {_fmt(result.get('captured'))}")


def _open_and_handshake(config: dict, port_override, init_mode: str,
                         no_prestep: bool = False, skip_wake: bool = False):
    conn = config.get("connection", {})
    port = port_override or conn.get("port", "COM3")
    baud = conn.get("baudrate", 10400)
    timeout = conn.get("timeout", 1.0)

    print(f"Connecting to {port} at {baud} baud...")
    ser = open_connection(port, baud, timeout)

    print(f"Performing handshake (mode={init_mode})...")
    kwargs = {}
    if InitMode(init_mode) == InitMode.TWO_PHASE:
        kwargs["do_address_prestep"] = not no_prestep
        kwargs["skip_wake"] = skip_wake

    result = perform_handshake(ser, mode=InitMode(init_mode), **kwargs)
    _print_handshake_result(result)

    if not result.get("success"):
        ser.close()
        return None
    return ser


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------

def run_demo(config: dict) -> None:
    tables = config.get("tables", {})
    active_key = _normalize_table_key(config.get("active_table", LIVE_DATA_TABLE))
    table_cfg = tables.get(active_key, {})

    print(f"Demo Mode -- Simulating table 0x{active_key:02X}: {table_cfg.get('name', '')}")
    print("-" * 40)

    try:
        while True:
            data = bytes(
                random.randint(0x00, 0xFF) for _ in range(table_cfg.get("expected_length", 24))
            )
            results = parse_parameters(data, table_cfg)
            for name, info in results.items():
                print(f"  {name}: {info['value']:.2f} {info['unit']}")
            print("-" * 40)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDemo stopped.")


# ---------------------------------------------------------------------------
# handshake
# ---------------------------------------------------------------------------

def run_handshake(config: dict, port_override, init_mode: str, no_prestep: bool, skip_wake: bool) -> None:
    ser = _open_and_handshake(config, port_override, init_mode, no_prestep, skip_wake)
    if ser:
        ser.close()


# ---------------------------------------------------------------------------
# live
# ---------------------------------------------------------------------------

def run_live(config: dict, port_override, table_override, init_mode: str,
             no_prestep: bool, skip_wake: bool) -> None:
    tables = config.get("tables", {})
    active_cfg = table_override or config.get("active_table", LIVE_DATA_TABLE)
    table_key = _normalize_table_key(active_cfg)
    table_cfg = tables.get(table_key, {})

    if not table_cfg:
        print(f"Warning: table 0x{table_key:02X} has no config entry -- "
              f"will print raw bytes instead of parsed values", file=sys.stderr)

    ser = _open_and_handshake(config, port_override, init_mode, no_prestep, skip_wake)
    if not ser:
        sys.exit(1)

    print(f"Streaming table 0x{table_key:02X}: {table_cfg.get('name', '')}")
    print("-" * 40)

    try:
        while True:
            resp = query_table(ser, table_key)
            if resp is None:
                print("No response / invalid table / checksum error")
            elif table_cfg:
                results = parse_parameters(bytes(resp), table_cfg)
                for name, info in results.items():
                    print(f"  {name}: {info['value']:.2f} {info['unit']}")
            else:
                print(f"  raw: {_fmt(resp)}")
            print("-" * 40)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nLive stream stopped.")
    finally:
        ser.close()


# ---------------------------------------------------------------------------
# read-table / read-vin
# ---------------------------------------------------------------------------

def run_read_table(config: dict, port_override, init_mode: str,
                    table_id_str: str, no_prestep: bool, skip_wake: bool) -> None:
    table_id = int(table_id_str, 0)

    ser = _open_and_handshake(config, port_override, init_mode, no_prestep, skip_wake)
    if not ser:
        sys.exit(1)

    resp = query_table(ser, table_id)
    if resp is None:
        print(f"Table 0x{table_id:02X}: no response / invalid / unsupported")
    else:
        print(f"Table 0x{table_id:02X}: {_fmt(resp)}")

    ser.close()


def run_read_vin(config: dict, port_override, init_mode: str, no_prestep: bool, skip_wake: bool) -> None:
    ser = _open_and_handshake(config, port_override, init_mode, no_prestep, skip_wake)
    if not ser:
        sys.exit(1)

    resp = read_vin(ser)
    if resp is None:
        print("VIN: no response")
    else:
        print(f"VIN raw bytes: {_fmt(resp)}")

    ser.close()


# ---------------------------------------------------------------------------
# probe-known / probe-all
# ---------------------------------------------------------------------------

def run_probe_known(config: dict, port_override, init_mode: str, no_prestep: bool, skip_wake: bool) -> None:
    ser = _open_and_handshake(config, port_override, init_mode, no_prestep, skip_wake)
    if not ser:
        sys.exit(1)

    print("Checking confirmed-valid table list...")
    print("-" * 40)
    results = probe_known_tables(ser)
    for table_id, info in results.items():
        status = info["status"]
        if status == "ACTIVE":
            print(f"  0x{table_id:02X}  ACTIVE  len={info['length']}  bytes={_fmt(info['raw_bytes'])}")
        else:
            print(f"  0x{table_id:02X}  {status}")

    ser.close()


def run_probe_all(config: dict, port_override, init_mode: str,
                   output_file: str, no_prestep: bool, skip_wake: bool) -> None:
    ser = _open_and_handshake(config, port_override, init_mode, no_prestep, skip_wake)
    if not ser:
        sys.exit(1)

    print("Probing full table ID range 0x00-0xFF...")
    print(f"Results written incrementally to: {output_file}")
    print("-" * 40)

    active_count = 0
    with open(output_file, "a") as f:
        import datetime
        f.write(f"\n=== Probe session {datetime.datetime.now().isoformat()} ===\n")
        f.flush()

        for table_id in range(0x00, 0x100):
            print(f"\r  Probing 0x{table_id:02X}...", end="", flush=True)
            try:
                resp = query_table(ser, table_id)
                if resp is not None:
                    active_count += 1
                    line = f"ACTIVE  0x{table_id:02X}  len={len(resp)}  bytes={_fmt(resp)}"
                    print(f"\n  *** {line}")
                    f.write(line + "\n")
                else:
                    f.write(f"INACTIVE  0x{table_id:02X}\n")
                f.flush()
            except Exception as exc:
                line = f"ERROR  0x{table_id:02X}  {exc}"
                f.write(line + "\n")
                f.flush()

        f.write(f"=== Done. Active tables: {active_count} ===\n")

    print(f"\nProbe complete. Active tables: {active_count}")
    print(f"Full results saved to: {output_file}")
    ser.close()


# ---------------------------------------------------------------------------
# faults / clear-faults
# ---------------------------------------------------------------------------

def run_faults(config: dict, port_override, init_mode: str, no_prestep: bool, skip_wake: bool) -> None:
    ser = _open_and_handshake(config, port_override, init_mode, no_prestep, skip_wake)
    if not ser:
        sys.exit(1)

    print("Reading fault codes...")
    faults = get_faults(ser)
    ser.close()

    for kind in ("current", "past"):
        codes = faults.get(kind, [])
        print(f"\n{kind.upper()} faults: {len(codes)}")
        for code in codes:
            desc = DTC.get(code, "Unknown code")
            print(f"  {code}: {desc}")


def run_clear_faults(config: dict, port_override, init_mode: str, no_prestep: bool,
                      yes: bool, skip_wake: bool = False) -> None:
    if not yes:
        confirm = input("This will clear all stored DTCs. Type 'yes' to continue: ")
        if confirm.strip().lower() != "yes":
            print("Cancelled.")
            return

    ser = _open_and_handshake(config, port_override, init_mode, no_prestep, skip_wake)
    if not ser:
        sys.exit(1)

    ok = clear_faults(ser)
    ser.close()
    print("Faults cleared." if ok else "Clear faults: no response / failed")


# ---------------------------------------------------------------------------
# sniff
# ---------------------------------------------------------------------------

def run_sniff(config: dict, port_override, duration: float) -> None:
    conn = config.get("connection", {})
    port = port_override or conn.get("port", "COM3")
    baud = conn.get("baudrate", 10400)
    timeout = conn.get("timeout", 1.0)

    print(f"Passively sniffing {port} at {baud} baud for {duration}s (no init sent)...")
    ser = open_connection(port, baud, timeout)
    result = perform_handshake(ser, mode=InitMode.PASSIVE_SNIFF, duration_s=duration)
    ser.close()
    _print_handshake_result(result)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Honda Keihin K-Line ECU Reader & Prober"
    )

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("demo", help="Simulated data, no hardware needed")

    p_hs = sub.add_parser("handshake", help="Run the handshake and report the result")
    p_hs.add_argument("--init-mode", choices=[m.value for m in InitMode if m != InitMode.PASSIVE_SNIFF],
                      default=InitMode.TWO_PHASE.value)
    p_hs.add_argument("--no-prestep", action="store_true",
                      help="Skip the empirical 0x33/0x31 address pre-step "
                           "(test whether it's actually still necessary)")
    p_hs.add_argument("--skip-wake", action="store_true",
                      help="Skip the unresponsive FE 04 72 8C wake packet, go straight to diag()")

    p_live = sub.add_parser("live", help="Stream a table continuously")
    p_live.add_argument("--table", help="Table ID override (default: confirmed live data table 0x17)")
    p_live.add_argument("--init-mode", choices=[m.value for m in InitMode if m != InitMode.PASSIVE_SNIFF],
                        default=InitMode.TWO_PHASE.value)
    p_live.add_argument("--no-prestep", action="store_true")
    p_live.add_argument("--skip-wake", action="store_true")

    p_rt = sub.add_parser("read-table", help="One-shot read of a specific table ID")
    p_rt.add_argument("table_id", help="Table ID, e.g. 0x17")
    p_rt.add_argument("--init-mode", choices=[m.value for m in InitMode if m != InitMode.PASSIVE_SNIFF],
                      default=InitMode.TWO_PHASE.value)
    p_rt.add_argument("--no-prestep", action="store_true")
    p_rt.add_argument("--skip-wake", action="store_true")

    p_vin = sub.add_parser("read-vin", help="One-shot VIN read (table 0x00)")
    p_vin.add_argument("--init-mode", choices=[m.value for m in InitMode if m != InitMode.PASSIVE_SNIFF],
                       default=InitMode.TWO_PHASE.value)
    p_vin.add_argument("--no-prestep", action="store_true")
    p_vin.add_argument("--skip-wake", action="store_true")

    p_pk = sub.add_parser("probe-known", help="Check only the 12 confirmed-valid table IDs")
    p_pk.add_argument("--init-mode", choices=[m.value for m in InitMode if m != InitMode.PASSIVE_SNIFF],
                      default=InitMode.TWO_PHASE.value)
    p_pk.add_argument("--no-prestep", action="store_true")
    p_pk.add_argument("--skip-wake", action="store_true")

    p_pa = sub.add_parser("probe-all", help="Full 0x00-0xFF table sweep")
    p_pa.add_argument("--init-mode", choices=[m.value for m in InitMode if m != InitMode.PASSIVE_SNIFF],
                      default=InitMode.TWO_PHASE.value)
    p_pa.add_argument("--output", default="probe_results.txt")
    p_pa.add_argument("--no-prestep", action="store_true")
    p_pa.add_argument("--skip-wake", action="store_true")

    p_faults = sub.add_parser("faults", help="Read current/past DTCs")
    p_faults.add_argument("--init-mode", choices=[m.value for m in InitMode if m != InitMode.PASSIVE_SNIFF],
                          default=InitMode.TWO_PHASE.value)
    p_faults.add_argument("--no-prestep", action="store_true")
    p_faults.add_argument("--skip-wake", action="store_true")

    p_clear = sub.add_parser("clear-faults", help="Clear DTCs (asks for confirmation)")
    p_clear.add_argument("--init-mode", choices=[m.value for m in InitMode if m != InitMode.PASSIVE_SNIFF],
                         default=InitMode.TWO_PHASE.value)
    p_clear.add_argument("--no-prestep", action="store_true")
    p_clear.add_argument("--skip-wake", action="store_true")
    p_clear.add_argument("--yes", action="store_true", help="Skip confirmation prompt")

    p_sniff = sub.add_parser("sniff", help="Passive listen, no init sent")
    p_sniff.add_argument("--duration", type=float, default=10.0)

    parser.add_argument("--port", help="Serial port (e.g. /dev/ttyUSB0)")
    parser.add_argument("--config", default=str(Path(__file__).parent / "config.yaml"))
    parser.add_argument("--debug", action="store_true",
                        help="Log raw TX/RX bytes (recommended)")

    args = parser.parse_args()
    _configure_logging(args.debug)

    if args.command in (None, "demo"):
        config = load_config(args.config)
        run_demo(config)
        return

    config = load_config(args.config)

    if args.command == "handshake":
        run_handshake(config, args.port, args.init_mode, args.no_prestep, args.skip_wake)
    elif args.command == "live":
        run_live(config, args.port, args.table, args.init_mode, args.no_prestep, args.skip_wake)
    elif args.command == "read-table":
        run_read_table(config, args.port, args.init_mode, args.table_id, args.no_prestep, args.skip_wake)
    elif args.command == "read-vin":
        run_read_vin(config, args.port, args.init_mode, args.no_prestep, args.skip_wake)
    elif args.command == "probe-known":
        run_probe_known(config, args.port, args.init_mode, args.no_prestep, args.skip_wake)
    elif args.command == "probe-all":
        run_probe_all(config, args.port, args.init_mode, args.output, args.no_prestep, args.skip_wake)
    elif args.command == "faults":
        run_faults(config, args.port, args.init_mode, args.no_prestep, args.skip_wake)
    elif args.command == "clear-faults":
        run_clear_faults(config, args.port, args.init_mode, args.no_prestep, args.yes, args.skip_wake)
    elif args.command == "sniff":
        run_sniff(config, args.port, args.duration)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
