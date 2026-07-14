"""
Honda Keihin K-Line ECU Reader & Prober — CLI (Simplified for K45A)
"""
import argparse
import logging
import sys
import time
import datetime
from pathlib import Path

import yaml

from .ecu_interface import (
    DTC, LIVE_DATA_TABLE, clear_faults, get_faults,
    open_connection, perform_handshake, query_table, read_vin,
)
from .parser import parse_parameters

logger = logging.getLogger("honda_reader")

def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f: return yaml.safe_load(f)

def _configure_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s.%(msecs)03d [%(name)s] %(message)s",
        datefmt="%H:%M:%S",
    )

def _fmt(data) -> str:
    if not data: return "(none)"
    return " ".join(f"{b:02X}" for b in data)

def _open_and_handshake(config: dict, port_override):
    conn = config.get("connection", {})
    port = port_override or conn.get("port", "/dev/ttyUSB0")
    baud = conn.get("baudrate", 10400)
    timeout = conn.get("timeout", 1.0)

    print(f"Connecting to {port} at {baud} baud...")
    ser = open_connection(port, baud, timeout)

    print("Performing Honda K45A handshake...")
    if not perform_handshake(ser):
        print("Handshake FAILED.")
        ser.close()
        return None
    print("Handshake OK. ECU is awake.")
    return ser

def run_live(config: dict, port_override, log_file=None):
    tables = config.get("tables", {})
    active_cfg = config.get("active_table", LIVE_DATA_TABLE)
    table_key = int(active_cfg, 0) if isinstance(active_cfg, str) else active_cfg
    table_cfg = tables.get(table_key, {})

    ser = _open_and_handshake(config, port_override)
    if not ser: return

    print(f"Streaming table 0x{table_key:02X}: {table_cfg.get('name', '')}")
    print("-" * 40)

    try:
        while True:
            resp = query_table(ser, table_key)
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")

            if resp is None:
                print("No response / checksum error")
            elif table_cfg:
                results = parse_parameters(bytes(resp), table_cfg)
                out_lines = [f"[{timestamp}]"]
                for name, info in results.items():
                    out_lines.append(f"  {name}: {info['value']:.2f} {info['unit']}")
                output = "\n".join(out_lines)
                print(output)
                if log_file:
                    log_file.write(output + "\n")
                    log_file.flush()
            else:
                raw = f"[{timestamp}] raw: {_fmt(resp)}"
                print(raw)
                if log_file:
                    log_file.write(raw + "\n")
                    log_file.flush()
            print("-" * 40)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nLive stream stopped.")
    finally:
        ser.close()

def run_read_vin(config: dict, port_override):
    ser = _open_and_handshake(config, port_override)
    if not ser: return
    resp = read_vin(ser)
    print(f"VIN raw bytes: {_fmt(resp) if resp else 'no response'}")
    ser.close()

def run_faults(config: dict, port_override):
    ser = _open_and_handshake(config, port_override)
    if not ser: return
    print("Reading fault codes...")
    faults = get_faults(ser)
    ser.close()
    for kind in ("current", "past"):
        codes = faults.get(kind, [])
        print(f"\n{kind.upper()} faults: {len(codes)}")
        for code in codes:
            print(f"  {code}: {DTC.get(code, 'Unknown code')}")

def run_clear_faults(config: dict, port_override, yes: bool):
    if not yes:
        confirm = input("This will clear all stored DTCs. Type 'yes' to continue: ")
        if confirm.strip().lower() != "yes":
            print("Cancelled."); return
    ser = _open_and_handshake(config, port_override)
    if not ser: return
    ok = clear_faults(ser)
    ser.close()
    print("Faults cleared." if ok else "Clear faults: no response / failed")

def main() -> None:
    parser = argparse.ArgumentParser(description="Honda Keihin K-Line ECU Reader")

    parser.add_argument("--k45a", action="store_true",
                        help="Start live telemetry for CBR150R K45A and auto-log to file")
    parser.add_argument("--port", help="Serial port (e.g. /dev/ttyUSB0)")
    parser.add_argument("--config", default=str(Path(__file__).parent / "config.yaml"))
    parser.add_argument("--debug", action="store_true", help="Log raw TX/RX bytes")

    sub = parser.add_subparsers(dest="command")
    sub.add_parser("live", help="Stream live telemetry")
    sub.add_parser("read-vin", help="Read VIN")
    sub.add_parser("faults", help="Read DTCs")
    p_clear = sub.add_parser("clear-faults", help="Clear DTCs")
    p_clear.add_argument("--yes", action="store_true")

    args = parser.parse_args()
    _configure_logging(args.debug)

    config = load_config(args.config)

    if args.k45a:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = f"telemetry_{timestamp}.log"
        print(f"Auto-logging telemetry to: {log_path}")
        with open(log_path, "a") as f:
            run_live(config, args.port, log_file=f)
        return

    if args.command == "live":
        run_live(config, args.port)
    elif args.command == "read-vin":
        run_read_vin(config, args.port)
    elif args.command == "faults":
        run_faults(config, args.port)
    elif args.command == "clear-faults":
        run_clear_faults(config, args.port, args.yes)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
