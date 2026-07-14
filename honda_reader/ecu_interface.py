"""
Honda Keihin K-Line ECU interface — Cleaned for CBR150R K45A
"""
import logging
import time
import serial

logger = logging.getLogger("honda_reader.ecu")

LIVE_DATA_TABLE = 0x11
VIN_TABLE = 0x00

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
    "18-01": "CMP sensor no signal",
    "19-01": "CKP sensor no signal",
    "21-01": "O2 sensor malfunction",
    "23-01": "O2 sensor heater malfunction",
    "29-01": "IACV circuit malfunction",
    "33-02": "ECM EEPROM malfunction",
    "51-01": "HESD linear solenoid malfunction",
    "54-01": "Bank angle sensor circuit low voltage",
    "54-02": "Bank angle sensor circuit high voltage",
    "86-01": "Serial communication malfunction",
}

def checksum(data: list) -> int:
    return (0x100 - (sum(data) & 0xFF)) & 0xFF

def message_is_valid(full_message: list) -> bool:
    return checksum(full_message) == 0

def format_message(mtype: list, data: list) -> list:
    ml = len(mtype)
    dl = len(data)
    msgsize = 2 + ml + dl
    msg = mtype + [msgsize] + data
    msg = msg + [checksum(msg)]
    return msg

def _hex(data) -> str:
    return " ".join(f"{b:02X}" for b in data) if data else "(none)"

def open_connection(port: str, baudrate: int, timeout: float) -> serial.Serial:
    return serial.Serial(
        port=port, baudrate=baudrate,
        bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE, timeout=timeout,
    )

def _read_exact(ser, n, deadline):
    buf = bytearray()
    while len(buf) < n and time.time() < deadline:
        chunk = ser.read(n - len(buf))
        if chunk: buf.extend(chunk)
    return bytes(buf) if len(buf) == n else None

def send_and_receive(ser, mtype, data, timeout=2.0, label=""):
    msg = format_message(mtype, data)
    ml = len(mtype)
    label = label or f"cmd_0x{mtype[0]:02X}"

    ser.reset_input_buffer()
    ser.reset_output_buffer()

    logger.debug("TX [%s]: %s", label, _hex(msg))
    ser.write(bytearray(msg))

    deadline = time.time() + timeout

    echo = _read_exact(ser, len(msg), deadline)
    if not echo: return None

    header = _read_exact(ser, ml + 1, deadline)
    if not header: return None

    length_byte = header[ml]
    remaining = length_byte - ml - 1
    if remaining <= 0: return None

    rest = _read_exact(ser, remaining, deadline)
    if not rest: return None

    full_response = list(header) + list(rest)
    logger.debug("RX [%s_resp]: %s", label, _hex(full_response))

    if not message_is_valid(full_response): return None
    return full_response[ml + 1:-1]

def _break_pulse(ser, low_ms=70.0, high_ms=130.0):
    # Bulletproof K-Line low pulse: spam 0x00 bytes to hold the line low.
    baud = ser.baudrate
    byte_time_ms = (10.0 / baud) * 1000.0
    num_bytes = int(low_ms / byte_time_ms)

    ser.write(b'\x00' * num_bytes)
    time.sleep(0.05)
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    time.sleep(high_ms / 1000.0)

def perform_handshake(ser):
    """Pure Honda K45A init sequence"""
    logger.debug("Break pulse: low=70ms high=130ms (0x00 spam)")
    _break_pulse(ser)

    # Ping
    ping_resp = send_and_receive(ser, [0xFE], [0x72], label="ping")
    if ping_resp is None:
        return False
    time.sleep(0.05)

    # Diag
    diag_resp = send_and_receive(ser, [0x72], [0x00, 0xF0], label="diag")
    if diag_resp is None:
        return False

    return True

def query_table(ser, table_id):
    return send_and_receive(ser, [0x72], [0x71, table_id], label=f"table_0x{table_id:02X}")

def read_vin(ser):
    return query_table(ser, VIN_TABLE)

def read_live_data(ser):
    return query_table(ser, LIVE_DATA_TABLE)

def get_faults(ser):
    faults = {"past": [], "current": []}
    for i in range(1, 0x0C):
        resp = send_and_receive(ser, [0x72], [0x74, i], label=f"dtc_current_{i}")
        if resp is None: break
        for j in (3, 5, 7):
            if j + 1 < len(resp) and resp[j] != 0:
                faults["current"].append(f"{resp[j]:02d}-{resp[j+1]:02d}")
        if len(resp) > 2 and resp[2] == 0: break

    for i in range(1, 0x0C):
        resp = send_and_receive(ser, [0x72], [0x73, i], label=f"dtc_past_{i}")
        if resp is None: break
        for j in (3, 5, 7):
            if j + 1 < len(resp) and resp[j] != 0:
                faults["past"].append(f"{resp[j]:02d}-{resp[j+1]:02d}")
        if len(resp) > 2 and resp[2] == 0: break

    return faults

def clear_faults(ser):
    resp = send_and_receive(ser, [0x72], [0x60, 0x01], label="clear_dtc")
    return resp is not None
