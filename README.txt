Honda Keihin K-Line ECU Reader
==============================

A Python diagnostic tool for Honda small-displacement motorcycles
(Keihin ECUs, e.g. CBR150R K45A) over K-Line via FTDI FT232RL.

Supports three modes: Demo (simulated), Live (physical ECU), and Probe
(memory table discovery).


Requirements
------------
- Python 3.10+
- pyserial >= 3.5
- PyYAML >= 6.0

Install dependencies:

    pip install pyserial pyyaml


Project Structure
-----------------
honda_reader/
    __init__.py
    main.py           # CLI entrypoint
    ecu_interface.py  # Serial comm, handshake, packet assembly/checksum
    parser.py         # Safe formula evaluation & parameter decoding
    config.yaml       # Table definitions & connection settings


Usage
-----

Run from the project root directory:

    python -m honda_reader.main [options]


Modes (mutually exclusive):

  --demo
      Simulate live telemetry with random data (no hardware needed).
      Reads parameter definitions from config.yaml.

  --live
      Connect to a physical ECU via FTDI FT232RL.
      Performs K-Line Fast Init handshake, then streams decoded telemetry.

  --probe
      Fuzz all table IDs (0x00-0xFF) to discover active memory regions.
      Reports which tables respond and their payload lengths.


Options:

  --port PORT       Serial port (e.g. COM3, /dev/ttyUSB0).
                    Overrides config.yaml.

  --table TABLE     Table ID to query in live/demo mode (e.g. 0x11).
                    Overrides config.yaml active_table.

  --config PATH     Path to YAML config file (default: honda_reader/config.yaml).


Examples
--------

  # Demo mode (no hardware)
  python -m honda_reader.main --demo

  # Live mode with explicit port and table
  python -m honda_reader.main --live --port /dev/ttyUSB0 --table 0x11

  # Probe mode to discover active tables
  python -m honda_reader.main --probe --port /dev/ttyUSB0


Configuration (config.yaml)
----------------------------
connection:
  port: "COM3"           # Default serial port
  baudrate: 10400        # K-Line baud rate
  timeout: 1.0

active_table: 0x11       # Default table to query

tables:                  # Each table defines expected_length and a list
                         # of parameters with offset, length, endian, formula
  0x11:
    name: "Live Telemetry"
    expected_length: 24
    parameters:
      engine_rpm:
        offset: 4
        length: 2
        endian: "big"
        formula: "x"
        unit: "RPM"

Formulas support basic math (+, -, *, /) on variable x, evaluated via
safe AST parsing (no bare eval()).


Handshake Sequence
------------------
1. DTR LOW  for 25ms (pull K-Line low)
2. DTR HIGH for 25ms (release K-Line)
3. Send wakeup packet: 0x72 0x05 0x0F 0xF0 [CS]
4. Expect response:    0x02 0x04 0x0F 0xF0 [CS]

Checksum: 8-bit two's complement of all preceding bytes in the packet.


Probing Algorithm
-----------------
For each table ID 0x00...0xFF:
  - Build query packet [0x72, len, 0x71, table_id, CS]
  - Send at 10400 baud
  - No response / timeout -> INACTIVE
  - Valid response with matching checksum -> ACTIVE (log length)
