# SMS PDU Decoder (spd)

> [!WARNING]  
> AI Disclosure: This project started as my first real world test of "vibe coding" and how feasible it is for
> more obscure topics. While this may appear to do it's job on the first glance, I still need to extensively test and
> fact-check this code. There are still a lot of issues with it. This warning will be updated once that is done.

A command-line utility for decoding SMS Protocol Data Units (PDUs) written in C11. This tool parses and displays SMS PDU data in a human-readable format, supporting various SMS message types as defined in 3GPP TS 23.040.

## Features

- **Multiple PDU Types Support**: Handles SMS-DELIVER, SMS-SUBMIT, SMS-STATUS-REPORT, SMS-COMMAND, and related report types
- **Human-Readable Output**: Converts raw hex data into formatted, readable information
- **Comprehensive Field Parsing**:
  - TPDU Header analysis
  - TP-MMS (More Messages to Send) indication
  - Originating/Destination address formatting (E.164 and alphanumeric)
  - TP-PID (Protocol Identifier) decoding per TS 123.040
  - TP-DCS (Data Coding Scheme) display
  - TP-SCTS (Service Centre Time Stamp) with timezone
  - UDH (User Data Header) raw bytes
  - Message payload raw bytes
- **Standards Compliant**: Implements SMS PDU parsing according to GSM/3GPP specifications

## Usage

```bash
./spd --pdu <HEX_STRING>
```

### Example

```bash
./spd --pdu "0009D053F87BBC0600005280108141028015CCB4BD0C62BFDD6750D84D06C1E5EF39BC2C07"
```

### Sample Output

```
PDU Type: SMS-DELIVER
TPDU Header: 00
TP MMS (More Messages to Send): No more messages
Originating Address Length: 9
Type-of-Originating-Address: D0
Originating Address: Spock (raw: 53F87BBC06)
TP PID: 00 (Short Message Type 0 (default))
TP DCS: 00
TP SCTS: 2025-08-01 18:14:20 +0000 (raw: 52801081410280)
UDL: 21
Message Payload (raw): CCB4BD0C62BFDD6750D84D06C1E5EF39BC2C07
```

## Build Instructions

### Prerequisites

- C11 compatible compiler (GCC, Clang)
- CMake 3.31 or higher

### Building

```bash
# Clone the repository
git clone <repository-url>
cd spd

# Create build directory
mkdir build
cd build

# Configure and build
cmake ..
make

# Or using CMake directly
cmake --build .
```

The executable will be created as `spd` in the build directory.

## Limitations

- User Data is displayed as raw hex bytes (no text decoding)
- UDH content is not parsed (displayed as raw bytes)
- Limited to PDU parsing only (no encoding functionality)

## Contributing

Contributions are welcome! Please ensure:

- Code follows C11 standards
- No external dependencies beyond libc
- Maintain compatibility with existing API

## License

GPLv3

## Author

Lennart Rosam <hello@takuto.de>



