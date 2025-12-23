# Simple MongoDB Honeypot Server

## Introduction
The Simple MongoDB Honeypot Server is a Python-based monitoring tool designed to detect and analyze unauthorized MongoDB access attempts. Built on Twisted, it emulates key parts of the MongoDB wire protocol (OP_MSG / OP_QUERY) and logs attacker reconnaissance and authentication activity.

## Features
- **MongoDB Wire Protocol Emulation**
  - Parses and responds to **OP_MSG (2013)** and **OP_QUERY (2004)**.
  - Supports modern handshake commands: `hello` / `ismaster`.
  - Replies in both **OP_MSG** and legacy **OP_REPLY** formats depending on client behavior.

- **Comprehensive Logging (kept compatible with existing logs)**
  - Connection events (`[CONN]`)
  - Command/metadata extraction (`[CMD]`)
  - Authentication attempt capture (`[AUTH]`)

- **Raw Payload Telemetry (for zero-day / fuzzing visibility)**
  - Logs **raw inbound wire bytes** as hex (`[RAW]`) with message metadata (opCode, requestId, responseTo, length).
  - Payload dumps are truncated to the first **4096 bytes** to keep logs manageable.

- **Safer Protocol Handling**
  - Strict message framing and size validation to avoid memory blowups.
  - Rejects malformed messages (invalid header or impossible lengths).

- **Configurable Deployment**
  - Bind host/port and advertised MongoDB version.

## Requirements
- Python 3.9+
- Twisted
- pymongo (provides `bson`)

## Installation
```bash
git clone https://github.com/0xNslabs/mongodb-honeypot.git
cd mongodb-honeypot
pip install twisted pymongo
```

## Usage
```bash
python3 mongodb.py --host 0.0.0.0 --port 27017 --version "8.0.9"
```

### Default Configuration
- Binds to all interfaces (`0.0.0.0`)
- Listens on MongoDB default port (`27017`)
- Presents as MongoDB version `8.0.9`

## Logging
Logs are written to `mongodb_honeypot.log`.

### Log Types
- **`[CONN]`**: Connection events (client IP/port)
- **`[CMD]`**: Parsed command and client metadata (application/driver/OS) in a JSON-like dict
- **`[AUTH]`**: SASL/SCRAM authentication attempt capture (username + client nonce when present)
- **`[RAW]`**: Raw inbound MongoDB wire message dump (hex), truncated to 4096 bytes

## Simple MongoDB Honeypot In Action
![MongoDB Honeypot Detection Example](https://raw.githubusercontent.com/0xNslabs/mongodb-honeypot/refs/heads/master/PoC.png)  
_Example of the honeypot capturing authentication attempts and client fingerprinting_

## Other Simple Honeypot Services
- [DNS Honeypot](https://github.com/0xNslabs/dns-honeypot) - Monitors DNS interactions.
- [FTP Honeypot](https://github.com/0xNslabs/ftp-honeypot) - Simulates an FTP server.
- [LDAP Honeypot](https://github.com/0xNslabs/ldap-honeypot) - Mimics an LDAP server.
- [HTTP Honeypot](https://github.com/0xNslabs/http-honeypot) - Monitors HTTP interactions.
- [HTTPS Honeypot](https://github.com/0xNslabs/https-honeypot) - Monitors HTTPS interactions.
- [MongoDB Honeypot](https://github.com/0xNslabs/mongodb-honeypot) - Simulates a MongoDB database server.
- [NTP Honeypot](https://github.com/0xNslabs/ntp-honeypot) - Monitors Network Time Protocol interactions.
- [PostgreSQL Honeypot](https://github.com/0xNslabs/postgresql-honeypot) - Simulates a PostgreSQL database server.
- [SIP Honeypot](https://github.com/0xNslabs/sip-honeypot) - Monitors SIP (Session Initiation Protocol) interactions.
- [SSH Honeypot](https://github.com/0xNslabs/ssh-honeypot) - Emulates an SSH server.
- [TELNET Honeypot](https://github.com/0xNslabs/telnet-honeypot) - Simulates a TELNET server.

## Security and Compliance
- **Caution**: Deploy only in controlled environments. Avoid exposing it directly to the public internet without proper containment and monitoring.
- **Compliance**: Ensure your use complies with local laws, organizational policy, and ethical guidelines.

## License
This project is available under the MIT License. See the `LICENSE` file for more information.
