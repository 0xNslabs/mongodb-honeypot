# Simple MongoDB Honeypot Server

## Introduction
The Simple MongoDB Honeypot Server is a Python-based network monitoring tool designed to detect and analyze unauthorized access attempts to MongoDB databases. Built with the Twisted framework, this server emulates MongoDB protocol behavior while logging attacker activities and reconnaissance patterns. Ideal for security researchers and network administrators looking to study MongoDB-targeted threats.

## Features
- **MongoDB Protocol Emulation**: Realistic responses to `OP_MSG` and `OP_QUERY` operations
- **Comprehensive Logging**: Captures client metadata, authentication attempts, and full commands
- **Security Analytics**: Logs client applications, driver versions, and OS fingerprints
- **Configurable Deployment**: Adjustable listening host/port and MongoDB version presentation
- **Authentication Trap**: Captures SCRAM-SHA credentials and client nonces
- **Real-Time Monitoring**: Immediate visibility into MongoDB protocol interactions

## Requirements
- Python 3.9+
- Twisted framework
- pymongo package

## Installation
```bash
git clone https://github.com/0xNslabs/mongodb-honeypot.git
cd mongodb-honeypot
pip install twisted pymongo
```

## Usage
```bash
python3 mongodb.py [--host 0.0.0.0] [--port 27017] [--version "8.0.9"]
```

**Default Configuration**:

-   Binds to all interfaces (`0.0.0.0`)
-   Listens on standard MongoDB port  `27017`
-   Presents as MongoDB version  `8.0.9`
    

## Logging

Detailed JSON-formatted logs are written to  `mongodb_honeypot.log`, including:

-   Client IP addresses and connection timestamps
-   Client application metadata
-   Operating system fingerprints
-   Full command execution attempts
-   Authentication payloads and credentials
-   Database interaction patterns
    

## Simple MongoDB Honeypot In Action

![MongoDB Honeypot Detection Example](https://raw.githubusercontent.com/0xNslabs/mongodb-honeypot/main/PoC.png)  
_Example of the honeypot capturing authentication attempts and client fingerprinting_

## Other Simple Honeypot Services

Check out the other honeypot services for monitoring various network protocols:

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
- **Caution**: Operate this honeypot within secure, controlled settings for research and learning purposes.
- **Compliance**: Deploy this honeypot in accordance with local and international legal and ethical standards.

## License
This project is available under the MIT License. See the LICENSE file for more information.