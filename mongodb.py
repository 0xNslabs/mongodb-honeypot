import os
import argparse
import struct
import datetime
from twisted.internet import reactor, protocol
from twisted.python import log
from bson import BSON

script_dir = os.path.dirname(os.path.abspath(__file__))

class SimpleMongoDBProtocol(protocol.Protocol):
    def __init__(self, version=None):
        self.buffer = b""
        self.client_ip = None
        self.client_port = None
        self.request_id = 0
        self.max_bson_size = 16 * 1024 * 1024
        self.version = version

    def connectionMade(self):
        peer = self.transport.getPeer()
        self.client_ip = peer.host
        self.client_port = peer.port
        log.msg(f"[CONN] {self.client_ip}:{self.client_port} - Connected")

    def dataReceived(self, data):
        self.buffer += data
        while True:
            if len(self.buffer) < 16:
                break
            length, request_id, response_to, op_code = struct.unpack(
                "<iiii", self.buffer[:16]
            )
            if length > len(self.buffer):
                break

            full_msg = self.buffer[:length]
            self.buffer = self.buffer[length:]

            self.handleMessage(full_msg, request_id, op_code)

    def handleMessage(self, full_msg, request_id, op_code):
        try:
            if op_code == 2013:
                self.handle_op_msg(full_msg, request_id)
            elif op_code == 2004:
                self.handle_op_query(full_msg, request_id)
            else:
                self.transport.loseConnection()

        except Exception as e:
            log.msg(f"Error handling message: {str(e)}")
            self.transport.loseConnection()

    def handle_op_msg(self, full_msg, request_id):
        payload = full_msg[16:]
        try:
            flags = struct.unpack("<I", payload[:4])[0]
            payload = payload[4:]

            sections = []
            while payload:
                kind = payload[0]
                payload = payload[1:]

                if kind == 0:
                    doc, end = BSON(payload).decode(), len(BSON(payload))
                    sections.append(("body", doc))
                    payload = payload[end:]
                elif kind == 1:
                    size = struct.unpack("<i", payload[:4])[0]
                    identifier = payload[4 : payload.find(b"\x00")]
                    docs = []
                    pos = 4 + len(identifier) + 1
                    while pos < size:
                        doc, end = BSON(payload[pos:]).decode(), len(
                            BSON(payload[pos:])
                        )
                        docs.append(doc)
                        pos += end
                    sections.append(("sequence", identifier.decode(), docs))
                    payload = payload[size:]
                else:
                    break

            for section in sections:
                if section[0] == "body":
                    self.process_op_msg_body(section[1], request_id)

        except Exception as e:
            response = {
                "ok": 0,
                "errmsg": str(e),
                "code": 13,
                "codeName": "Unauthorized",
            }
            self.send_op_msg_response(request_id, response)

    def process_op_msg_body(self, doc, request_id):
        cmd_name = next(iter(doc)) if doc else "unknown"
        db = doc.get("$db", "")
        self.log_command(doc, cmd_name)
        if cmd_name == "ismaster":
            self.send_ismaster_response(request_id)
        elif cmd_name == "saslStart":
            self.handle_sasl_start(doc, request_id)
        elif cmd_name == "ping":
            self.send_ping_response(request_id)
        elif cmd_name == "buildInfo":
            self.send_buildinfo_response(request_id)
        else:
            self.send_unauthorized(request_id)

    def handle_op_query(self, full_msg, request_id):
        payload = full_msg[16:]
        try:
            flags = struct.unpack("<i", payload[:4])[0]
            payload = payload[4:]

            collection_name, _, payload = payload.partition(b"\x00")
            collection_name = collection_name.decode()
            db_name = collection_name.split(".")[0]

            skip = struct.unpack("<i", payload[:4])[0]
            return_count = struct.unpack("<i", payload[4:8])[0]
            query = BSON(payload[8:]).decode()

            cmd_name = next(iter(query)) if query else "unknown"

            self.log_command(query, cmd_name)

            if cmd_name == "ismaster" or cmd_name == "hello":
                self.send_ismaster_response(request_id)
            elif cmd_name == "ping":
                self.send_ping_response(request_id)
            elif cmd_name == "buildInfo":
                self.send_buildinfo_response(request_id)
            else:
                self.send_unauthorized(request_id)
        except Exception as e:
            log.msg(f"Error handling OP_QUERY: {str(e)}")
            self.send_unauthorized(request_id)

    def log_command(self, doc, cmd_name):
        client = doc.get("client", {})
        app_info = client.get("application", {})
        driver_info = client.get("driver", {})
        os_info = client.get("os", {})
        application_name = f"{app_info.get('name', '')} ({app_info.get('platform', '')}) | {driver_info.get('name', '')} {driver_info.get('version', '')}".strip(
            " |"
        )
        os_str = f"{os_info.get('name', '')} {os_info.get('architecture', '')} {os_info.get('version', '')}".strip()

        log_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "client": f"{self.client_ip}:{self.client_port}",
            "application": application_name,
            "os": os_str,
            "database": doc.get("$db", ""),
            "command": cmd_name if cmd_name else "unknown",
        }
        log.msg(f"[CMD] {log_data}")

    def handle_sasl_start(self, doc, request_id):
        username = ""
        client_nonce = ""
        try:
            payload = doc.get("payload", b"")
            if payload:
                payload_str = payload.decode("utf-8", "ignore")
                parts = dict(
                    p.split("=", 1) for p in payload_str.split(",") if "=" in p
                )
                username = parts.get("n", "")
                client_nonce = parts.get("r", "")

        except Exception as e:
            log.msg(f"Error parsing SASL payload: {str(e)}")

        log_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "client": f"{self.client_ip}:{self.client_port}",
            "username": username,
            "client_nonce": client_nonce,
            "status": "auth_attempt",
        }
        log.msg(f"[AUTH] {log_data}")
        self.send_auth_failure(request_id)

    def build_op_reply(self, request_id, response_doc):
        response_payload = BSON.encode(response_doc)

        if len(response_payload) > self.max_bson_size:
            response_payload = self.create_error_response("BSON size too large")

        response_flags = 0
        cursor_id = 0
        starting_from = 0
        number_returned = 1

        reply_body = struct.pack("<i", response_flags)
        reply_body += struct.pack("<q", cursor_id)
        reply_body += struct.pack("<i", starting_from)
        reply_body += struct.pack("<i", number_returned)
        reply_body += response_payload

        total_length = 16 + len(reply_body)
        header = struct.pack("<iiii", total_length, 0, request_id, 1)

        return header + reply_body

    def create_error_response(self, message):
        return BSON.encode(
            {"ok": 0, "errmsg": message, "code": 13, "codeName": "Unauthorized"}
        )

    def send_op_msg_response(self, request_id, response_doc):
        try:
            payload = BSON.encode(response_doc)
            if len(payload) > self.max_bson_size:
                payload = self.create_error_response("Response too large")

            flags = 0
            msg = struct.pack("<I", flags)
            msg += b"\x00"
            msg += payload

            total_length = 16 + len(msg)
            header = struct.pack("<iiii", total_length, 0, request_id, 2013)

            self.transport.write(header + msg)
        except Exception as e:
            log.msg(f"Error sending OP_MSG response: {str(e)}")

    def send_ismaster_response(self, request_id):
        response = {
            "ismaster": True,
            "maxWireVersion": 13,
            "minWireVersion": 0,
            "ok": 1.0,
            "localTime": datetime.datetime.utcnow(),
            "maxBsonObjectSize": self.max_bson_size,
            "maxMessageSizeBytes": self.max_bson_size,
            "maxWriteBatchSize": 1000,
            "compression": ["none"],
            "saslSupportedMechs": ["SCRAM-SHA-1", "SCRAM-SHA-256"],
        }
        self.send_op_msg_response(request_id, response)

    def send_ping_response(self, request_id):
        response = {"ok": 1.0, "ping": "pong"}
        self.send_op_msg_response(request_id, response)

    def send_buildinfo_response(self, request_id):
        response = {
            "storageEngines": ["devnull", "wiredTiger"],
            "buildEnvironment": {
                "distarch": "x86_64",
                "cc": "/opt/mongodbtoolchain/v4/bin/gcc: gcc (GCC) 11.3.0",
                "cppdefines": "SAFEINT_USE_INTRINSICS 0 PCRE2_STATIC NDEBUG _XOPEN_SOURCE 700 _GNU_SOURCE _FORTIFY_SOURCE 2 ABSL_FORCE_ALIGNED_ACCESS BOOST_ENABLE_ASSERT_DEBUG_HANDLER BOOST_FILESYSTEM_NO_CXX20_ATOMIC_REF BOOST_LOG_NO_SHORTHAND_NAMES BOOST_LOG_USE_NATIVE_SYSLOG BOOST_LOG_WITHOUT_THREAD_ATTR BOOST_MATH_NO_LONG_DOUBLE_MATH_FUNCTIONS BOOST_SYSTEM_NO_DEPRECATED BOOST_THREAD_USES_DATETIME BOOST_THREAD_VERSION 5",
                "cxxflags": "-Woverloaded-virtual -Wpessimizing-move -Wno-maybe-uninitialized -fsized-deallocation -Wno-deprecated -std=c++20",
                "linkflags": "-Wl,--fatal-warnings -B/opt/mongodbtoolchain/v4/bin -gdwarf-5 -pthread -Wl,-z,now -fuse-ld=lld -fstack-protector-strong -gdwarf64 -Wl,--build-id -Wl,--hash-style=gnu -Wl,-z,noexecstack -Wl,--warn-execstack -Wl,-z,relro -Wl,--compress-debug-sections=none -Wl,-z,origin -Wl,--enable-new-dtags",
                "ccflags": "-Werror -include mongo/platform/basic.h -ffp-contract=off -fasynchronous-unwind-tables -g2 -Wall -Wsign-compare -Wno-unknown-pragmas -Winvalid-pch -gdwarf-5 -fno-omit-frame-pointer -fno-strict-aliasing -O2 -march=sandybridge -mtune=generic -mprefer-vector-width=128 -Wno-unused-local-typedefs -Wno-unused-function -Wno-deprecated-declarations -Wno-unused-const-variable -Wno-unused-but-set-variable -Wno-missing-braces -fstack-protector-strong -gdwarf64 -Wa,--nocompress-debug-sections -fno-builtin-memcmp -Wimplicit-fallthrough=5",
                "target_arch": "x86_64",
                "distmod": "ubuntu2204",
                "target_os": "linux",
                "cxx": "/opt/mongodbtoolchain/v4/bin/g++: g++ (GCC) 11.3.0",
            },
            "ok": 1.0,
            "sysInfo": "deprecated",
            "modules": [],
            "openssl": {
                "compiled": "OpenSSL 3.0.2 15 Mar 2022",
                "running": "OpenSSL 3.0.2 15 Mar 2022",
            },
            "javascriptEngine": "mozjs",
            "version": self.version,
            "allocator": "tcmalloc",
            "debug": "false",
            "maxBsonObjectSize": 16777216,
            "bits": 64,
            "gitVersion": "cf29fc744f8ee2ac9245f2845f29c6a706dc375a",
        }
        self.send_op_msg_response(request_id, response)

    def send_auth_failure(self, request_id):
        response = {
            "ok": 0,
            "errmsg": "Authentication failed",
            "code": 18,
            "codeName": "AuthenticationFailed",
            "conversationId": 1,
            "done": True,
        }
        self.send_op_msg_response(request_id, response)

    def send_unauthorized(self, request_id):
        response = {
            "ok": 0,
            "errmsg": "Unauthorized",
            "code": 13,
            "codeName": "Unauthorized",
        }
        self.send_op_msg_response(request_id, response)


class SimpleMongoFactory(protocol.Factory):
    def __init__(self, version=None):
        self.version = version

    def buildProtocol(self, addr):
        return SimpleMongoDBProtocol(self.version)


def main():
    parser = argparse.ArgumentParser(description="Simple MongoDB Honeypot")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind")
    parser.add_argument("--port", type=int, default=27017, help="Port to bind")
    parser.add_argument("--version", default="8.0.9", help="MongoDB version")
    args = parser.parse_args()

    log_file = os.path.join(script_dir, "mongodb_honeypot.log")
    log_observer = log.FileLogObserver(open(log_file, "a"))
    log.startLoggingWithObserver(log_observer.emit, setStdout=False)

    print(f"MongoDB Honeypot active on {args.host}:{args.port}")
    print(f"Logging to: {log_file}")

    reactor.listenTCP(args.port, SimpleMongoFactory(args.version), interface=args.host)
    reactor.run()


if __name__ == "__main__":
    main()
