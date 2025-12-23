import os
import argparse
import struct
import datetime
from twisted.internet import reactor, protocol
from twisted.python import log
from bson import BSON
from bson.binary import Binary

script_dir = os.path.dirname(os.path.abspath(__file__))


class SimpleMongoDBProtocol(protocol.Protocol):
    def __init__(self, version=None):
        self.buffer = b""
        self.client_ip = None
        self.client_port = None
        self.request_id = 0
        self.server_request_id = 0
        self.max_bson_size = 16 * 1024 * 1024
        self.max_message_size = 64 * 1024 * 1024
        self.version = version

    def connectionMade(self):
        peer = self.transport.getPeer()
        self.client_ip = peer.host
        self.client_port = peer.port
        log.msg(f"[CONN] {self.client_ip}:{self.client_port} - Connected")

    def dataReceived(self, data):
        self.buffer += data
        if len(self.buffer) > self.max_message_size * 2:
            self.transport.loseConnection()
            return

        while True:
            if len(self.buffer) < 16:
                break

            try:
                length, request_id, response_to, op_code = struct.unpack("<iiii", self.buffer[:16])
            except Exception:
                self.transport.loseConnection()
                return

            if length < 16 or length > self.max_message_size:
                self.transport.loseConnection()
                return

            if length > len(self.buffer):
                break

            full_msg = self.buffer[:length]
            self.buffer = self.buffer[length:]

            self._log_raw_message(full_msg, request_id, response_to, op_code)

            try:
                self.handleMessage(full_msg, request_id, op_code)
            except Exception as e:
                log.msg(f"Error handling message: {str(e)}")
                self.transport.loseConnection()
                return

    def _next_server_request_id(self):
        self.server_request_id = (self.server_request_id + 1) & 0x7fffffff
        if self.server_request_id == 0:
            self.server_request_id = 1
        return self.server_request_id

    def _log_raw_message(self, full_msg, request_id, response_to, op_code):
        try:
            max_dump = 4096
            chunk = full_msg[:max_dump]
            hex_data = chunk.hex()
            suffix = "" if len(full_msg) <= max_dump else f"...(truncated,{len(full_msg)}B)"
            log.msg(
                f"[RAW] {self.client_ip}:{self.client_port} op={op_code} request_id={request_id} response_to={response_to} len={len(full_msg)} data={hex_data}{suffix}"
            )
        except Exception:
            pass

    def handleMessage(self, full_msg, request_id, op_code):
        if op_code == 2013:
            self.handle_op_msg(full_msg, request_id)
            return
        if op_code == 2004:
            self.handle_op_query(full_msg, request_id)
            return
        self.transport.loseConnection()

    def _parse_bson_doc(self, bts, offset=0):
        if offset + 4 > len(bts):
            return None, offset
        dlen = struct.unpack("<i", bts[offset:offset + 4])[0]
        if dlen < 5 or offset + dlen > len(bts):
            return None, offset
        doc = BSON(bts[offset:offset + dlen]).decode()
        return doc, offset + dlen

    def handle_op_msg(self, full_msg, request_id):
        payload = full_msg[16:]
        if len(payload) < 5:
            self.send_op_msg_response(request_id, {"ok": 0, "errmsg": "Malformed OP_MSG", "code": 9, "codeName": "FailedToParse"})
            return

        try:
            _flags = struct.unpack("<I", payload[:4])[0]
            payload = payload[4:]

            body_doc = None

            while payload:
                kind = payload[0]
                payload = payload[1:]

                if kind == 0:
                    doc, new_off = self._parse_bson_doc(payload, 0)
                    if isinstance(doc, dict):
                        body_doc = doc
                    break

                if kind == 1:
                    if len(payload) < 4:
                        break
                    size = struct.unpack("<i", payload[:4])[0]
                    if size < 5 or size > len(payload):
                        break
                    block = payload[:size]
                    payload = payload[size:]

                    nul = block.find(b"\x00", 4)
                    if nul == -1:
                        continue
                    pos = nul + 1
                    while pos < len(block):
                        doc, pos2 = self._parse_bson_doc(block, pos)
                        if doc is None:
                            break
                        pos = pos2
                    continue

                break

            if not isinstance(body_doc, dict):
                self.send_op_msg_response(
                    request_id,
                    {"ok": 0, "errmsg": "Malformed OP_MSG", "code": 9, "codeName": "FailedToParse"},
                )
                return

            self.process_op_msg_body(body_doc, request_id)

        except Exception as e:
            response = {"ok": 0, "errmsg": str(e), "code": 13, "codeName": "Unauthorized"}
            self.send_op_msg_response(request_id, response)

    def process_op_msg_body(self, doc, request_id):
        cmd_name = next(iter(doc)) if doc else "unknown"
        self.log_command(doc, cmd_name)

        cmd_lc = str(cmd_name).lower()
        if cmd_lc in ("ismaster", "hello"):
            self.send_ismaster_response(request_id, requested_cmd=cmd_lc, is_op_msg=True)
            return
        if cmd_lc == "saslstart" or cmd_lc == "saslcontinue":
            self.handle_sasl_start(doc, request_id)
            return
        if cmd_lc == "ping":
            self.send_ping_response(request_id, is_op_msg=True)
            return
        if cmd_lc == "buildinfo":
            self.send_buildinfo_response(request_id, is_op_msg=True)
            return

        self.send_unauthorized(request_id, is_op_msg=True)

    def handle_op_query(self, full_msg, request_id):
        payload = full_msg[16:]
        try:
            if len(payload) < 4:
                self.transport.loseConnection()
                return

            _flags = struct.unpack("<i", payload[:4])[0]
            payload = payload[4:]

            nul = payload.find(b"\x00")
            if nul == -1:
                self.transport.loseConnection()
                return

            collection_name = payload[:nul].decode("utf-8", "replace")
            payload = payload[nul + 1:]

            if len(payload) < 8:
                self.transport.loseConnection()
                return

            _skip, _return_count = struct.unpack("<ii", payload[:8])
            payload = payload[8:]

            query_doc, off = self._parse_bson_doc(payload, 0)
            if not isinstance(query_doc, dict):
                self.send_unauthorized(request_id, is_op_msg=False)
                return

            if "$query" in query_doc and isinstance(query_doc.get("$query"), dict):
                base = query_doc.get("$query") or {}
                extras = {k: v for k, v in query_doc.items() if k != "$query"}
                merged = dict(base)
                merged.update(extras)
                query_doc = merged

            db_name = collection_name.split(".")[0] if "." in collection_name else collection_name
            if "$db" not in query_doc:
                query_doc["$db"] = db_name

            cmd_name = next(iter(query_doc)) if query_doc else "unknown"
            self.log_command(query_doc, cmd_name)

            cmd_lc = str(cmd_name).lower()
            if cmd_lc in ("ismaster", "hello"):
                self.send_ismaster_response(request_id, requested_cmd=cmd_lc, is_op_msg=False)
                return
            if cmd_lc == "ping":
                self.send_ping_response(request_id, is_op_msg=False)
                return
            if cmd_lc == "buildinfo":
                self.send_buildinfo_response(request_id, is_op_msg=False)
                return
            if cmd_lc == "saslstart" or cmd_lc == "saslcontinue":
                self.handle_sasl_start(query_doc, request_id)
                return

            self.send_unauthorized(request_id, is_op_msg=False)

        except Exception as e:
            log.msg(f"Error handling OP_QUERY: {str(e)}")
            self.send_unauthorized(request_id, is_op_msg=False)

    def log_command(self, doc, cmd_name):
        client = doc.get("client", {}) if isinstance(doc, dict) else {}
        app_info = client.get("application", {}) if isinstance(client, dict) else {}
        driver_info = client.get("driver", {}) if isinstance(client, dict) else {}
        os_info = client.get("os", {}) if isinstance(client, dict) else {}

        application_name = f"{app_info.get('name', '')} ({app_info.get('platform', '')}) | {driver_info.get('name', '')} {driver_info.get('version', '')}".strip(" |")
        os_str = f"{os_info.get('name', '')} {os_info.get('architecture', '')} {os_info.get('version', '')}".strip()

        log_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "client": f"{self.client_ip}:{self.client_port}",
            "application": application_name,
            "os": os_str,
            "database": doc.get("$db", "") if isinstance(doc, dict) else "",
            "command": cmd_name if cmd_name else "unknown",
        }
        log.msg(f"[CMD] {log_data}")

    def handle_sasl_start(self, doc, request_id):
        username = ""
        client_nonce = ""
        try:
            payload = doc.get("payload", b"") if isinstance(doc, dict) else b""
            if isinstance(payload, Binary):
                payload = bytes(payload)
            if isinstance(payload, (bytes, bytearray)) and payload:
                payload_str = payload.decode("utf-8", "ignore")
                parts = dict(p.split("=", 1) for p in payload_str.split(",") if "=" in p)
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
        self.send_auth_failure(request_id, is_op_msg=True)

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
        header = struct.pack("<iiii", total_length, self._next_server_request_id(), request_id, 1)
        return header + reply_body

    def create_error_response(self, message):
        return BSON.encode({"ok": 0, "errmsg": message, "code": 13, "codeName": "Unauthorized"})

    def send_op_reply_response(self, request_id, response_doc):
        try:
            reply = self.build_op_reply(request_id, response_doc)
            self.transport.write(reply)
        except Exception:
            pass

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
            header = struct.pack("<iiii", total_length, self._next_server_request_id(), request_id, 2013)
            self.transport.write(header + msg)
        except Exception as e:
            log.msg(f"Error sending OP_MSG response: {str(e)}")

    def _wire_version_from_version(self):
        try:
            major = int(str(self.version or "").split(".", 1)[0])
        except Exception:
            major = 5
        wv_map = {4: 9, 5: 13, 6: 17, 7: 21, 8: 25}
        return wv_map.get(major, 13)

    def send_ismaster_response(self, request_id, requested_cmd="ismaster", is_op_msg=True):
        max_wv = self._wire_version_from_version()
        response = {
            "ismaster": True,
            "isWritablePrimary": True,
            "minWireVersion": 0,
            "maxWireVersion": max_wv,
            "ok": 1.0,
            "localTime": datetime.datetime.utcnow(),
            "maxBsonObjectSize": self.max_bson_size,
            "maxMessageSizeBytes": self.max_message_size,
            "maxWriteBatchSize": 1000,
            "compression": ["none"],
            "saslSupportedMechs": ["SCRAM-SHA-1", "SCRAM-SHA-256"],
            "logicalSessionTimeoutMinutes": 30,
            "connectionId": 1,
        }
        if str(requested_cmd).lower() == "hello":
            response["helloOk"] = True

        if is_op_msg:
            self.send_op_msg_response(request_id, response)
        else:
            self.send_op_reply_response(request_id, response)

    def send_ping_response(self, request_id, is_op_msg=True):
        response = {"ok": 1.0, "ping": "pong"}
        if is_op_msg:
            self.send_op_msg_response(request_id, response)
        else:
            self.send_op_reply_response(request_id, response)

    def send_buildinfo_response(self, request_id, is_op_msg=True):
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
        if is_op_msg:
            self.send_op_msg_response(request_id, response)
        else:
            self.send_op_reply_response(request_id, response)

    def send_auth_failure(self, request_id, is_op_msg=True):
        response = {
            "ok": 0,
            "errmsg": "Authentication failed",
            "code": 18,
            "codeName": "AuthenticationFailed",
            "conversationId": 1,
            "done": True,
        }
        if is_op_msg:
            self.send_op_msg_response(request_id, response)
        else:
            self.send_op_reply_response(request_id, response)

    def send_unauthorized(self, request_id, is_op_msg=True):
        response = {"ok": 0, "errmsg": "Unauthorized", "code": 13, "codeName": "Unauthorized"}
        if is_op_msg:
            self.send_op_msg_response(request_id, response)
        else:
            self.send_op_reply_response(request_id, response)


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
