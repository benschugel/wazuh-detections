"""Minimal client for the wazuh-logtest socket.

Shared by run_cases.py and replay.py. Runs inside a manager container, where
/var/ossec/queue/sockets/logtest exists and the framework Python is available
as /var/ossec/framework/python/bin/python3.
"""
import json
import socket
import struct

SOCK = "/var/ossec/queue/sockets/logtest"


def ask(event, location="guard", token=None, sock=SOCK, origin="wazuh-detections"):
    """Send one event through wazuh-logtest and return the matched rule.

    event: a dict (sent as JSON) or a raw log line.
    token: pass the token from a previous call to keep frequency state
           between events of the same session.
    Returns {"token", "id", "level", "description", "messages", "output"}.
    The id is "none" and the level 0 when no rule matched.
    """
    if not isinstance(event, str):
        event = json.dumps(event)
    params = {"event": event, "log_format": "syslog", "location": location}
    if token:
        params["token"] = token
    payload = json.dumps({"version": 1, "origin": {"name": origin, "module": origin},
                          "command": "log_processing", "parameters": params}).encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock)
    s.sendall(struct.pack("<I", len(payload)) + payload)
    hdr = b""
    while len(hdr) < 4:
        chunk = s.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError("logtest closed the connection before the header")
        hdr += chunk
    size, buf = struct.unpack("<I", hdr)[0], b""
    while len(buf) < size:
        chunk = s.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("logtest closed the connection before the body")
        buf += chunk
    s.close()
    data = json.loads(buf.decode(errors="replace").rstrip("\x00")).get("data", {})
    output = data.get("output", {})
    rule = output.get("rule", {})
    return {"token": data.get("token", token), "id": rule.get("id", "none"), "level": rule.get("level", 0),
            "description": rule.get("description", ""), "messages": data.get("messages", []), "output": output}
