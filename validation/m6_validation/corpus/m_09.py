#!/usr/local/bin/python3
# SANDBOX_M4_YARA_TEST_MARKER
import socket
s=socket.socket()
s.settimeout(2)
try:
    s.connect(('8.8.8.8',53))
except Exception:
    pass
