#!/usr/bin/env python3
"""An INDEPENDENT ZeroMQ subscriber for the publisher tests.

The point of this file is that it is not our code. A Lisp publisher checked
only by a Lisp subscriber proves that our implementation agrees with itself,
which is exactly the failure mode a wire protocol has. pyzmq speaks ZMTP
through libzmq's own client, so what it accepts is what real subscribers accept.

Usage: subscriber.py <address> <topic> [count]
Prints one line per message: "OK <topic> <body-hex> <sequence>", or "FAIL ...".
"""
import sys, zmq

addr = sys.argv[1]
topic = sys.argv[2].encode()
count = int(sys.argv[3]) if len(sys.argv) > 3 else 1

ctx = zmq.Context()
sock = ctx.socket(zmq.SUB)
sock.connect(addr)
sock.setsockopt(zmq.SUBSCRIBE, topic)
sock.RCVTIMEO = 20000
try:
    for _ in range(count):
        parts = sock.recv_multipart()
        print("OK", parts[0].decode(), parts[1].hex(),
              int.from_bytes(parts[2], "little"), flush=True)
except Exception as exc:
    print("FAIL", exc, flush=True)
