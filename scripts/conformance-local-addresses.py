#!/usr/bin/env python3
"""Give the conformance container the routable addresses two Core tests need.

feature_bind_port_discover.py and feature_bind_port_externalip.py skip unless
1.1.1.1 (and, for the first, 2.2.2.2) are assigned to an interface of the
machine and the test is run with --ihave1111and2222 / --ihave1111: the nodes
bind 1.1.1.1 and discover both through getifaddrs. scripts/conformance.sh runs
this INSIDE the project container, started with --cap-add NET_ADMIN for those
two tests only, so the addresses exist in that container's own network
namespace and nowhere else -- not on the host, not in any other container.

Added as /32 aliases of eth0 (eth0:1, eth0:2) with SIOCSIFADDR and
SIOCSIFNETMASK: the image has no iproute2, and an alias of a non-loopback
interface is what Core's Discover (common/netif.cpp:367-381) reports.
"""
import fcntl
import socket
import struct

SIOCSIFADDR = 0x8916
SIOCSIFNETMASK = 0x891C


def set_alias(name, address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for request, value in ((SIOCSIFADDR, address), (SIOCSIFNETMASK, "255.255.255.255")):
        ifreq = struct.pack("16sH2s4s8s", name.encode(), socket.AF_INET, b"\0\0",
                            socket.inet_aton(value), b"\0" * 8)
        fcntl.ioctl(sock, request, ifreq)


set_alias("eth0:1", "1.1.1.1")
set_alias("eth0:2", "2.2.2.2")
print("conformance: 1.1.1.1 and 2.2.2.2 assigned to eth0 in this container")
