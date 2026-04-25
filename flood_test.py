#!/usr/bin/env python3
"""
IFIRE Flood Tester v2 — tests all detection modules.
Forces packets through eth0 via SO_BINDTODEVICE.
Usage: sudo python3 flood_test.py [target_ip] [interface]
"""

import socket, struct, random, time, sys, os, threading

TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.17.211"
IFACE  = sys.argv[2] if len(sys.argv) > 2 else "eth0"
SO_BINDTODEVICE = 25

# ── packet builders ────────────────────────────────────────────────────────────

def cksum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += data[i] + (data[i+1] << 8)
    if n: s += data[-1]
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def ip_hdr(src, dst, proto, payload):
    tot = 20 + len(payload)
    fid = random.randint(0, 65535)
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot, fid, 0, 64, proto, 0, s, d)
    c = cksum(h)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot, fid, 0, 64, proto, c, s, d)

def tcp_seg(src_ip, dst_ip, sport, dport, flags):
    seq = random.randint(0, 0xFFFFFFFF)
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 65535, 0, 0)
    pseudo = struct.pack("!4s4sBBH",
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
                         0, 6, len(seg))
    c = cksum(pseudo + seg)
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 65535, c, 0)

def icmp_echo(size=1200):
    hdr = struct.pack("!BBHHH", 8, 0, 0, random.randint(0,65535), random.randint(0,65535))
    pay = b'A' * size
    c   = cksum(hdr + pay)
    return struct.pack("!BBHHH", 8, 0, c, random.randint(0,65535), random.randint(0,65535)) + pay

def raw_sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, IFACE.encode() + b'\x00')
    return s

def rand_ip():
    return f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

def send_tcp(src, dport, flags, count, delay=0):
    s  = raw_sock()
    sp = random.randint(1024, 65535)
    for _ in range(count):
        seg = tcp_seg(src, TARGET, sp, dport, flags)
        pkt = ip_hdr(src, TARGET, 6, seg)
        s.sendto(pkt + seg, (TARGET, 0))
        if delay: time.sleep(delay)
    s.close()

# ── attacks ────────────────────────────────────────────────────────────────────

def syn_flood():
    src = rand_ip()
    print(f"[SYN FLOOD]    → port 80   | 500 SYNs from {src}")
    send_tcp(src, 80, 0x02, 500)
    print(f"  done")

def port_scan():
    src   = rand_ip()
    ports = random.sample(range(1, 65535), 25)
    print(f"[PORT SCAN]    → 25 ports  | SYNs from {src}")
    s  = raw_sock()
    sp = random.randint(1024, 65535)
    for dp in ports:
        seg = tcp_seg(src, TARGET, sp, dp, 0x02)
        pkt = ip_hdr(src, TARGET, 6, seg)
        s.sendto(pkt + seg, (TARGET, 0))
        time.sleep(0.05)
    s.close()
    print(f"  done")

def ping_flood():
    src = rand_ip()
    print(f"[PING FLOOD]   → 120×1200B | ICMP from {src}")
    s   = raw_sock()
    pkt_icmp = icmp_echo(1200)
    pkt_ip   = ip_hdr(src, TARGET, 1, pkt_icmp)
    for _ in range(120):
        s.sendto(pkt_ip + pkt_icmp, (TARGET, 0))
        time.sleep(0.04)
    s.close()
    print(f"  done")

def ssh_brute():
    src = rand_ip()
    print(f"[SSH BRUTE]    → port 22   | 15 SYNs from {src}")
    send_tcp(src, 22, 0x02, 15, delay=0.1)
    print(f"  done")

def rdp_brute():
    src = rand_ip()
    print(f"[RDP BRUTE]    → port 3389 | 8 SYNs from {src}")
    send_tcp(src, 3389, 0x02, 8, delay=0.1)
    print(f"  done")

def http_flood():
    src = rand_ip()
    print(f"[HTTP FLOOD]   → port 80   | 250 SYNs from {src}")
    send_tcp(src, 80, 0x02, 250)
    print(f"  done")

def null_scan():
    src = rand_ip()
    print(f"[NULL SCAN]    → port 443  | 5 pkts flags=0x00 from {src}")
    send_tcp(src, 443, 0x00, 5, delay=0.05)
    print(f"  done")

def fin_scan():
    src = rand_ip()
    print(f"[FIN SCAN]     → port 22   | 5 pkts flags=FIN from {src}")
    send_tcp(src, 22, 0x01, 5, delay=0.05)
    print(f"  done")

def xmas_scan():
    src = rand_ip()
    print(f"[XMAS SCAN]    → port 80   | 5 pkts flags=FIN+PSH+URG from {src}")
    send_tcp(src, 80, 0x29, 5, delay=0.05)  # FIN=0x01 PSH=0x08 URG=0x20
    print(f"  done")

# ── main ───────────────────────────────────────────────────────────────────────

ATTACKS = [
    syn_flood, port_scan, ping_flood,
    ssh_brute, rdp_brute, http_flood,
    null_scan, fin_scan,  xmas_scan,
]

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run as root:  sudo python3 flood_test.py [target] [iface]")
        sys.exit(1)

    print(f"\n  IFIRE Flood Tester v2")
    print(f"  target   : {TARGET}")
    print(f"  interface: {IFACE}")
    print(f"  attacks  : SYN-flood, Port-scan, Ping-flood, SSH-brute,")
    print(f"             RDP-brute, HTTP-flood, NULL-scan, FIN-scan, XMAS-scan")
    print(f"\n  Start IFIRE first:  sudo ./ifire -d {IFACE} -q")
    print()

    for i in range(3, 0, -1):
        print(f"  Starting in {i}...", end="\r", flush=True)
        time.sleep(1)
    print("  Launching all attacks now!\n")

    threads = [threading.Thread(target=fn) for fn in ATTACKS]
    for t in threads: t.start()
    for t in threads: t.join()

    print("\n  All done.")
    print("  Expected IFIRE alerts: SYN_FLOOD, PORT_SCAN, PING_FLOOD,")
    print("  SSH_BRUTE, RDP_BRUTE, HTTP_FLOOD, NULL_SCAN, FIN_SCAN, XMAS_SCAN")
