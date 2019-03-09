# library imports
from scapy.all import conf

# system imports
import argparse

parser = argparse.ArgumentParser(description = "[Info] Captures network traffic and attempts to inject forged responses to poison the cache of a victim's resolver.")

def main():
    conf.sniff_promisc = True

    setup_args()

    args = parser.parse_args()
    run(args)

def setup_args():
    """ Sets up positional and optional arguments for command-line usage. """
    parser.add_argument('-i', metavar='interface', help='the network device to listen to')
    parser.add_argument('-f', metavar='hostnames', help='a list of IP addresses and hostname pairs specifying the hostnames to be hijacked')
    parser.add_argument('expression', help='a BPF filter that specifies a subset of the traffic to be monitored', nargs='?')

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

def run(args):
    print_run_msg(args)

if __name__ == '__main__':
    main()