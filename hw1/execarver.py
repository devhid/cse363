# pylint: skip-file

import argparse
import binascii
import re
from scapy.all import sniff, TCP, IP, Raw, Padding, hexdump, Scapy_Exception

parser = argparse.ArgumentParser(description='[Info] A file extractor that will carve out Windows executables (PE) files from TCP traffic.')

def main():
    """ Entry point for the program where command-line arguments are processed. """
    setup_args()

    args = parser.parse_args()
    run(args)

def setup_args():
    """ Sets up positional and optional arguments for command-line usage. """
    parser.add_argument('-i', metavar='interface', help='the network device to listen to')
    parser.add_argument('-r', metavar='tracefile', help='read packets from the tracefile in tcpdump format')
    parser.add_argument('--strict', help='only extract PE files that have a PE signature at offset 0x3c', action='store_true')
    parser.add_argument('--exact', help='program will attempt to carve the exact number of bytes as original file', action='store_true')
    parser.add_argument('expression', help='a BPF filter that specifies a subset of the traffic to be monitored', nargs='?')

def validate_args(args):
    try:
        if args.r:
            open(args.r)
    except FileNotFoundError:
        print("Error: File '{file_name}' does not exist.".format(file_name=args.r))
        exit(1)

    try:
        if args.i and not args.r:
             sniff(iface=args.i, count=1)
    except OSError:
        print("Error: Interface, '{interface}' not found.".format(interface=args.i))
        exit(1)

    try:
        if args.expression:
            if args.i and not args.r:
                sniff(iface=args.i, count=1, filter=str.lower(args.expression))
            elif not args.r:
                sniff(count=1, filter=str.lower(args.expression))
    except Scapy_Exception:
        print("Error: BPF Filter, '{filter}' is invalid.".format(filter=args.expression))
        exit(1)

def run(args):
    validate_args(args)
    """ Sniffs TCP traffic, collects payloads and attempts to extract PE files from them. """
    print_run_msg(args)

    pkts = sniff(offline=args.r) if args.r else sniff(iface = args.i if args.i else 'eth0', filter=str.lower(args.expression) if args.expression else None)
    sessions = pkts.sessions()

    index = 0
    for session in sessions:
        payload = b''
        for packet in sessions[session]:
            try:
                if Padding not in packet and TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                    payload += packet[TCP].load
            except:
                pass

        if has_pe_file(payload, args.strict):
            extract_pe_file(payload, index, args.exact)
            index += 1

def has_pe_file(payload, strict):
    """ Checks if the payload contains a MZ signature and PE signature and has at least 97 bytes after the signature. """
    mz_index = payload.find(b'MZ')

    if mz_index != -1:
        # Get beginning of PE file.
        pe_file = payload[mz_index:]

        # Payload should at least be 97 bytes.
        if len(pe_file) < 97:
            print("Payload is less than 97 bytes.")
            return False

        # The offset for the PE signature is at memory location 0x3c or 60 in decimal.
        if strict:
            pe_offset = pe_file[60]
            has_pe_signature = pe_file[pe_offset:pe_offset + 4] == b'PE\x00\x00'
            return has_pe_signature
        
        return True
    
    # print("No MZ signature found.")
    return False

def get_file_size(payload): # Content-Length: 2961328\r\n
    headers = payload[:payload.find(b'MZ')]

    has_size = headers.find(b'Content-Length')
    if headers.find(b'Content-Length') == -1:
        return -1
    
    result = re.search(b"Content-Length: ([0-9]+)", headers)
    return result.groups()[0]

def extract_pe_file(payload, index, exact): # Need 746,592
    """ Extract the PE file from the packet payload, write it to a .exe file, and print its name and size."""
    start = payload.find(b'MZ')
    extracted = payload[start:]

    file_size = len(extracted)

    if exact:
        actual_size = int(get_file_size(payload))

        if actual_size != -1:
            file_size = actual_size
            extracted = extracted[:file_size]

    file_name = "file-{index}.exe".format(index=index) 
    with open(file_name, 'wb') as fd:
        fd.write(extracted)

    print("\nExtracted file, '{file_name}' with a size of {size} bytes.".format(file_name=file_name, size=file_size))

def print_run_msg(args):
    """ Print an appropriate run message based on the flags specified. """
    uses_interface = args.i and not args.r
    uses_tracefile = args.r
    uses_filter = args.expression and not args.r

    run_msg = "Listening on default interface, '{interface}'...".format(interface=args.i if uses_interface else 'eth0')
        
    if uses_filter:
        run_msg = run_msg[:-3] + " with filter, '{filter}'...".format(filter=args.expression)

    if uses_tracefile:
        run_msg = "Reading trace file, '{tracefile}'...".format(tracefile=args.r)

    print(run_msg)

if __name__ == '__main__':
    main()
