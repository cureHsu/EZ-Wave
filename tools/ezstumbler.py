#!/usr/bin/python

from scapy.all import *
from utils.ezutils import *
from argparse import ArgumentParser

_seen = dict()

def passive_scan(timeout):
    global _seen
    _seen = PassiveScanner(timeout).run
    #scanner.display()

def active_scan(homeid):
    global _seen 
    _seen[homeid] = ActiveScanner(_seen[homeid]).run()


def display():
    global _seen
    print("\n****************** Scan Results *********************\n")
    for homeid in _seen:
        _seen[homeid].display()
    print("*****************************************************\n")

if __name__ == "__main__":
    parser = ArgumentParser(sys.argv[0])
    parser.add_argument("--passive", "-p", action="store_true",
                        help="Conduct passive scan")
    parser.add_argument("--timeout", "-t", type=int, default=20,
                        help="Stop sniffing after a given time (in seconds)")
    parser.add_argument("--active", "-a", action="store_true",
                        help="Conduct active scan")
    parser.add_argument("--homeid", type=str, default=None,
                        help="4 byte HomeID to scan (ex: 0x1a2b3c4d)" )
    
    args = parser.parse_args(sys.argv[1:])
    
    if not args.passive and args.active:
        if args.homeid is None:
            sys.exit("Please provide a 4 byte HomeID to scan (ex: --homeid=0x1a2b3c4d)")
        print args.homeid
        _seen[args.homeid] = ZWaveNetwork(args.homeid)
        active_scan(args.homeid)
    elif args.passive and not args.active:
        passive_scan(args.timeout)
    else:
        passive_scan(args.timeout)
        for homeid in _seen:
            print hex(homeid)
            #time.sleep(3)
            active_scan(homeid)

    display()