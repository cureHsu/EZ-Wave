#!/usr/bin/python

from scapy.all import *
from utils.ezutils import *
from argparse import ArgumentParser


if __name__ == "__main__":
    parser = ArgumentParser(sys.argv[0])
    parser.add_argument("-p", "--passive", action="store_true",
                        help="Conduct a passive scan for a set time (secs)")
    parser.add_argument("-t", "--timeout", type=int, default=60,
                        help="Timeout (secs) for scans, default=60")
    parser.add_argument("-a", "--active", action="store_true",
                        help="Conduct an active scan for a set time (secs)")
    parser.add_argument("--homeid", type=str, default=None,
                        help="4 byte HomeID to scan (ex: 0x1a2b3c4d)" )
    
    args = parser.parse_args(sys.argv[1:])

    seen = dict()

    if not args.passive and args.active:
        if args.homeid is None:
            sys.exit("Please provide a 4 byte HomeID to scan (ex: --homeid=0x1a2b3c4d)")

        homeid = int(args.homeid,16)
        seen[homeid] = ActiveScanner(ZWaveNetwork(homeid), args.timeout).run

    elif args.passive and not args.active:
        seen = PassiveScanner(args.timeout).run

    else:
        seen = PassiveScanner(args.timeout).run

        for homeid in seen:
            seen[homeid] = ActiveScanner(seen[homeid], args.timeout).run

    print("\n****************** Scan Results *********************\n")
    for homeid in seen:
        seen[homeid].display()
    print("*****************************************************\n")