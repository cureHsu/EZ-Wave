#!/usr/bin/python

from scapy.all import *
from scapy.layers.ZWave import *
from scapy.modules.gnuradio import *
from utils.ezutils import *
from argparse import ArgumentParser

if __name__ == "__main__":
    parser = ArgumentParser(sys.argv[0])
    parser.add_argument("homeid", type=str, help="4 byte HomeID to scan (ex: 0x1a2b3c4d)")
    parser.add_argument("nodeid", type=int, help="Target device NodeID (in decimal)" )

    args = parser.parse_args(sys.argv[1:])

    homeid = int(args.homeid,16)
    print "Scanning " + str(args.nodeid) + " with standard preamble"
    network = ActiveScanner(ZWaveNetwork(homeid), timeout=10, nodeid=args.nodeid, strict=True).run

    if args.nodeid in network.nodes:
        print "Node " + str(args.nodeid) + " found"
        print "Scanning " + str(args.nodeid) + " with shortened preamble"
        network=None
        network = ActiveScanner(ZWaveNetwork(homeid), timeout=10, nodeid=args.nodeid, preamble_len=16, strict=True).run
        if args.nodeid in network.nodes:
            print hex(homeid) + " Node " + str(args.nodeid) + ": ZW0301 Transceiver"
        else:
            print hex(homeid) + " Node " + str(args.nodeid) + ": SD3501 Transceiver"
    else:
        print hex(homeid) + " Node " + str(args.nodeid) + " not found..."

    print "Exit"