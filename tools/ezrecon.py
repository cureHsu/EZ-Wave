#!/usr/bin/python

import os
from scapy.modules.gnuradio import *
from scapy.all import *
from scapy.layers.ZWave import *
from utils.ezutils import *
from argparse import ArgumentParser


def verify_checksum(packet):
    p = bytearray(str(packet))
    p = p[:-1]
    calc_crc = hex(reduce(lambda x, y: x ^ y, p, 0xFF))
    crc_byte = packet[ZWaveReq].get_field('crc').i2repr(packet, packet.crc)
    if calc_crc == crc_byte:
        return True
    else:
        return False


def handle_packets(packet, target):
    if packet.homeid == target.homeid and packet.src == target.nodeid:
        if verify_checksum(packet[ZWaveReq]):
            #packet[ZWaveReq].show()
            if packet.cmd_class == 0x72 and packet.cmd == 0x05:
                target.manspec = str(packet[Raw]).encode("HEX")
                target.parse_manspec()
                return
            elif packet.cmd_class == 0x86 and packet.cmd == 0x12:
                target.version = str(packet[Raw]).encode("HEX")
                return
            elif packet.cmd_class == 0x01:
                target.cmdclasses = str(packet[Raw])[6:].encode("HEX")
                return
            elif packet.cmd_class == 0x70 and packet.cmd == 0x06:
                target.configs[str(packet[Raw])[:2].encode("HEX")] = str(packet[Raw])[2:].encode("HEX")


if __name__ == "__main__":
    parser = ArgumentParser(sys.argv[0])
    parser.add_argument("homeid", type=str, help="4 byte HomeID of target network (ex: 0x1a2b3c4d)")
    parser.add_argument("nodeid", type=int, help="Target device NodeID (in decimal, <233)" )
    parser.add_argument("-c", "--config", action="store_true",
                        help="Include scan of device configuration settings (takes a while)")
    parser.add_argument("-t", "--timeout", type=int, default=30,
                        help="Stop scanning after a given time (secs, default=30)")

    args = parser.parse_args(sys.argv[1:])

    load_module('gnuradio')

    homeid = int(args.homeid,16)
    nodeid = args.nodeid
    _target = ZWaveNode(homeid, nodeid)

    print "Interrogating " + hex(homeid) + " Node " + str(nodeid)

    manspec = ZWave(homeid=homeid, dst=nodeid) / ZWaveManufacturerSpecific(cmd="GET")
    version = ZWave(homeid=homeid, dst=nodeid) / ZWaveVersion(cmd="GET")
    nif = ZWave(homeid=homeid, dst=nodeid) / ZWaveNodeInfo() / chr(2)
    if args.config:
        config = ZWave(homeid=homeid, ackreq=1, dst=nodeid) / ZWaveConfiguration(cmd="GET")
        _target.configs = dict()
    else:
        _target.configs = False

    timeout = args.timeout
    pid = os.fork()
    if pid > 0:
        timer = time.time()
        i = 0
        while time.time() - timer < timeout:
            for _ in range(0,3):
                send(manspec, verbose=False)
            time.sleep(2)
            for _ in range(0,3):
                send(version, verbose=False)
            time.sleep(2)
            for _ in range(0,3):
                send(nif, verbose=False)
            time.sleep(6)
        time.sleep(2)
        #os._exit(0)

    else:
        sniffradio(radio="Zwave", store=0, count=None, timeout=timeout,
                   prn=lambda p,t=_target: handle_packets(p,t),
                   lfilter=lambda x: x.haslayer(ZWaveReq))

        print "\n****************** Recon Results *********************\n"
        print "**************** Home ID: " + hex(homeid) + " *****************"
        _target.display(verbose=True)


    #print "Exit"