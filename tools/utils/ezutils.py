from scapy.all import *
from scapy.layers.ZWave import *
from scapy.modules.gnuradio import *
import xml.etree.ElementTree as ET
from urllib import urlopen

_COMMAND_CLASS = {0: "NoOperation", 1:"Zwave", 32:"Basic", 33:"ControllerReplication", 34:"ApplicationStatus",
                  35:"ZipServices", 36:"ZipServer", 37:"SwitchBinary", 38:"SwitchMultilevel", 39:"SwitchAll",
                  40:"SwitchToggleBinary", 41:"SwitchToggleMultilevel", 43:"SceneActivation", 44:"SceneActuatorConf",
                  45:"SceneControllerConf", 48:"SensorBinary", 49:"SensorMultilevel", 50:"Meter", 51:"Color",
                  52:"MeterPulse", 61:"MeterTableMonitor", 64:"ThermostatMode", 66:"ThermostatOperatingState",
                  67:"ThermostatSetPoint", 68:"ThermostatFanMode", 69:"ThermostatFanState", 70:"ClimateControlSchedule",
                  76:"DoorLockLogging", 78:"ScheduleEntryLock", 79:"6lowpan", 80:"BasicWindowCovering",
                  85:"TransportService", 86:"CRCEncap", 90:"DeviceResetLocally", 91:"CentralScene", 94:"ZWavePlusInfo",
                  96:"MultiChannel", 98:"DoorLock", 99:"UserCode", 112:"Configuration", 113:"Alarm",
                  114:"ManufacturerSpecific", 115:"PowerLevel", 117:"Protection", 118:"Lock", 119:"NodeNaming",
                  122:"FirmwareUpdate", 123:"GroupNaming", 124:"RemoteAssociationActivate", 125:"RemoteAssociation",
                  128:"Battery", 129:"Clock", 130:"Hail", 132:"WakeUp", 133:"Association", 134:"Version",
                  135:"Indicator", 136:"Proprietary", 137:"Language", 138:"Time", 139:"TimeParameters",
                  140:"GeographicLocation", 142:"MultiChannelAssociation", 143:"MultiCmd", 144:"EnergyProduction",
                  145:"ManufacturerProprietary", 146:"Screen", 147:"ScreenAttributes", 148:"SimpleAvControl",
                  152:"Security", 154:"IpConfiguration", 155:"AssociationCommandConfiguration", 156:"SensorAlarm",
                  157:"SilenceAlarm", 158:"SensorConfiguration", 239:"Mark"}

class ZWaveNode(object):
    def __init__(self, homeid, nodeid):
        self.homeid = homeid
        self.nodeid = nodeid
        self.manspec = None
        self.cmdclasses = None
        self.version = None
        self.basic = None
        self.configs = None


    def parse_manspec(self):
        response = None
        if self.manspec is None:
            response = "\tManufacturer: Unknown \n\tProduct Name: Unknown "
        else:
            tree = ET.parse(urlopen('https://raw.githubusercontent.com/OpenZWave/open-zwave/master/config/manufacturer_specific.xml'))
            root = tree.getroot()
            xmlns="{http://code.google.com/p/open-zwave/}"
            for manufacturer in root.iter(xmlns+'Manufacturer'):
                if manufacturer.get("id") == self.manspec[:4]:
                    response = "\tManufacturer: " + manufacturer.get('name') + " (0x" + self.manspec[:4] + ")"
                    length = len(response)
                    for product in manufacturer:
                        if product.get('type') == self.manspec[4:8] and product.get('id') == self.manspec[8:]:
                            response += "\n\tProduct Name: " + product.get('name') + " (0x" + self.manspec[4:8] + " 0x" + self.manspec[8:] + ")"
                    if len(response) == length:
                        response += "\n\tProduct Name: Unknown (0x" + self.manspec[4:8] + " 0x" + self.manspec[8:] + ")"
            if response is None:
                response = "\tManufacturer: Unknown (0x" + self.manspec[:4] + ")\n\tProduct Name: Unknown (0x" + self.manspec[4:8] + " 0x " + self.manspec[8:] + ")"
        return response


    def parse_version(self):
        response = None
        library_type = {"01":"Controller_Static", "02":"Controller", "03":"Slave_Enhanced", "04":"Slave",
                         "05":"Installer", "06":"Slave_Routing", "07":"Controller_Bridge", "08":"DUT"}

        if self.version is None:
            response = "\tLibrary Type: Unknown\n\tProtocol Version/Subverion: Unknown\n\tApplication Version/Subversion: Unknown"
        else:
            response = "\tLibrary Type: " + library_type[self.version[:2]] + " (0x" + self.version[:2] + ")"
            response += "\n\tProtocol Version/Subversion: 0x" + self.version[2:4] + " / 0x" + self.version[4:6]
            response += "\n\tApplication Version/Subversion: 0x" + self.version[6:8] + " / 0x" + self.version[8:10]

        return response


    def parse_cmd_classes(self):
        response = "\tSupported Command Classes: "
        if self.cmdclasses is None:
            response += "Unknown"
        else:
            for i in range(0,len(self.cmdclasses)-1,2):
                cc = int(self.cmdclasses[i:i+2], 16)
                if cc in _COMMAND_CLASS:
                    response += "\n\t\t" + _COMMAND_CLASS[cc] + " (" + hex(cc)+ ")"
                else:
                    response += "\n\t\tUnknown (" + hex(cc)+ ")"
        return response


    def parse_basic(self):
        response = "\tBasic Status: "
        if self.basic is None:
            response += "Unknown"
        elif self.basic == chr(0).encode("HEX"):
            response += "Off (0x00)"
        elif self.basic == chr(255).encode("HEX"):
            response += "On (0xFF)"
        else:
            response += "Unknown (0x" + self.basic + ")"
        return response


    def parse_configs(self):
        response = "\tConfigurations: "
        if self.configs is None:
            response += "Unknown"
        elif not self.configs:
            response += "\n\t\tSkipped (use: ezrecon.py --homeid=" + hex(self.homeid) + " --nodeid=" + str(self.nodeid) + " --configs)"
        else:
            for config in self.configs:
                response += "\n\t\tParam: 0x" + config + " Value: 0x" + self.configs[config]
        return response

    def display(self, verbose=False):
        if verbose:
            self.fix()
            print "NodeID " + str(self.nodeid) + ":"
            print self.parse_manspec()
            print self.parse_version()
            print self.parse_cmd_classes()
            print self.parse_basic()
            print self.parse_configs()
        else:
            print ("\tNodeID " + str(self.nodeid))


class ZWaveNetwork(object):
    def __init__(self, homeid):
        self.homeid = homeid
        self.nodes = dict()

    def add_node(self, node):
        if node.nodeid not in self.nodes:
            self.nodes[node.nodeid] = node

    def remove_node(self, node):
        if node.nodeid in self.nodes:
            del self.nodes[node.nodeid]

    def display(self, verbose=False):
        print("*************** Home ID: " + hex(self.homeid) + " *****************")
        #print "Devices:"
        for node in self.nodes:
            self.nodes[node].display(verbose)

        print("\n*****************************************************\n")


class Zwave_Automaton(Automaton):
    def parse_args(self, request, expected_response, preamble_length=80, *args, **kargs):
        Automaton.parse_args(self, *args, **kargs)
        load_module('gnuradio')
        self.request = request
        self.response = expected_response
        self.preamble_length = preamble_length
        self.tries = 0
        self.retries = 2

    @staticmethod
    def verify_checksum(packet):
        p = bytearray(str(packet))
        p = p[8:-1]
        calc_crc = hex(reduce(lambda x, y: x ^ y, p, 0xFF))
        crc_byte = packet[ZWaveReq].get_field('crc').i2repr(packet, packet.crc)
        if calc_crc == crc_byte:
            return True
        else:
            return False

    def master_filter(self, pkt):
        return (pkt.haslayer(ZWaveReq) and pkt[ZWaveReq].src == self.response[ZWaveReq].src)

    @ATMT.state(initial=1)
    def BEGIN(self):
        # switch_radio_protocol("Zwave")
        # time.sleep(2)
        if self.preamble_length != 80:
            gnuradio_set_vars(host="localhost", port=8080, preamble_len=self.preamble_length)
            time.sleep(1)

    @ATMT.condition(BEGIN)
    def begin(self):
        raise self.WAITING()

    @ATMT.action(begin)
    def initial_tx(self):
        # print "initial_tx"
        for _ in range(0, 3):
            send(self.request, verbose=False)

    @ATMT.state()
    def WAITING(self):
        # print "WAITING"
        pass

    @ATMT.receive_condition(WAITING)
    def valid_response(self, pkt):
        pkt[ZWaveReq].show()
        # print "valid_response"
        if self.response[ZWaveReq].headertype == pkt[ZWaveReq].headertype:
            # print "Same headertype"
            if self.response[ZWaveReq].headertype == 3:
                # print "Ack"
                raise self.END(pkt[ZWaveReq])
            if pkt[ZWaveReq].cmd_class == self.response[ZWaveReq].cmd_class:
                # print "Right Command Class"
                # Logic to check if GET
                raise self.END(pkt[ZWaveReq])
                # raise self.END(pkt)

    @ATMT.receive_condition(WAITING, prio=1)
    def invalid_response(self, pkt):
        # print "invalid_response"
        if self.tries >= self.retries:
            raise self.ERROR()
        else:
            self.tries += 1
            raise self.WAITING()

    @ATMT.timeout(WAITING, 1)
    def waiting_timeout(self):
        # print "timeout"
        # print "tries: " + str(self.tries)
        if self.tries >= self.retries:
            raise self.ERROR()
        else:
            self.tries += 1
            raise self.WAITING()

    @ATMT.action(invalid_response)
    @ATMT.action(waiting_timeout)
    def retransmit(self):
        # print "retransmit"
        if self.tries >= self.retries:
            for _ in range(0, 3):
                send(self.request, verbose=False)

    @ATMT.state(final=1)
    def ERROR(self):
        # print "ERROR"
        #gnuradio_exit(conf)
        return None

    @ATMT.state(final=1)
    def END(self, pkt):
        # print "END"
        #gnuradio_exit(conf)
        return pkt


class PassiveScanner:
    def __init__(self, timeout):
        self.seen = dict()
        self.timeout = timeout

    @staticmethod
    def verify_checksum(packet):
        p = bytearray(str(packet))
        p = p[:-1]
        calc_crc = hex(reduce(lambda x, y: x ^ y, p, 0xFF))
        crc_byte = packet[ZWaveReq].get_field('crc').i2repr(packet, packet.crc)
        if (calc_crc == crc_byte):
            return True
        else:
            return False

    def display(self):
        print("\n*************** Passive Scan Results *****************\n")
        for homeid in self.seen:
            self.seen[homeid].display()

    def handle_packets(self, packet):
        if packet[ZWaveReq].dst == 255:
            return
        if not self.verify_checksum(packet[ZWaveReq]):
            # print "Checksum Error: Ignoring Frame..."
            return
        if packet.homeid not in self.seen:
            print "[+] Found new Zwave network: " + hex(packet.homeid)
            self.seen[packet.homeid] = ZWaveNetwork(packet.homeid)
        for nodeid in (packet.src, packet.dst):
            if nodeid not in self.seen[packet.homeid].nodes:
                print "[+][+] Found new Zwave node: " + hex(packet.homeid) + " node " + str(nodeid)
                self.seen[packet.homeid].add_node(ZWaveNode(packet.homeid, nodeid))

    @property
    def run(self):
        load_module('gnuradio')
        print "Sniffing for " + str(self.timeout) + " seconds..."

        sniffradio(radio="Zwave", store=0, count=None, timeout=self.timeout,
                   prn=lambda p: self.handle_packets(p),
                   lfilter=lambda x: x.haslayer(ZWaveReq))
        gnuradio_exit(conf)
        return self.seen


class ActiveScanner:
    def __init__(self, network, timeout, nodeid=255, preamble_len=80, strict=False):
        self.network = network
        self.timeout = timeout
        self.nodeid = nodeid
        self.preamble_length = preamble_len
        self.strict = strict


    @staticmethod
    def verify_checksum(packet):
        p = bytearray(str(packet))
        p = p[:-1]
        calc_crc = hex(reduce(lambda x, y: x ^ y, p, 0xFF))
        crc_byte = packet[ZWaveReq].get_field('crc').i2repr(packet, packet.crc)
        if (calc_crc == crc_byte):
            return True
        else:
            return False

    def handle_packets(self, packet):
        if packet.dst == self.nodeid:
            return
        if not self.verify_checksum(packet[ZWaveReq]):
            #print "Checksum Error: Ignoring Frame..."
            return
        if packet.homeid != self.network.homeid:
            return
        if self.strict:
            if packet.src == self.nodeid and packet.headertype == 3:
                if packet.src not in self.network.nodes:
                    #print "[+][+] Found new Zwave node: " + hex(packet.homeid) + " node " + str(packet.src)
                    self.network.add_node(ZWaveNode(packet.homeid, packet.src))
        else:
            for nodeid in (packet.src, packet.dst):
                if nodeid not in self.network.nodes:
                    print "[+][+] Found new Zwave node: " + hex(packet.homeid) + " node " + str(nodeid)
                    self.network.add_node(ZWaveNode(packet.homeid, nodeid))

    @property
    def run(self):
        print "Active Scan of " + hex(self.network.homeid) + " for " + str(self.timeout) + " seconds..."
        load_module('gnuradio')
        pid = os.fork()
        if pid > 0:
            timer = time.time()
            if self.preamble_length != 80:
                time.sleep(1)
                gnuradio_set_vars(host="localhost", port=8080, preamble_len=self.preamble_length)
            time.sleep(1)
            pkt = ZWave(homeid=self.network.homeid, dst=self.nodeid, ackreq=1) / ZWaveNOP()
            while time.time() - timer < self.timeout:
                for _ in range(0,3):
                    send(pkt, verbose=False)
                time.sleep(3)
            time.sleep(5)
            os._exit(0)
        else:
            sniffradio(radio="Zwave", store=0, count=None, timeout=self.timeout,
                       prn=lambda p: self.handle_packets(p),
                       lfilter=lambda x: x.haslayer(ZWaveReq))

        gnuradio_exit(conf)
        return self.network

    '''
    def __init__(self, network):
        self.network = network
        self.max_node = 105
        self.request = ZWave(src=1, homeid=self.network.homeid, ackreq=1) / ZWaveNOP()
        self.response = ZWave(homeid=self.network.homeid, headertype=3, dst=1)

    @property
    def run(self):
        print "Active Scan of " + hex(self.network.homeid)

        load_module('gnuradio')
        switch_radio_protocol("Zwave")
        time.sleep(2)

        # loop through all possible nodeids
        for i in range(97, self.max_node + 1):
            # skip if the nodeid has already been seen
            # if i not in self.network.nodes:
            print i
            self.request.dst = i
            self.response.src = i
            #self.request.show()
            #self.response.show()
            ping = Zwave_Automaton(self.request, self.response).run()
            if ping is not None:
                self.network.add_node(ZWaveNode(self.network.homeid, i))
            time.sleep(1)

        return self.network
    '''
