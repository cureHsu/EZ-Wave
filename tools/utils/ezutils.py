'''
Created on Jun 29, 2015

@author: Joseph Hall
'''

from scapy.all import * #@UnusedWildImport
from scapy.layers.ZWave import * #@UnusedWildImport
from scapy.modules.gnuradio import * #@UnusedWildImport

class ZWaveNode(object):

    def __init__(self, homeid, nodeid):
        self.homeid = homeid
        self.nodeid = nodeid
        self.manspec = None
        self.cmdclasses = None
        self.version = None
        self.configs = None
        
    def display(self, verbose=False):
        if verbose:
            print ("\tNodeID " + str(self.nodeid) + ":")
            print ("\t\tManufacturer: ")
            print ("\t\tProduct Name: ")
            print ("\t\tLibrary Type: ")
            print ("\t\tProtocol Version/Sub-version: ")
            print ("\t\tApplication Version/Sub-version: \n")
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
        print "Devices:"
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
        self.retries = 3  

    
    @staticmethod
    def verify_checksum(packet):
        p = bytearray(str(packet))
        p = p[8:-1]
        calc_crc = hex(reduce(lambda x, y: x ^ y, p, 0xFF))
        crc_byte = packet[ZWaveReq].get_field('crc').i2repr(packet, packet.crc)
        if (calc_crc == crc_byte): return True
        else: return False
        
    
    def master_filter(self, pkt):
        return ( pkt.haslayer(ZWaveReq) and pkt[ZWaveReq].src == self.response[ZWaveReq].src)
    
            
    @ATMT.state(initial=1)
    def BEGIN(self):
        switch_radio_protocol("Zwave")
        time.sleep(2)
        if self.preamble_length != 80:
            gnuradio_set_vars(host="localhost", port=8080, preamble_len=self.preamble_length)
            time.sleep(1)
    @ATMT.condition(BEGIN)
    def begin(self):
        raise self.WAITING()
    @ATMT.action(begin)
    def initial_tx(self):
        #print "initial_tx"
        for _ in range(0,3):
            send(self.request, verbose=False)
    
    
    @ATMT.state()
    def WAITING(self):
        #print "WAITING"
        pass            
    @ATMT.receive_condition(WAITING)
    def valid_response(self, pkt):
        pkt[ZWaveReq].show()
        #print "valid_response"
        if self.response[ZWaveReq].headertype == pkt[ZWaveReq].headertype:
            #print "Same headertype"
            if self.response[ZWaveReq].headertype == 3:
                #print "Ack"
                raise self.END(pkt[ZWaveReq])
            if pkt[ZWaveReq].cmd_class == self.response[ZWaveReq].cmd_class:
                #print "Right Command Class"
                #Logic to check if GET
                raise self.END(pkt[ZWaveReq])
        #raise self.END(pkt) 
    @ATMT.receive_condition(WAITING, prio=1)
    def invalid_response(self, pkt):
        #print "invalid_response"
        if self.tries >= self.retries:
            raise self.ERROR()
        else:
            self.tries+=1
            raise self.WAITING()
            
    
    @ATMT.timeout(WAITING, 4)
    def waiting_timeout(self):
        #print "timeout"
        #print "tries: " + str(self.tries)
        if self.tries >= self.retries:
            raise self.ERROR()
        else:
             self.tries+=1
             raise self.WAITING()
         
    
    @ATMT.action(invalid_response)
    @ATMT.action(waiting_timeout)
    def retransmit(self):
        #print "retransmit"
        if self.tries >= self.retries:
            for _ in range(0,3):
                send(self.request, verbose=False)
    
    
    @ATMT.state(final=1)
    def ERROR(self):      
        #print "ERROR"
        gnuradio_exit(conf)
        return None
        
    
    @ATMT.state(final=1)
    def END(self, pkt):
        #print "END"
        gnuradio_exit(conf)
        return pkt    

        
class PassiveScanner:

    def __init__(self, timeout):
        self.seen = dict()
        self.timeout = timeout

    @staticmethod
    def verify_checksum(packet):
        p = bytearray(str(packet))
        p = p[8:-1]
        calc_crc = hex(reduce(lambda x, y: x ^ y, p, 0xFF))
        crc_byte = packet[ZWaveReq].get_field('crc').i2repr(packet, packet.crc)
        if (calc_crc == crc_byte): return True
        else: return False

    def display(self):
        print("\n******************* Passive Scan Results *******************\n")
        for homeid in self.seen:
            self.seen[homeid].display()

    def handle_packets(self, packet):

        if self.verify_checksum(packet) == False:
            #print "Checksum Error: Ignoring Frame..."
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
        print "Scanning for " + str(self.timeout) + " seconds..."

        sniffradio(radio="Zwave", store=0, count=None, timeout=self.timeout,
                       prn=lambda p: self.handle_packets(p),
                       lfilter=lambda x: x.haslayer(ZWaveReq))
        gnuradio_exit(conf)
        return self.seen


class ActiveScanner:

    def __init__(self, network):
        self.network = network
        self.max_node = 63
        self.request = ZWave(src=1, homeid=self.network.homeid, ackreq=1) / ZWaveNOP()
        self.response = ZWave(homeid=self.network.homeid, headertype=3, dst=1)

    def run(self):
        print "Active Scan of " + hex(self.network.homeid)

        #loop through all possible nodeids
        for i in range(63, self.max_node+1):
            #skip if the nodeid has already been seen
            #if i not in self.network.nodes:
            self.request.dst = i
            self.response.src = i
            self.request.show()
            self.response.show()
            ping = Zwave_Automaton(self.request, self.response).run()
            if ping is not None:
                self.network.add_node(ZWaveNode(self.network.homeid, i))

        return self.network