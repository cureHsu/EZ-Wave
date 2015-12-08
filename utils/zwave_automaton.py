'''
Created on Jun 29, 2015

@author: Joseph Hall
'''


from scapy.all import * #@UnusedWildImport
from scapy.layers.ZWave import * #@UnusedWildImport
from scapy.modules.gnuradio import * #@UnusedWildImport
from scapy.layers.ZWave import ZWaveReq

class Zwave_Automaton(Automaton):
    '''
    classdocs
    '''
    
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
        print "initial_tx"
        for _ in range(0,3):
            send(self.request, verbose=False)
    
    
    @ATMT.state()
    def WAITING(self):
        print "WAITING"
        pass            
    @ATMT.receive_condition(WAITING)
    def valid_response(self, pkt):
        #pkt.show()
        print "valid_response"
        if self.response[ZWaveReq].headertype == pkt[ZWaveReq].headertype:
            print "Same headertype"
            if self.response[ZWaveReq].headertype == 3:
                print "Ack"
                raise self.END(pkt[ZWaveReq])
            if pkt[ZWaveReq].cmd_class == self.response[ZWaveReq].cmd_class:
                print "Right Command Class"
                #Logic to check if GET
                raise self.END(pkt[ZWaveReq])
        #raise self.END(pkt) 
    @ATMT.receive_condition(WAITING, prio=1)
    def invalid_response(self, pkt):
        print "invalid_response"
        if self.tries >= self.retries:
            raise self.ERROR()
        else:
            self.tries+=1
            raise self.WAITING()
            
    
    @ATMT.timeout(WAITING, 4)
    def waiting_timeout(self):
        print "timeout"
        print "tries: " + str(self.tries)
        if self.tries >= self.retries:
            raise self.ERROR()
        else:
             self.tries+=1
             raise self.WAITING()
         
    
    @ATMT.action(invalid_response)
    @ATMT.action(waiting_timeout)
    def retransmit(self):
        print "retransmit"
        if self.tries >= self.retries:
            for _ in range(0,3):
                send(self.request, verbose=False)
    
    
    @ATMT.state(final=1)
    def ERROR(self):      
        print "ERROR"  
        return None
        
    
    @ATMT.state(final=1)
    def END(self, pkt):
        print "END"
        gnuradio_exit(conf)
        return pkt    

        
