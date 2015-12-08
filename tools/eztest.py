from scapy.all import * #@UnusedWildImport
from scapy.layers.ZWave import * #@UnusedWildImport
from scapy.layers.gnuradio import * #@UnusedWildImport
from scapy.modules.gnuradio import * #@UnusedWildImport
from zwave_automaton import * #@UnusedWildImport

if __name__ == "__main__":
   
    load_module('gnuradio')
    switch_radio_protocol("Zwave")
    time.sleep(2)
    #preamble_length = 32
    #gnuradio_set_vars(host="localhost", port=8080, preamble_len=preamble_length)
    #time.sleep(1)
    home_id=0xe1453473
    dst_id=85
    '''
    test = ZWave(homeid=home_id, ackreq=1, dst=dst_id) / ZWaveBasic(cmd="SET") / chr(255)
    for _ in range(0,3):
        send(test, verbose=False)
    '''
    manspec = ZWave(src=82, homeid=home_id, dst=dst_id) / ZWaveManufacturerSpecific(cmd="GET")
    version = ZWave(src=82, homeid=home_id, dst=dst_id) / ZWaveVersion(cmd="GET")
    nif = ZWave(src=82, homeid=home_id, dst=dst_id) / ZWaveNodeInfo() / chr(2)
    config = ZWave(homeid=home_id, dst=dst_id) / ZWaveConfiguration(cmd="GET")
    
    for _ in range(0,3):
        send(manspec, verbose=False)
    
    time.sleep(4)
    
    for _ in range(0,3):
        send(version, verbose=False)
        
    time.sleep(4)
    
    for _ in range(0,3):
        send(nif, verbose=False)
        
    time.sleep(4)
    
    '''
    for i in range(0,256):
        #conf = "\\" + hex(i)[1:]
        #print conf
        frame = config / chr(i)

        for _ in range(0,3):
            send(frame, verbose=False)
        
        time.sleep(5)
    '''
    time.sleep(3)
    print "Exit"
