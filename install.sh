#!/bin/bash

scapy_radio_clone(){
	#sudo apt-get install mercurial -y
	hg clone https://bitbucket.org/cybertools/scapy-radio
	mv scapy-radio/ ${HOME}/
	cp scapy-radio_mod/gr-Zwave/preamble_impl* ${HOME}/scapy-radio/gnuradio/gr-Zwave/lib/
	cp scapy-radio_mod/gr-Zwave/preamble.h ${HOME}/scapy-radio/gnuradio/gr-Zwave/include/Zwave/
	cp scapy-radio_mod/gr-Zwave/Zwave_preamble.xml ${HOME}/scapy-radio/gnuradio/gr-Zwave/grc/
	cp scapy-radio_mod/install.sh ${HOME}/scapy-radio/
	chmod 755 ${HOME}/scapy-radio/install.sh
	cp scapy-radio_mod/Zwave.grc ${HOME}/scapy-radio
	cp scapy-radio_mod/scapy/layers/* ${HOME}/scapy-radio/scapy/scapy/layers
	cp scapy-radio_mod/scapy/modules/* ${HOME}/scapy-radio/scapy/scapy/modules
}

scapy_update() {
	rm /usr/local/lib/python2.7/dist-packages/scapy/layers/ZWave*
	rm /usr/local/lib/python2.7/dist-packages/scapy/layers/gnuradio*
	cp ~/EZ-Wave/scapy-radio_mod/scapy/layers/ZWave.py /usr/local/lib/python2.7/dist-packages/scapy/layers/
 	cp ~/EZ-Wave/scapy-radio_mod/scapy/layers/gnuradio.py /usr/local/lib/python2.7/dist-packages/scapy/layers/
	cp ~/EZ-Wave/scapy-radio_mod/scapy/modules/gnuradio.py /usr/local/lib/python2.7/dist-packages/scapy/modules/
	python -m py_compile /usr/local/lib/python2.7/dist-packages/scapy/layers/ZWave.py
	python -m py_compile /usr/local/lib/python2.7/dist-packages/scapy/layers/gnuradio.py
	python -m py_compile /usr/local/lib/python2.7/dist-packages/scapy/modules/gnuradio.py
}

scapy_radio_install(){
	${HOME}/test/scapy-radio/install.sh
}

if [ $# -eq 0 ]; then
	scapy_radio_clone
	#scapy_radio_install	
else
	while [ $# -ne 0 ]; do
  		case $1 in
    		clone)
			scapy_radio_clone
			;;
		update)
			scapy_update
			;;
    		*)
			echo "Invalid option: $1"
  		esac
  		shift
	done
fi
