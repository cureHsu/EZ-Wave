#!/bin/bash

scapy_radio_clone(){
	#sudo apt-get install mercurial -y
	hg clone https://bitbucket.org/cybertools/scapy-radio
	mv scapy-radio/ ${HOME}/
	cp setup/gr-Zwave/preamble_impl* ${HOME}/scapy-radio/gnuradio/gr-Zwave/lib/
	cp setup/gr-Zwave/preamble.h ${HOME}/scapy-radio/gnuradio/gr-Zwave/include/Zwave/
	cp setup/gr-Zwave/Zwave_preamble.xml ${HOME}/scapy-radio/gnuradio/gr-Zwave/grc/
	cp setup/install.sh ${HOME}/scapy-radio/
	chmod 755 ${HOME}/scapy-radio/install.sh
	cp setup/Zwave.grc ${HOME}/scapy-radio
	cp setup/scapy/layers/* ${HOME}/scapy-radio/scapy/scapy/layers
	cp setup/scapy/modules/* ${HOME}/scapy-radio/scapy/scapy/modules
	rm -rf ${HOME}/scapy-radio/utils
}

scapy_update() {
	rm /usr/local/lib/python2.7/dist-packages/scapy/layers/ZWave*
	rm /usr/local/lib/python2.7/dist-packages/scapy/layers/gnuradio*
	cp setup/scapy/layers/ZWave.py /usr/local/lib/python2.7/dist-packages/scapy/layers/
 	cp setup/scapy/layers/gnuradio.py /usr/local/lib/python2.7/dist-packages/scapy/layers/
	cp setup/scapy/modules/gnuradio.py /usr/local/lib/python2.7/dist-packages/scapy/modules/
	python -m py_compile /usr/local/lib/python2.7/dist-packages/scapy/layers/ZWave.py
	python -m py_compile /usr/local/lib/python2.7/dist-packages/scapy/layers/gnuradio.py
	python -m py_compile /usr/local/lib/python2.7/dist-packages/scapy/modules/gnuradio.py
}


if [ $# -eq 0 ]; then
	scapy_radio_clone	
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
