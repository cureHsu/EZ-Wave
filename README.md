# EZ-Wave
EZ-Wave: Tools for Attacking and Evaluating Z-Wave Networks using Software-Defined Radios.

# Requirements

**Tested on Ubuntu 14.04 only

Python 2.7

GNU Radio 3.7+ (recommend Pybombs: https://gnuradio.org/redmine/projects/pybombs/wiki/QuickStart)

Wireshark 1.12+ (https://code.wireshark.org/review/wireshark)

Mercurial (sudo apt-get install mercurial -y)

**Default configuration is for 2 HackRF One SDRs. Other SDRs can be use by modifying the GRC files accordingly post install ($HOME/.scapy/radio).

OsmocomSDR (http://sdr.osmocom.org/trac/wiki/GrOsmoSDR)

HackRF host software (https://github.com/mossmann/hackrf/tree/master/host)

# Installation

The setup script will clone Scapy-radio (https://bitbucket.org/cybertools/scapy-radio/) and modify installation files

```
./setup.sh
```

## Install Scapy-radio

```
cd $HOME/scapy-radio
./install.sh scapy
./install.sh blocks
'''

Edit [gnuradio prefix]/etc/gnuradio/conf.d
		Append ":/usr/local/share/gnuradio/grc/blocks" to global_blocks_path

'''
./install.sh grc
'''

## Install Wireshark dissector

Copy all files in EZ-Wave/setup/wireshark to [wireshark]/epan/dissectors

```
cd [wireshark]
./autogen.sh
./configure
make
sudo make install
sudo ldconfig


# Usage

##ezstumbler

##ezfingerprint

##ezrecon
