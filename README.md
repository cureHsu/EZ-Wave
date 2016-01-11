# EZ-Wave
EZ-Wave: Tools for Evaluating and Exploiting Z-Wave Networks using Software-Defined Radios.

ezstumbler: passive Z-Wave network discovery and active network enumeration

ezrecon: Z-Wave device interrogation including:
	- Manufacturer and device name
	- Software/firmware versions
	- Supported Z-Wave command classes
	- Device configuration settings

ezfingerprint: determines device's Z-Wave module generation (3rd of 5th gen) using a PHY layer manipulation technique (preamble length manipulation).

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
```

Open [gnuradio prefix]/etc/gnuradio/conf.d in a text editor and append ":/usr/local/share/gnuradio/grc/blocks" to global_blocks_path

```
./install.sh grc
```

## Install Wireshark dissector

Copy all files in EZ-Wave/setup/wireshark to [wireshark]/epan/dissectors

```
cd [wireshark]
./autogen.sh
./configure
make
sudo make install
sudo ldconfig
```

# Usage

##ezstumbler

ezstumbler.py [-h, --help] [-p, --passive] [-t, --timeout] [-a, --active] [--homeid]
	-p, --passive		Conduct a passive scan for a set time (secs)
	-t, --timeout		Timeout (secs) for scans, default=60
	-a, --active		Conduct an active scan for a set time (secs)
	--homeid		4 byte HomeID to scan (ex: 0x1a2b3c4d)

30s passive followed by active scan:
```
ezstumbler.py --timeout=30
```

passive scan:
```
ezstumbler.py --passive
```

active scan:
```
ezstumbler.py --active --homeid=0x1a2b3d4e
```

##ezrecon

ezrecon.py [-h, --help] [-c, --config] [-t, --timeout] homeid nodeid
	homeid			4 byte HomeID of target network (ex: 0x1a2b3c4d)
	nodeid			Target device NodeID (in decimal, <233)
	-c, --config		Include scan of device configuration settings (takes a while)
	-t, --timeout		Stop scanning after a given time (secs, default=30)

```
ezrecon.py 0x1a2b3c4d 20
```

##ezfingerprint

ezfingerprint.py homeid nodeid
	homeid			4 byte HomeID of target network (ex: 0x1a2b3c4d)
	nodeid			Target device NodeID (in decimal, <233)

```
ezfingerprint.py 0x1a2b3c4d 20
```
