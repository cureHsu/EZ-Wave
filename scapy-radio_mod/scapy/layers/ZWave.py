## This file is for use with Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Airbus DS CyberSecurity
## Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay
## This program is published under a GPLv2 license

"""
Wireless Z-Wave.
"""

from scapy.packet import *
from scapy.fields import *
import struct

_COMMAND_CLASS = {
    0x00: "NO_OPERATION",
    0x20: "BASIC",
    0x21: "CONTROLLER_REPLICATION",
    0x22: "APPLICATION_STATUS",
    0x23: "ZIP_SERVICES",
    0x24: "ZIP_SERVER",
    0x25: "SWITCH_BINARY",
    0x26: "SWITCH_MULTILEVEL",
    0x27: "SWITCH_ALL",
    0x28: "SWITCH_TOGGLE_BINARY",
    0x29: "SWITCH_TOGGLE_MULTILEVEL",
    0x2A: "CHIMNEY_FAN",
    0x2B: "SCENE_ACTIVATION",
    0x2C: "SCENE_ACTUATOR_CONF",
    0x2D: "SCENE_CONTROLLER_CONF",
    0x2E: "ZIP_CLIENT",
    0x2F: "ZIP_ADV_SERVICES",
    0x30: "SENSOR_BINARY",
    0x31: "SENSOR_MULTILEVEL",
    0x32: "METER",
    0x33: "COLOR",
    0x34: "ZIP_ADV_CLIENT",
    0x35: "METER_PULSE",
    0x3C: "METER_TBL_CONFIG",
    0x3D: "METER_TBL_MONITOR",
    0x3E: "METER_TBL_PUSH",
    0x38: "THERMOSTAT_HEATIN",
    0x40: "THERMOSTAT_MODE",
    0x42: "THERMOSTAT_OPERATING_STATE",
    0x43: "THERMOSTAT_SETPOINT",
    0x44: "THERMOSTAT_FAN_MODE",
    0x45: "THERMOSTAT_FAN_STATE",
    0x46: "CLIMATE_CONTROL_SCHEDULE",
    0x47: "THERMOSTAT_SETBACK",
    0x4C: "DOOR_LOCK_LOGGING",
    0x4E: "SCHEDULE_ENTRY_LOCK",
    0x50: "BASIC_WINDOW_COVERING",
    0x51: "MTP_WINDOW_COVERING",
    0x60: "MULTI_CHANNEL_V2",
    0x61: "MULTI_INSTANCE",
    0x62: "DOOR_LOCK",
    0x63: "USER_CODE",
    0x70: "CONFIGURATION",
    0x71: "ALARM",
    0x72: "MANUFACTURER_SPECIFIC",
    0x73: "POWERLEVEL",
    0x75: "PROTECTION",
    0x76: "LOCK",
    0x77: "NODE_NAMING",
    0x7A: "FIRMWARE_UPDATE_MD",
    0x7B: "GROUPING_NAME",
    0x7C: "REMOTE_ASSOCIATION_ACTIVATE",
    0x7D: "REMOTE_ASSOCIATION",
    0x80: "BATTERY",
    0x81: "CLOCK",
    0x82: "HAIL",
    0x84: "WAKE_UP",
    0x85: "ASSOCIATION ",
    0x86: "VERSION",
    0x87: "INDICATOR",
    0x88: "PROPRIETARY",
    0x89: "LANGUAGE ",
    0x8A: "TIME ",
    0x8B: "TIME_PARAMETERS",
    0x8C: "GEOGRAPHIC_LOCATION",
    0x8D: "COMPOSITE",
    0x8E: "MULTI_INSTANCE_ASSOCIATION",
    0x8F: "MULTI_CMD ",
    0x90: "ENERGY_PRODUCTION ",
    0x91: "MANUFACTURER_PROPRIETARY",
    0x92: "SCREEN_MD",
    0x93: "SCREEN_ATTRIBUTES",
    0x94: "SIMPLE_AV_CONTROL",
    0x95: "AV_CONTENT_DIRECTORY_MD",
    0x96: "AV_RENDERER_STATUS",
    0x97: "AV_CONTENT_SEARCH_MD",
    0x98: "SECURITY",
    0x99: "AV_TAGGING_MD ",
    0x9A: "SIP_CONFIGURATION",
    0x9B: "ASSOCIATION_COMMAND_CONFIGURATION",
    0x9C: "SENSOR_ALARM ",
    0x9D: "SILENCE_ALARM",
    0x9E: "MARK",
    0xF0: "NON_INTEROPERABLE"
}

class BaseZWave(Packet):
    name = "ZWave"
    fields_desc = [
        XIntField("homeid", 0x01020304),
        XByteField("src", 1),
        BitField("routed", 0, 1),
        BitField("ackreq", 0, 1),
        BitField("lowpower", 0, 1),
        BitField("speedmodified", 0, 1),
        BitField("headertype", 1, 4),
        BitField("reserved_1", 0, 1),
        BitField("beam_control", 0, 2),
        BitField("reserved_2", 0, 1),
        BitField("seqn", 1, 4),
        XByteField("length", None),
        XByteField("dst", 2),
    ]
 
    def post_build(self, p, pay):
        #Reorder bytes to move crc to last byte
        crc = p[-1]
        p = p[:-1] + pay
        #Calculate Length    
        if self.length is None:
            p = p[:7] + chr((len(p) + 1) & 0xff) + p[8:]
            self.length = ord(p[7])
        #Calculate Checksum
        p += crc if self.crc is not None else chr(reduce(lambda x, y: x ^ ord(y), p, 0xff))
        
        return p       


class ZWaveReq(BaseZWave):
    name = "ZWaveReq"
    fields_desc = [
        BaseZWave,
        ConditionalField(ByteEnumField("cmd_class", 0, _COMMAND_CLASS),
                         lambda pkt: hasattr(pkt, "headertype") and pkt.headertype != 3),
        XByteField("crc", None),
    ]
    
    def pre_dissect(self, s):
        return s[:10] + s[-1] + s[10:-1]

class ZWaveNOP(Packet):
    name = "ZWaveNOP"

class ZWaveNodeInfo(Packet):
    name = "ZWaveNodeInfo"

class ZWaveBasic(Packet):
    name = "ZWaveBasic"
    fields_desc = [
        ByteEnumField("cmd", 0, {1: "SET", 2: "GET", 3: "REPORT"}),
    ]
    
class ZWaveControllerReplication(Packet):
    name = "ZWaveControllerReplication"
    fields_desc = [
        ByteEnumField("cmd", 0, {0x31: "TRANSFERGROUP", 0x32: "TRANSFERGROUPNAME", 0x33: "TRANSFERSCENE", 0x34: "TRANSFERSCENENAME"}),
    ]
    
class ZWaveApplicationStatus(Packet):
    name = "ZWaveApplicationStatus"
    fields_desc = [
        ByteEnumField("cmd", 0, {1: "BUSY", 2: "REJECTED"}),
    ]

class ZWaveSwitchBin(Packet):
    name = "ZWaveSwitchBin"
    fields_desc = [
        ByteEnumField("cmd", 0, {1: "SET", 2: "GET", 3: "REPORT"}),  
    ]

class ZWaveSwitchMulti(Packet):
    name = "ZWaveSwitchMulti"
    fields_desc = [
        ByteEnumField("cmd", 0, {1: "SET", 2: "GET", 3: "REPORT", 4: "START_LVL_CHANGE", 5: "STOP_LVL_CHANGE"}),
    ]
    
class ZWaveSwitchAll(Packet):
    name = "ZWaveSwitchAll"
    fields_desc = [
        ByteEnumField("cmd", 0, {1: "SET", 2: "GET", 3: "REPORT", 4: "ON", 5: "OFF"}),
    ]
    
class ZWaveSwitchToggleBin(Packet):
    name = "ZWaveSwitchToggleBin"
    fields_desc = [
        ByteEnumField("cmd", 0, {1: "SET", 2: "GET", 3: "REPORT"}),
    ]
     
class ZWaveSceneActivation(Packet):
    name = "ZWaveSceneActivation"
    fields_desc = [
        ByteEnumField("cmd", 0, {1: "SET"}),
    ]
       
class ZWaveSwitchToggleMulti(Packet):
    name = "ZWaveSwitchToggleMulti"
    fields_desc = [
        ByteEnumField("cmd", 0, {1: "SET", 2: "GET", 3: "REPORT", 4: "STARTLEVEL", 5: "STOPLEVEL"}),
    ]
        
class ZWaveSensBin(Packet):
    name = "ZWaveSensBin"
    fields_desc = [
        ByteEnumField("cmd", 0, {2: "GET", 3: "REPORT"}),
    ]
    
class ZWaveSensMulti(Packet):
    name = "ZWaveSensMulti"
    fields_desc = [
        ByteEnumField("cmd", 0, {1: "SUPPORTEDGET", 2: "SUPPORTEDREPORT", 4: "GET", 5: "REPORT"}),
    ]
    
class ZWaveMeter(Packet):
    name = "ZWaveMeter"
    fields_desc = [
        ByteEnumField("cmd", 0, {1: "GET", 2: "REPORT", 3: "SUPPORTEDGET", 4: "SUPPORTEDREPORT", 5: "RESET"}),
    ]


class ZWaveColor(Packet):
    name = "ZWaveColor"
    fields_desc = [
        ByteEnumField("cmd", 1, {0x01: "CAPABILITYGET", 0x02: "CAPABILITYREPORT",
                                 0x03: "GET", 0x04: "REPORT", 0x05: "SET",
                                 0x06: "STARTLEVEL", 0x07: "STOPSTATECHANGE"}),
    ]
    
class ZWaveMeterPulse(Packet):
    name = "ZWaveMeterPulse"
    fields_desc = [
        ByteEnumField("cmd", 0, {4: "GET", 5: "REPORT"}),
    ]
 
class ZWavePlusInfo(Packet):
    name = "ZWavePlusInfo"
    fields_desc = [
        ByteEnumField("cmd", 1, {0x01: "GET", 0x02: "REPORT"}),
    ]  
    
class ZWaveDoorLock(Packet):
    name = "ZWaveDoorLock"
    fields_desc = [
        ByteEnumField("cmd", 1, {0x01: "SET", 0x02: "GET", 0x03: "REPORT", 0x04: "CONFIGSET", 0x05: "CONFIGGET", 0x06: "CONFIGREPORT"}),
    ] 
    
class ZWaveUserCode(Packet):
    name = "ZWaveUserCode"
    fields_desc = [
        ByteEnumField("cmd", 1, {0x01: "USERCODESET", 0x02: "USERCODEGET", 0x03: "USERCODEREPORT", 0x04: "USERNUMSET", 0x05: "USERNUMGET", 0x06: "USERREPORT"}),
    ] 
    
class ZWaveConfiguration(Packet):
    name = "ZWaveConfiguration"
    fields_desc = [
        ByteEnumField("cmd", 0, {0x04: "SET", 0x05: "GET", 0x06: "REPORT"}),
    ]  

class ZWaveManufacturerSpecific(Packet):
    name = "ZWaveManufacturerSpecific"
    fields_desc = [
        ByteEnumField("cmd", 0x04, {0x04: "GET", 0x05: "REPORT"}),
    ]     
       
class ZWavePowerlevel(Packet):
    name = "ZWavePowerlevel"
    fields_desc = [
        ByteEnumField("cmd", 0, {0x01: "SET", 0x02: "GET", 0x03: "REPORT", 0x04: "TESTSET", 0x05: "TESTGET", 0x06: "TESTREPORT"}),
    ] 
    
class ZWaveProtection(Packet):
    name = "ZWaveProtection"
    fields_desc = [
        ByteEnumField("cmd", 1, {0x01: "SET", 0x02: "GET", 0x03: "REPORT"}),
    ] 
    
class ZWaveBattery(Packet):
    name = "ZWaveBattery"
    fields_desc = [
        ByteEnumField("cmd", 1, {0x01: "SET", 0x02: "GET", 0x03: "REPORT"}),
    ] 
    
class ZWaveWakeup(Packet):
    name = "ZWaveWakeup"
    fields_desc = [
        ByteEnumField("cmd", 0x4, {0x4: "INTERVALSET", 0x5: "INTERVALGET", 0x6: "INTERVALREPORT", 0x7: "NOTIFICATION", 0x8: "NOMOREINFO", 0x9: "INTERVALCAPABILITIESGET", 0xa: "INTERVALCAPABILITIESREPORT"}),
    ]  
    
class ZWaveAssociation(Packet):
    name = "ZWaveAssociation"
    fields_desc = [
        ByteEnumField("cmd", 0x1, {0x1: "SET", 0x2: "GET", 0x3: "REPORT", 0x4: "REMOVE", 0x5: "GROUPINGSGET", 0x6: "GROUPINGSREPORT"}),
    ]    
    
class ZWaveVersion(Packet):
    name = "ZWaveVersion"
    fields_desc = [
        ByteEnumField("cmd", 0x11, {0x11: "GET", 0x12: "REPORT", 0x13: "CCGET", 0x14: "CCREPORT"}),
    ] 
    
class ZWaveIndicator(Packet):
    name = "ZWaveIndicator"
    fields_desc = [
        ByteEnumField("cmd", 1, {0x01: "SET", 0x02: "GET", 0x03: "REPORT"}),
    ] 
    
class ZWaveProprietary(Packet):
    name = "ZWaveProprietary"
    fields_desc = [
        ByteEnumField("cmd", 1, {0x01: "SET", 0x02: "GET", 0x03: "REPORT"}),
    ] 
    
class ZWaveManufacturerProprietary(Packet):
    name = "ZWaveManufacturerProprietary"
    fields_desc = [
        ByteEnumField("cmd", 1, {0x01: "SET", 0x02: "GET", 0x03: "REPORT"}),
    ] 
    
class ZWaveSecurity(Packet):
    name = "ZWaveSecurity"
    fields_desc = [
        ByteEnumField("cmd", 3, {0x02: "GET", 0x03: "REPORT", 0x4: "SCHEMEGET", 0x5: "SCHEMEREPORT", 
                                 0x6: "KEYSET", 0x7: "KEYVERIFY", 0x8: "SCHEMEINHERIT", 
                                 0x40: "NONCEGET", 0x80: "NONCEREPORT", 0x81: "MSGENCAP", 0xc1: "MSGENCAPNONCEGET" }),
    ]
    
def ZWave(_pkt=None, *args, **kargs):
    return ZWaveReq(_pkt, *args, **kargs)


bind_layers(ZWaveReq, ZWaveNOP, cmd_class=0x0)
bind_layers(ZWaveReq, ZWaveNodeInfo, cmd_class=0x1)
bind_layers(ZWaveReq, ZWaveBasic, cmd_class=0x20)
bind_layers(ZWaveReq, ZWaveControllerReplication, cmd_class=0x21)
bind_layers(ZWaveReq, ZWaveApplicationStatus, cmd_class=0x22)
bind_layers(ZWaveReq, ZWaveSwitchBin, cmd_class=0x25)
bind_layers(ZWaveReq, ZWaveSwitchMulti, cmd_class=0x26)
bind_layers(ZWaveReq, ZWaveSwitchAll, cmd_class=0x27)
bind_layers(ZWaveReq, ZWaveSwitchToggleBin, cmd_class=0x28)
bind_layers(ZWaveReq, ZWaveSceneActivation, cmd_class=0x2a)
bind_layers(ZWaveReq, ZWaveSwitchToggleMulti, cmd_class=0x2b)
bind_layers(ZWaveReq, ZWaveSensBin, cmd_class=0x30)
bind_layers(ZWaveReq, ZWaveSensMulti, cmd_class=0x31)
bind_layers(ZWaveReq, ZWaveMeter, cmd_class=0x32)
bind_layers(ZWaveReq, ZWaveColor, cmd_class=0x33)
bind_layers(ZWaveReq, ZWaveMeterPulse, cmd_class=0x35)
bind_layers(ZWaveReq, ZWavePlusInfo, cmd_class=0x5e)
bind_layers(ZWaveReq, ZWaveDoorLock, cmd_class=0x62)
bind_layers(ZWaveReq, ZWaveUserCode, cmd_class=0x63)
bind_layers(ZWaveReq, ZWaveConfiguration, cmd_class=0x70)
bind_layers(ZWaveReq, ZWaveManufacturerSpecific, cmd_class=0x72)
bind_layers(ZWaveReq, ZWavePowerlevel, cmd_class=0x73)
bind_layers(ZWaveReq, ZWaveProtection, cmd_class=0x75)
bind_layers(ZWaveReq, ZWaveBattery, cmd_class=0x80)
bind_layers(ZWaveReq, ZWaveWakeup, cmd_class=0x84)
bind_layers(ZWaveReq, ZWaveAssociation, cmd_class=0x85)
bind_layers(ZWaveReq, ZWaveVersion, cmd_class=0x86)
bind_layers(ZWaveReq, ZWaveIndicator, cmd_class=0x87)
bind_layers(ZWaveReq, ZWaveProprietary, cmd_class=0x88)
bind_layers(ZWaveReq, ZWaveManufacturerProprietary, cmd_class=0x91)
bind_layers(ZWaveReq, ZWaveSecurity, cmd_class=0x98)
