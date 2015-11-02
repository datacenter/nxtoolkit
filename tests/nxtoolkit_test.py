################################################################################
#                                                                              #
# Copyright (c) 2015 Cisco Systems                                             #
# All Rights Reserved.                                                         #
#                                                                              #
#    Licensed under the Apache License, Version 2.0 (the "License"); you may   #
#    not use this file except in compliance with the License. You may obtain   #
#    a copy of the License at                                                  #
#                                                                              #
#         http://www.apache.org/licenses/LICENSE-2.0                           #
#                                                                              #
#    Unless required by applicable law or agreed to in writing, software       #
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT #
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the  #
#    License for the specific language governing permissions and limitations   #
#    under the License.                                                        #
#                                                                              #
################################################################################
"""Nexus Toolkit Test module
"""
from nxtoolkit.nxbaseobject import BaseNXObject, BaseRelation
from nxtoolkit.nxsession import Session
from nxtoolkit.nxtoolkit import (
    BGPSession, PortChannel, LinkNeighbors, Hardware, HardwareInternal,
    Logging, LogTimeStamp, LogConsole, LogMonitor, LogSourceInterface,
    LogLevel, LogServer, L2BD, L3Inst, InterfaceBreakout, BreakoutModule,
    SVI, ConfigInterfaces, ConfigVrrps, Vrrp, VrrpID, Lacp, IP, IPRoute,
    Feature, FeatureAttributes, Dhcp, DhcpRelay, BootNxos, Copy, 
    RunningToStartUp, DNS, DnsProfile, DnsHost, DnsDomExt, DnsDom, 
    DnsProvider, DnsVrf, ICMP, ConfigBDs, UDLD, STP, StpInterface, StpVlan,
    StpMst, ARP, AaaRole, AaaUserRole, AaaUser, AaaRadiusProvider, AaaRadius,
    AaaTacacsProvider, AaaProviderRef, AaaTacacsProviderGroup, AaaTacacs, 
    AaaAaa, RBAC, NdPrefix, NdInterface, ND, MatchRtType, MatchRtTag, 
    SetPeerAddr, SetNextHop, SetLocalPref, SetOrigin, SetCommList, RtmapRs, 
    RtmapMatch, RegCom, SetRegCom, RouteMapEntry, RouteMap, RtPrefix, 
    PrefixList, AccessList, AsPath, CommunityItem, CommunityEntry, 
    CommunityList, RPM)

from nxtoolkit.nxphysobject import (Interface)
import unittest
import string
import random
import time
import json
try:
    from credentials import URL, LOGIN, PASSWORD
except ImportError:
    print
    print 'To run live tests, please create a credentials.py file with the following variables filled in:'
    print """
    URL = ''
    LOGIN = ''
    PASSWORD = ''
    """

MAX_RANDOM_STRING_SIZE = 20

def random_string(size):
    """
    Generates a random string of a certain specified size.

    :param size: Integer indicating size of string
    :returns: String of random characters
    """
    return ''.join(random.choice(string.ascii_uppercase +
                                 string.digits) for _ in range(size))


def random_size_string():
    """
    Generates a random string between 1 and MAX_RANDOM_STRING_SIZE
    characters

    :returns: String of random characters between 1 and\
              MAX_RANDOM_STRING_SIZE characters.
    """
    return random_string(random.randint(1, MAX_RANDOM_STRING_SIZE))


class TestPortChannel(unittest.TestCase):
    """
    This class defines off line testing of port channel
    """
    def create_pc(self):
        """
        creates port channel and interface objects attach interfaces
        to the portchannel
        """
        if1 = Interface('eth1/8')
        if2 = Interface('eth1/5')
        pc = PortChannel('444')
        pc.attach(if1)
        pc.attach(if2)
        return pc

    def test_create_pc(self):
        """
        Test creating a PortChannel
        """
        pc = self.create_pc()
        self.assertTrue(pc.is_interface())
        self.assertTrue(pc.is_vpc())
        port_channel = pc.get_json()

        expected_resp = ("{'pcAggrIf': {'attributes': {'pcId': '444', 'name':"
                         " 'po444', 'id': 'po444'}, 'children': [{'pcRsMbrIfs"
                         "': {'attributes': {'tDn': 'sys/intf/phys-[eth1/8]'}"
                         ", 'children': []}}, {'pcRsMbrIfs': {'attributes': {"
                         "'tDn': 'sys/intf/phys-[eth1/5]'}, 'children': []}}]"
                         "}}")

        self.assertEqual(str(port_channel), expected_resp)
        
    def config_vlan(self):
        """
        Create a PortChannel and configure vlan on it
        """
        # Create one port channel
        pc1 = PortChannel('444')
        # Enable above created vlans on the port channel
        pc1.set_access_vlan('vlan-111')
        return pc1
    
    def test_config_vlan(self):
        """
        Test configuring vlan
        """
        pc = self.config_vlan()
        resp = pc.get_json()
        expected_json = ("{'pcAggrIf': {'attributes': {'pcId': '444', 'access"
                         "Vlan': 'vlan-111', 'name': 'po444', 'id': 'po444'},"
                         " 'children': []}}")
        self.assertEqual(str(resp), expected_json)
        
        
class TestLogging(unittest.TestCase):
    """
    This class defines off line testing of logging
    """
    def create_logging(self):
        """
        create logging parameter used as setup for test cases
        """
        log = Logging()
        timestamp = LogTimeStamp(format='milliseconds')
        console = LogConsole(admin_st='1', severity='2')
        monitor = LogMonitor(admin_st='1', severity='2')
        source_iface = LogSourceInterface(admin_st='1', if_name='lo 2')
        level = LogLevel(severity='2', facility='local5')
        server = LogServer(host='10.10.1.12', severity='2', 
                      vrf_name='management', fwd_facility='auth')
        
        log.add_log(timestamp)
        log.add_log(console)
        log.add_log(monitor)
        log.add_log(source_iface)
        log.add_log(level)
        log.add_log(server) 
        return log
           
    def test_create_logging(self): 
        """
        Test creating logging parameters
        """
        log = self.create_logging()
        resp = log.get_json()
        expected_resp = ("{'syslogSyslog': {'attributes': {}, 'children': [{'"
                         "syslogTimeStamp': {'attributes': {'format': 'millis"
                         "econds'}}}, {'syslogConsole': {'attributes': {'admi"
                         "nState': '1', 'severity': '2'}}}, {'syslogTermMonit"
                         "or': {'attributes': {'adminState': '1', 'severity':"
                         " '2'}}}, {'syslogSourceInterface': {'attributes': {"
                         "'adminState': '1', 'ifName': 'lo 2'}}}, {'syslogLev"
                         "el': {'attributes': {'severity': '2', 'facility': '"
                         "local5'}}}, {'syslogRemoteDest': {'attributes': {'f"
                         "orwardingFacility': 'auth', 'host': '10.10.1.12', '"
                         "vrfName': 'management', 'severity': '2'}}}]}}")

        self.assertEqual(str(resp), expected_resp)
        
        
class TestL2BD(unittest.TestCase):
    """
    This class defines off line testing of bridge domains
    """
    def create_l2bd(self):
        """
        Creating a L2bd used as setup for test cases
        """
        return L2BD('vlan-111')
                
    def create_l2bd_multiple(self):
        """
        Creating multiple L2bds
        """
        bds = ConfigBDs()
        bd1 = L2BD('vlan-10')
        bd2 = L2BD('vlan-20')
        bds.add_l2bds(bd1)
        bds.add_l2bds(bd2)
        return bds

    def test_create_l2bd(self):
        """
        Test creating L2bd
        """
        l2bd = self.create_l2bd()
        resp = l2bd.get_json()
        expected_resp = ("{'l2BD': {'attributes': {'fabEncap': 'vlan-111', 'n"
                         "ame': 'vlan-111', 'unkMacUcastAct': 'flood', 'admin"
                         "St': 'active', 'id': '111', 'unkMcastAct': 'flood'}"
                         ", 'children': []}}")
        self.assertEqual(str(resp), expected_resp)

    def test_create_l2bd_multiple(self):
        """
        Test creating multiple L2bds
        """
        bds = self.create_l2bd_multiple()
        resp = bds.get_json()
        expected_resp = ("{'bdEntity': {'attributes': {}, 'children': [{'l2BD"
                         "': {'attributes': {'fabEncap': 'vlan-10', 'name': '"
                         "vlan-10', 'unkMacUcastAct': 'flood', 'adminSt': 'ac"
                         "tive', 'id': '10', 'unkMcastAct': 'flood'}, 'childr"
                         "en': []}}, {'l2BD': {'attributes': {'fabEncap': 'vl"
                         "an-20', 'name': 'vlan-20', 'unkMacUcastAct': 'flood"
                         "', 'adminSt': 'active', 'id': '20', 'unkMcastAct': "
                         "'flood'}, 'children': []}}]}}")
        self.assertEqual(str(resp), expected_resp)
        

class TestL3Inst(unittest.TestCase):
    """
    Create L3Inst class
    """
    def create_l3inst(self):
        """
        Creating L3Inst used as setup for test cases
        """
        l3inst = L3Inst('test-l3-inst')

        return l3inst
    
    def test_create_l3inst(self):
        """
        Test creating L3Inst
        """
        l3inst = self.create_l3inst()
        resp = l3inst.get_json()
        expected_json = ("{'l3Inst': {'attributes': {'name': 'test-l3-inst'},"
                         " 'children': []}}")
        self.assertEqual(str(resp), expected_json)
        

class TestInterfaceBreakout(unittest.TestCase):
    """
    Create breakout class
    """
    def create_breakout(self):
        """
        Create breakout object used as setup for test cases
        """
        brkout = InterfaceBreakout()
    
        module1 = BreakoutModule('1')
        module1.add_port_map('1', '10g-4x')
        
        module2 = BreakoutModule('2')
        module2.add_port_map('1', '10g-4x')
        
        brkout.add_module(module1)
        brkout.add_module(module2)
        
        return brkout
    
    def test_interface_breakout(self):
        """
        Test creating breakout interface
        """
        brkout = self.create_breakout()
        resp = brkout.get_json()
        expected_json = ("{'imBreakout': {'attributes': {}, 'children': "
                         "[{'imMod': {'attributes': {'id': '1'}, 'childr"
                         "en': [{'imFpP': {'attributes': {'breakoutMap':"
                         " '10g-4x', 'id': '1'}}}]}}, {'imMod': {'attrib"
                         "utes': {'id': '2'}, 'children': [{'imFpP': {'a"
                         "ttributes': {'breakoutMap': '10g-4x', 'id': '1"
                         "'}}}]}}]}}")
        self.assertEqual(str(resp), expected_json)
    
    def test_get_delete_url(self):
        """
        Test delete url of Interface Breakout
        """
        brkout = InterfaceBreakout()
        expected_url  = '/api/mo/sys/breakout/module-1/fport-1.json'
        self.assertEqual(expected_url, brkout.get_delete_url('1', '1'))


class TestSVI(unittest.TestCase):
    """
    Offline testing of SVI
    """
    def create_svi(self):
        """
        Create SVI object used as setup for test cases
        """
        svi10 = SVI('vlan10', admin_st='up', descr='Sample test')
        return svi10
    
    def create_svi_multiple(self):
        """
        Create multiple SVIs
        """
        config = ConfigInterfaces()
        # Create SVI objects providing vlans
        svi1 = SVI('vlan10')
        svi2 = SVI('vlan20')
        # Add svis to the config
        config.add_svis(svi1)
        config.add_svis(svi2)
        return config
    
    def test_config_svi_one(self):
        """
        Test creating SVI
        """
        svi = self.create_svi()
        resp = svi.get_json()
        expected_json = ("{'sviIf': {'attributes': {'id': 'vlan10', 'descr':"
                         " 'Sample test', 'adminSt': 'up'}, 'children': []}}")
        self.assertEqual(str(resp), expected_json)
    
    def test_config_svi_multiple(self):
        """
        Test creating mutiple SVI's
        """
        config = self.create_svi_multiple()
        resp = config.get_json()
        expected_json = ("{'interfaceEntity': {'attributes': {}, 'children': "
                         "[{'sviIf': {'attributes': {'id': 'vlan10'}, 'childr"
                         "en': []}}, {'sviIf': {'attributes': {'id': 'vlan20'"
                         "}, 'children': []}}]}}")
        self.assertEqual(str(resp), expected_json)

       
class TestInterface(unittest.TestCase):
    """
    Create Interface class
    """
    def create_interfcae(self):
        """
        Create Interface object and configure the its parameters
        """
        int1 = Interface('eth1/5')
        int1.set_admin_status('up')
        int1.set_layer('Layer2')
        int1.set_duplex('auto')
        int1.set_link_log('default')
        int1.set_mode('trunk')
        int1.set_speed('10G')
        int1.set_access_vlan('vlan-1')
        int1.set_trunk_log('default')
        int1.set_link_log('default')
        return int1

    def create_interface_mulitple(self):
        """
        Create multiple interfaces
        """
        config  = ConfigInterfaces()
        int1 = Interface('eth1/5')
        int2 = Interface('eth1/8')
        int1.set_layer('Layer2')
        int2.set_layer('Layer3')
        # Adding interfaces to be configured
        config.add_interface(int1)
        config.add_interface(int2)
        return config
    
    
    def test_config_interface(self):
        """
        Test creating Interface off line
        """
        iface = self.create_interfcae()
        resp = iface.get_json()
        expected_json = ("{'l1PhysIf': {'attributes': {'layer': 'Layer2', "
                         "'duplex': 'auto', 'trunkLog': 'default', 'mtu': "
                         "'1500', 'linkLog': 'default', 'mode': 'trunk', '"
                         "snmpTrapSt': 'default', 'accessVlan': 'vlan-1', "
                         "'adminSt': 'up', 'speed': '10G', 'id': 'eth1/5'}"
                         ", 'children': []}}")
        self.assertEqual(str(resp), expected_json)

    def test_config_interface_multiple(self):
        """
        Test creating multiple Interfaces
        """
        config = self.create_interface_mulitple()
        resp = config.get_json()
        expected_json = ("{'interfaceEntity': {'attributes': {}, 'children'"
                         ": [{'l1PhysIf': {'attributes': {'layer': 'Layer2'"
                         ", 'duplex': 'auto', 'trunkLog': 'default', 'mtu':"
                         " '1500', 'linkLog': 'default', 'mode': 'access', "
                         "'snmpTrapSt': 'default', 'speed': '10G', 'id': 'e"
                         "th1/5'}, 'children': []}}, {'l1PhysIf': {'attribu"
                         "tes': {'layer': 'Layer3', 'duplex': 'auto', 'trun"
                         "kLog': 'default', 'mtu': '1500', 'linkLog': 'defa"
                         "ult', 'mode': 'access', 'snmpTrapSt': 'default', "
                         "'speed': '10G', 'id': 'eth1/8'}, 'children': []}}"
                         "]}}")
        self.assertEqual(str(resp), expected_json)
        
        
class TestConfigVrrps(unittest.TestCase):
    """
    Test the ConfigVrrps off line
    """
    def create_vrrps(self):
        """
        Create a VRRP object and configure the parameters
        """
        vrrp = ConfigVrrps()
        int = Interface('eth2/1')
        vrrp_int = Vrrp(int)
        vrrp_id = VrrpID('50')
        vrrp_id.set_primary('10.10.0.11')
        vrrp_id.set_secondary('10.10.0.12')
        
        vrrp_int.add_vrrp_id(vrrp_id)
        vrrp.add_vrrp(vrrp_int)
        return vrrp
    
    def test_create_vrrp(self):
        """
        Test creating vrrp
        """
        vrrp = self.create_vrrps()
        resp = vrrp.get_json()
        expected_resp = ("{'vrrpInst': {'attributes': {}, 'children': [{'vrrp"
                         "Interface': {'attributes': {'id': 'eth2/1'}, 'child"
                         "ren': [{'vrrpId': {'attributes': {'id': '50', 'prim"
                         "ary': '10.10.0.11'}, 'children': [{'vrrpSecondary':"
                         " {'attributes': {'secondary': '10.10.0.12'}}}]}}]}}"
                         "]}}")
        self.assertEqual(str(resp), expected_resp)        


class TestLacp(unittest.TestCase):
    """
    Test the LACP off line
    """
    def create_lacp(self):
        """
        Create an Interface object and confugure LACP in that interface
        """
        int = Interface('eth1/1')
        lacp = Lacp(rate='fast', interface=int)
        return lacp
    
    def test_create_lacp(self):
        """
        Test creating lacp
        """
        lacp = self.create_lacp()
        resp = lacp.get_json()
        expected_resp = ("{'lacpIf': {'attributes': {'txRate': 'fast', 'id': "
                         "'eth1/1'}, 'children': []}}")
        self.assertEqual(str(resp), expected_resp)


class TestIPV6(unittest.TestCase):
    """
    Test the IPV6 class offline
    """
    def create_ipv6(self):
        """
        Create two interface object and a port channel then configure 
        ipv6 in those interfaces and port channel
        """
        int1 = Interface('eth1/1')
        int2 = Interface('eth1/2')
        pc1 = PortChannel('211')
        ipv6 = IP('v6')
        ipv6.add_interface_address(int1, '2004:0DB8::1/10', link_local='FE83::1')
        ipv6.add_interface_address(int2, '2104:0DB8::1/11')
        ipv6.add_interface_address(int2, '2002:0DB8::1/12')
        ipv6.add_interface_address(pc1, '2022:0DB8::1/13')
        return ipv6  
    
    def test_config_ipv6(self):
        """
        Test configuring ipv6
        """
        ipv6 = self.create_ipv6()
        resp = ipv6.get_json()
        expected_resp = ("{'ipv6Dom': {'attributes': {'name': 'default'}, "
                         "'children': [{'ipv6If': {'attributes': {'id': 'e"
                         "th1/1'}, 'children': [{'ipv6Addr': {'attributes'"
                         ": {'addr': '2004:0DB8::1/10'}}}, {'ipv6LLaddr': "
                         "{'attributes': {'addr': 'FE83::1'}}}]}}, {'ipv6I"
                         "f': {'attributes': {'id': 'eth1/2'}, 'children':"
                         " [{'ipv6Addr': {'attributes': {'addr': '2104:0DB"
                         "8::1/11'}}}, {'ipv6Addr': {'attributes': {'addr'"
                         ": '2002:0DB8::1/12'}}}]}}, {'ipv6If': {'attribut"
                         "es': {'id': 'po211'}, 'children': [{'ipv6Addr': "
                         "{'attributes': {'addr': '2022:0DB8::1/13'}}}]}}]"
                         "}}")
        self.assertEqual(str(resp), expected_resp)  
    
    def test_get_delete_url(self):
        """
        Test delete url of ipv6
        """
        ipv6 = IP('v6')
        resp = ipv6.get_delete_url('eth1/1')
        expected_resp = '/api/node/mo/sys/ipv6/inst/dom-default/if-[eth1/1].json'
        self.assertEqual(str(resp), expected_resp)


class TestIPV6Route(unittest.TestCase):
    """
    This class defines the IPV6Route testing offline
    """
    def create_ipv6_route(self):
        """
        Create IPv6 route configure in the interfaces and port channel
        """
        # Create Interfaces
        int1 = Interface('eth1/1')
        int2 = Interface('eth1/2')
        # Create a L3 port channel
        pc1 = PortChannel('211', layer='Layer3')
        route = IPRoute('2000:0::0/12', 'v6')
        route.add_next_hop('234E:44::1', int1, vrf='default', track_id='0',
                           tag='1')
        route.add_next_hop('234E:44::2', int2)
        route.add_next_hop('234E:44::4', pc1, vrf='default', track_id='1',
                           tag='2')
        return route
    
    def test_ipv6_route(self):
        """
        Test configuring IPV6Route
        """
        route = self.create_ipv6_route()
        resp = route.get_json()
        expected_json = ("{'ipv6Route': {'attributes': {'prefix': '2000:0::"
                         "0/12'}, 'children': [{'ipv6Nexthop': {'attributes"
                         "': {'nhAddr': '234E:44::1', 'object': '0', 'tag':"
                         " '1', 'nhVrf': 'default', 'nhIf': 'eth1/1'}}}, {'"
                         "ipv6Nexthop': {'attributes': {'nhAddr': '234E:44:"
                         ":2', 'nhVrf': 'default', 'nhIf': 'eth1/2'}}}, {'i"
                         "pv6Nexthop': {'attributes': {'nhAddr': '234E:44::"
                         "4', 'object': '1', 'tag': '2', 'nhVrf': 'default'"
                         ", 'nhIf': 'po211'}}}]}}")
        self.assertEqual(str(resp), expected_json)


class TestIP(unittest.TestCase):
    """
    Test the IPV6 class offline
    """
    def create_ip(self):
        """
        Create two interface object and a port channel then configure 
        ipv in those interfaces and port channel
        """
        int1 = Interface('eth1/1')
        int2 = Interface('eth1/2')
        pc1 = PortChannel('211')
        
        # Create IPv4 instance
        ip = IP()
        
        # enable ip directed broadcast on the interface
        ip.enable_directed_broadcast(int1)
        
        # Add interfaces
        ip.add_interface_address(int1, '172.11.2.1/20')
        ip.add_interface_address(int2, '171.11.3.1/21')
    
        # Add port channel
        ip.add_interface_address(pc1, '172.11.4.4/13')

        return ip  
    
    def test_config_ip(self):
        """
        Test configuring ip
        """
        ip = self.create_ip()
        resp = ip.get_json()
        expected_resp = ("{'ipv4Dom': {'attributes': {'name': 'default'}, "
                         "'children': [{'ipv4If': {'attributes': {'id': 'e"
                         "th1/1'}, 'children': [{'ipv4Addr': {'attributes'"
                         ": {'addr': '172.11.2.1/20'}}}]}}, {'ipv4If': {'a"
                         "ttributes': {'id': 'eth1/2'}, 'children': [{'ipv"
                         "4Addr': {'attributes': {'addr': '171.11.3.1/21'}"
                         "}}]}}, {'ipv4If': {'attributes': {'id': 'po211'}"
                         ", 'children': [{'ipv4Addr': {'attributes': {'add"
                         "r': '172.11.4.4/13'}}}]}}]}}")
        self.assertEqual(str(resp), expected_resp)  
    
    def test_get_delete_url(self):
        """
        Test delete url of ip
        """
        ip = IP()
        resp = ip.get_delete_url('eth1/1')
        expected_resp = '/api/node/mo/sys/ipv4/inst/dom-default/if-[eth1/1].json'
        self.assertEqual(str(resp), expected_resp)


class TestIPRoute(unittest.TestCase):
    """
    This class defines the IPV6Route testing offline
    """
    def create_ip_route(self):
        """
        Create IPv6 route configure in the interfaces and port channel
        """
        # Create Interfaces
        int1 = Interface('eth1/20')
        int2 = Interface('eth1/21')
        # Create a L3 port channel
        pc1 = PortChannel('211', layer='Layer3')

        # Configure IPv4 route and Nexthop information
        r1 = IPRoute('1.1.1.1/32')
        r1.add_next_hop('2.2.2.2', int1, vrf='default', track_id='0', tag='1')
        r1.add_next_hop('3.3.3.3', int2)
        r1.add_next_hop('4.4.4.4', pc1, vrf='default', track_id='1', tag='2')
        
        return r1
    
    def test_ip_route(self):
        """
        Test configuring IPV6Route
        """
        route = self.create_ip_route()
        resp = route.get_json()
        expected_json = ("{'ipv4Route': {'attributes': {'prefix': '1.1.1.1/32"
                         "'}, 'children': [{'ipv4Nexthop': {'attributes': {'n"
                         "hAddr': '2.2.2.2', 'object': '0', 'tag': '1', 'nhVr"
                         "f': 'default', 'nhIf': 'eth1/20'}}}, {'ipv4Nexthop'"
                         ": {'attributes': {'nhAddr': '3.3.3.3', 'nhVrf': 'de"
                         "fault', 'nhIf': 'eth1/21'}}}, {'ipv4Nexthop': {'att"
                         "ributes': {'nhAddr': '4.4.4.4', 'object': '1', 'tag"
                         "': '2', 'nhVrf': 'default', 'nhIf': 'po211'}}}]}}")

        self.assertEqual(str(resp), expected_json)


class TestLFeature(unittest.TestCase):
    """
    This class tests the Feature class offline
    """
    def feature_status(self):
        """
        Create Feature object and enable bgp and disable dhcp
        """
        feature = Feature()
        feature.enable('bgp')
        feature.disable('dhcp')
        return feature
    
    def test_feature_status(self):
        """
        Test enable/disable Feature
        """
        feature = self.feature_status()
        resp = feature.get_json()
        expected_resp = ("{'fmEntity': {'attributes': {}, 'children': [{'fmBg"
                         "p': {'attributes': {'adminSt': 'enabled'}}}, {'fmDh"
                         "cp': {'attributes': {'adminSt': 'disabled'}}}]}}")
        self.assertEqual(str(resp), expected_resp)
        

class TestDhcp(unittest.TestCase):
    """
    Test the DHCP class offline
    """
    def configure_dhcp(self):
        """
        Configure dhcp 
        """
        dhcp = Dhcp()
        dhcp.set_v4relay_st('yes')
        dhcp.set_v6relay_st('no')
    
        relay = DhcpRelay('eth2/1')
        relay.add_relay_address('1.1.1.2')
        relay.add_relay_address('23ad:33::fd2', 'test_vrf_name')
        dhcp.add_relay(relay)  
        return dhcp
    
    def test_configure_dhcp(self):
        """
        Test to configure DHCP
        """
        dhcp = self.configure_dhcp()
        resp = dhcp.get_json()
        expected_resp = ("{'dhcpInst': {'attributes': {'v6RelayEnabled': 'no'"
                         ", 'v4RelayEnabled': 'yes'}, 'children': [{'dhcpRela"
                         "yIf': {'attributes': {'id': 'eth2/1'}, 'children': "
                         "[{'dhcpRelayAddr': {'attributes': {'vrf': '!unspeci"
                         "fied', 'address': '1.1.1.2'}}}, {'dhcpRelayAddr': {"
                         "'attributes': {'vrf': 'test_vrf_name', 'address': '"
                         "23ad:33::fd2'}}}]}}]}}")
        self.assertEqual(str(resp), expected_resp)
        

class TestBootNxos(unittest.TestCase):
    """
    Test the BootNxos class offline
    """
    def configure_boot_image(self):
        """
        Create a BootNxos object offline
        """
        boot = BootNxos('n9000-dk9.7.0.3.I2.0.551')
        return boot
    
    def test_configure_boot(self):
        """
        Test to set boot variable
        """
        boot = self.configure_boot_image()
        resp = boot.get_json()
        expected_resp = ("{'bootBoot': {'attributes': {}, 'children': [{'boot"
                         "Image': {'attributes': {'sup1': 'bootflash:/n9000-d"
                         "k9.7.0.3.I2.0.551.bin', 'sup2': 'bootflash:/n9000-d"
                         "k9.7.0.3.I2.0.551.bin'}}}]}}")
        self.assertEqual(str(resp), expected_resp)


class TestCopy(unittest.TestCase):
    """
    Class to test the copy task offline
    """
    def copy_running_to_startup(self):
        copy = Copy()
        run_to_start = RunningToStartUp()
        copy.add(run_to_start)
        return copy
    
    def test_copy_running_to_startup(self):
        """
        Test copy running-config to startup-config
        """
        copy = self.copy()
        resp = copy.get_json()
        expected_resp = ("{'actionLSubj': {'attributes': {'dn': 'sys/action/"
                         "lsubj-[sys]'}, 'children': [{'topSystemCopyRSLTask"
                         "': {'attributes': {'freq': 'one-shot', 'adminSt': "
                         "'start'}}}]}}")
        self.assertEqual(str(resp), expected_resp)


class TestRunningToStartUp(unittest.TestCase):
    """
    Test the RunningToStartUp class
    """
    def test_running_to_startup(self):
        """
        Test creating RunningToStartUp
        """
        r_s = RunningToStartUp()
        resp = r_s.get_json()
        expected_resp = ("{'topSystemCopyRSLTask': {'attributes': {'freq'"
                         ": 'one-shot', 'adminSt': 'start'}}}")
        self.assertEqual(str(resp), expected_resp)


class TestDns(unittest.TestCase):
    """
    Test the DNS class offline
    """
    def create_dns(self):
        """
        Create a DNS object and add other typr of dns objects
        """
        dns = DNS()
        dns.enable_lookup()
    
        prof1 = DnsProfile()
    
        dns_provider = DnsProvider('1.1.1.1')
        prof1.add(dns_provider)
    
        dns_domain = DnsDom('name')
        prof1.add(dns_domain)
    
        dns_dmn_ext = DnsDomExt('name1')
        prof1.add(dns_dmn_ext)
    
        dns_host = DnsHost('name2', '1:1::12')
        prof1.add(dns_host)
    
        vrf1 = DnsVrf('test_vrf1')
        vrf2 = DnsVrf('test_vrf2')
    
        vrf1.use_in(dns_provider)
        vrf2.use_in(dns_dmn_ext)
    
        prof1.add(vrf1)
        prof1.add(vrf2)
    
        dns.add_profile(prof1)
        return dns
    
    def test_create_dns(self):
        """
        Test creating DNS
        """
        dns = self.create_dns()
        resp = dns.get_json()
        expected_resp = ("{'dnsEntity': {'attributes': {'adminSt': 'enabled'}"
                         ", 'children': [{'dnsProf': {'attributes': {'name': "
                         "'default'}, 'children': [{'dnsProvider': {'attribut"
                         "es': {'addr': '1.1.1.1'}, 'children': []}}, {'dnsDo"
                         "m': {'attributes': {'name': 'name'}, 'children': []"
                         "}}, {'dnsDomExt': {'attributes': {'name': 'name1'},"
                         " 'children': []}}, {'dnsHost': {'attributes': {'nam"
                         "e': 'name2'}, 'children': [{'dnsIpv6Host': {'attrib"
                         "utes': {'addr': '1:1::12'}}}]}}, {'dnsVrf': {'attri"
                         "butes': {'name': 'test_vrf1'}, 'children': [{'dnsPr"
                         "ovider': {'attributes': {'addr': '1.1.1.1'}, 'child"
                         "ren': []}}]}}, {'dnsVrf': {'attributes': {'name': '"
                         "test_vrf2'}, 'children': [{'dnsDomExt': {'attribute"
                         "s': {'name': 'name1'}, 'children': []}}]}}]}}]}}")
        self.assertEqual(str(resp), expected_resp)
        
        
class TestDnsVrf(unittest.TestCase):
    """
    Test the DnsVrf class offline
    """       
    def create_vrf(self):
        """
        Create a DnsVrf and configure it
        """
        vrf = DnsVrf('test_vrf1')
        vrf.set_profile('test_profile')
        
        dns_provider = DnsProvider('1.1.1.1')
        dns_domain = DnsDom('name')
        dns_dmn_ext = DnsDomExt('name1')
        
        vrf.use_in(dns_provider)
        vrf.use_in(dns_domain)
        vrf.use_in(dns_dmn_ext)
        
        return vrf
    
    def test_create_vrf(self):
        """
        Test creating DnsVrf
        """
        vrf = self.create_vrf()
        resp = vrf.get_json()
        expected_resp = ("{'dnsVrf': {'attributes': {'name': 'test_vrf1'}, 'c"
                         "hildren': [{'dnsProvider': {'attributes': {'addr': "
                         "'1.1.1.1'}, 'children': []}}, {'dnsDom': {'attribut"
                         "es': {'name': 'name'}, 'children': []}}, {'dnsDomEx"
                         "t': {'attributes': {'name': 'name1'}, 'children': ["
                         "]}}]}}")
        self.assertEqual(str(resp), expected_resp)
        

class TestIcmp(unittest.TestCase):
    """
    Test the Icmp offline
    """
    def create_icmpv4(self):
        """configure icmp on an interface """
        int1 = Interface('eth1/20')
        icmp = ICMP('v4', int1, "redirect")
        return icmp
    
    def test_config_icmpv4(self):
        """
        Test configuring IcmpV4
        """
        icmp = self.create_icmpv4()
        resp = icmp.get_json()
        expected_resp = ("{'icmpv4If': {'attributes': {'ctrl': 'redirect'}, '"
                         "children': []}}")
        self.assertEqual(str(resp), expected_resp)
        
    def create_icmpv6(self):
        """
        Create a IcmpV6 used as setup for test cases
        """
        int1 = Interface('eth1/20')
        icmp = ICMP('v6', int1, "redirect")
        return icmp
        
    def test_config_icmpv6(self):
        """
        Test configuring IcmpV6
        """
        icmp = self.create_icmpv6()
        resp = icmp.get_json()
        expected_resp = ("{'icmpv6If': {'attributes': {'ctrl': 'redirect'}, '"
                         "children': []}}")
        self.assertEqual(str(resp), expected_resp)        


class TestSTP(unittest.TestCase):
    """
    Test the STP class offline
    """       
    def create_stp(self):
        """
        Create a Stp and configure it
        """
        stp = STP()
        stp.set_mode('pvrst')
    
        stp.add_port_type('bpdufilter')
        stp.add_port_type('bpduguard')
        stp.add_port_type('edge')
        stp.add_port_type('network')
    
        mst_etity = StpMst()
        mst_etity.set_simulate('disabled')
    
        vlan = StpVlan('222')
        vlan.set_admin_st('enabled')
        vlan.set_bdg_priority('12288')
    
        int = Interface('eth1/1')
        i_face = StpInterface(int)
        # Mode can be set to network/edge/normal only for l2 interface
        i_face.set_mode('network')
    
        stp.add(mst_etity)
        stp.add(vlan)
        stp.add(i_face)
        return stp
    
    def test_create_stp(self):
        """
        Test creating stp
        """
        stp = self.create_stp()
        resp = stp.get_json()
        expected_resp = ("{'stpInst': {'attributes': {'mode': 'pvrst', 'ctrl'"
                         ": 'normal,extchp-bpdu-filter,extchp-bpdu-guard,netw"
                         "ork'}, 'children': [{'stpMstEntity': {'attributes':"
                         " {'simulate': 'disabled'}, 'children': []}}, {'stpV"
                         "lan': {'attributes': {'bridgePriority': '12510', 'i"
                         "d': '222', 'adminSt': 'enabled'}, 'children': []}},"
                         " {'stpIf': {'attributes': {'id': 'eth1/1', 'mode': "
                         "'network'}, 'children': []}}]}}")
        self.assertEqual(str(resp), expected_resp)


class TestUdld(unittest.TestCase):
    """
    Test the udld class offline
    """       
    def create_udld(self):
        """
        Create a Udld and configure it
        """
        udld = UDLD()
        int = Interface('eth1/2')
    
        udld.enable_aggress()
        udld.disable_aggress(int)
        return udld
    
    def test_create_udld(self):
        """
        Test creating udld
        """
        udld = self.create_udld()
        resp = udld.get_json()
        expected_resp = ("{'udldInst': {'attributes': {'aggressive': 'enabled"
                         "'}, 'children': [{'udldPhysIf': {'attributes': {'ag"
                         "gressive': 'disabled', 'id': 'eth1/2'}}}]}}")
        self.assertEqual(str(resp), expected_resp)
        
        
class TestArp(unittest.TestCase):
    """
    Test the arp class offline
    """
    def create_arp(self):
        """
        Create arp and configure it
        """
        arp = ARP() 
        arp.set_timeout('100')
        return arp
    
    def test_create_arp(self):
        """
        Test creating arp
        """
        arp = self.create_arp()
        resp = arp.get_json()
        expected_resp = ("{'arpInst': {'attributes': {'timeout': '100'}, 'chi"
                         "ldren': []}}")
        self.assertEqual(str(resp), expected_resp)        


class TestRBAC(unittest.TestCase):
    """
    Test the Route Based Access Control class offline
    """
    def create_rbac(self):
        """
        create rbac and configure it
        """
        rbac = RBAC()
        rbac.create_role('test-role')
        rbac.enable_pwd_strength_check()
        rbac.enable_pwd_secure_mode()
        rbac.set_pwd_max_length('127')
        rbac.set_pwd_min_length('4')
        
        user = AaaUser(name='test1', password='Test1',role='network-admin',
                      ssh_key='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDczcGut'
                      'F5w331l0bNAeDSqKmwzLYYjElGIEogIE04rE0kX+CaWP/nDVEwETT'
                      'sKlp5w4gi0mA9/4kpk7gDGRCmAiNT8MWaTYt4ewGj+dZ+fbpUUf5t'
                      'v1DwLvxcQOoQ3qvxazOQWOLxwSW7zrJBpSokEtDNyY6BlsXP33q2h'
                      'gOBeAw==')
        
        rad_server = AaaRadius()
        rad_server.set_retries('4')
        rad_server.set_timeout('30')
        rad_server.set_src_interface('lo0')
        rad_server.set_key(key='cisco', key_enc='7')
        rad_server.add_host('1.2.3.4', key='cisco', key_enc='7', 
                            timeout='5',retries='3')
        
        tacacs = AaaTacacs()
        tacacs.set_deadtime('10')
        tacacs.set_timeout('20')
        tacacs.set_src_interface('mgmt 0')
        tacacs.set_key(key='cisco', key_enc='7')
        tacacs.add_host('1.2.3.3', key='cisco', key_enc='7', port='50', 
                        timeout='30')
        tacacs.add_group('tac1', vrf='management', deadtime='10', 
                         server='1.2.3.3')
        
        aaa = AaaAaa()
        aaa.disable_auth_login('error-enable')
        aaa.enable_auth_login('ascii-authentication')
        aaa.set_auth_default_grp('tac1') #pass default group name
        aaa.set_author_default_grp() #pass default group name and cmd type(cmd type will be exec by default)
        aaa.set_acc_default_grp('tac1') #pass default group name
        
        rbac.add(user)
        rbac.add(rad_server)
        rbac.add(tacacs)
        rbac.add(aaa)
        return rbac
    
    def test_create_rbac(self):
        """ Test creating rbac """
        rbac = self.create_rbac()
        resp = rbac.get_json()
        expected_resp = ("{'aaaUserEp': {'attributes': {'pwdStrengthCheck': '"
                         "yes', 'pwdMinLength': '4', 'pwdMaxLength': '127', '"
                         "pwdSecureMode': 'yes'}, 'children': [{'aaaRole': {'"
                         "attributes': {'name': 'test-role'}, 'children': []}"
                         "}, {'aaaUser': {'attributes': {'pwd': 'Test1', 'nam"
                         "e': 'test1', 'pwdSet': 'yes'}, 'children': [{'aaaSs"
                         "hAuth': {'attributes': {'data': 'ssh-rsa AAAAB3NzaC"
                         "1yc2EAAAADAQABAAAAgQDczcGutF5w331l0bNAeDSqKmwzLYYjE"
                         "lGIEogIE04rE0kX+CaWP/nDVEwETTsKlp5w4gi0mA9/4kpk7gDG"
                         "RCmAiNT8MWaTYt4ewGj+dZ+fbpUUf5tv1DwLvxcQOoQ3qvxazOQ"
                         "WOLxwSW7zrJBpSokEtDNyY6BlsXP33q2hgOBeAw=='}}}, {'aa"
                         "aUserDomain': {'attributes': {'dn': 'sys/userext/us"
                         "er-test1/userdomain-all', 'name': 'all'}, 'children"
                         "': [{'aaaUserRole': {'attributes': {'name': 'networ"
                         "k-admin'}}}]}}]}}, {'aaaRadiusEp': {'attributes': {"
                         "'retries': '4', 'timeout': '30', 'keyEnc': '7', 'ke"
                         "y': 'cisco', 'srcIf': 'lo0'}, 'children': [{'aaaRad"
                         "iusProvider': {'attributes': {'retries': '3', 'time"
                         "out': '5', 'name': '1.2.3.4', 'key': 'cisco', 'keyE"
                         "nc': '7'}, 'children': []}}]}}, {'aaaTacacsPlusEp':"
                         " {'attributes': {'timeout': '20', 'deadtime': '10',"
                         " 'keyEnc': '7', 'key': 'cisco', 'srcIf': 'mgmt 0'},"
                         " 'children': [{'aaaTacacsPlusProvider': {'attribute"
                         "s': {'port': '50', 'timeout': '30', 'name': '1.2.3."
                         "3', 'key': 'cisco', 'keyEnc': '7'}, 'children': []}"
                         "}, {'aaaTacacsPlusProviderGroup': {'attributes': {'"
                         "deadtime': '10', 'name': 'tac1', 'vrf': 'management"
                         "'}, 'children': [{'aaaProviderRef': {'attributes': "
                         "{'name': '1.2.3.3'}, 'children': []}}]}}]}}, {'aaaA"
                         "uthRealm': {'attributes': {}, 'children': [{'aaaDef"
                         "aultAuth': {'attributes': {'providerGroup': 'tac1',"
                         " 'errEn': 'no', 'authProtocol': 'ascii'}}}, {'aaaDe"
                         "faultAuthor': {'attributes': {'providerGroup': '', "
                         "'cmdType': 'exec'}}}, {'aaaDefaultAcc': {'attribute"
                         "s': {'providerGroup': 'tac1'}}}]}}]}}")
        self.assertEqual(str(resp), expected_resp)
        
        
class TestND(unittest.TestCase):
    """
    Test the Neighbor Discovery class offline
    """
    def create_nd(self):
        """
        create nd and configure it
        """
        nd = ND()
        nd_int = NdInterface('vlan123')
        nd_int.disable_redirect()
        nd_int.set_ra_interval('600')
        nd_int.set_prefix('2000::/12', '100', '99')
        nd.add(nd_int)
        return nd
    
    def test_create_nd(self):
        """ Test creating neighbor discovery """
        nd = self.create_nd()
        resp = nd.get_json()
        expected_resp = ("{'ndDom': {'attributes': {}, 'children': [{'ndIf': "
                         "{'attributes': {'raIntvl': '600', 'id': 'vlan123', "
                         "'ctrl': ''}, 'children': [{'ndPfx': {'attributes': "
                         "{'lifetime': '100', 'addr': '2000::/12', 'prefLifet"
                         "ime': '99'}, 'children': []}}]}}]}}")
        self.assertEqual(str(resp), expected_resp)
        
        
class TestRPM(unittest.TestCase):
    """
    Test the Route Processor Module class offline
    """
    def create_rpm(self):
        """
        create rpm and configure it
        """
        rpm = RPM()       
        route_map = RouteMap('Test_route_map')     
        map_entry = RouteMapEntry('permit', '10')
        map_entry.set_descr('This is test route-map')
        map_entry.match_rt_type('local')     
        map_entry.match_rt_tag('200')        
        map_entry.disable_nh_peer('v4')  
        map_entry.set_next_hop('10.10.10.10') 
        map_entry.set_next_hop('10:20::30:40')
        map_entry.set_local_pref('1000')            
        map_entry.set_origin('incomplete')            
        map_entry.set_comm_list('test-community', 'delete')     
        map_entry.match_as_path('test-access-list')
        map_entry.match_pfxlistv4('test-prefix-v4')
        map_entry.match_pfxlistv6('test-prefix-v6')
        map_entry.match_comm('test-community', 'exact')
        map_entry.set_comm('additive,internet,local-AS,no-advertise,no-export,1:2')
    
        route_map.add(map_entry)
    
        pfx_v4 = PrefixList('test_prefix')
        pfx_v4.set_prefix(pfx_addr='1.2.3.4/8', action='permit', seq_no='10')
    
        pfx_v6 = PrefixList('test_prefix', 'v6')
        pfx_v6.set_prefix(pfx_addr='ffff:1::2:3/8', action='permit', seq_no='10')
    
        as_path = AsPath('testAccList')
        as_path.set_access_list('permit', '1234')
    
        comm = CommunityList('comrule', 'standard')
        comm_entry = CommunityEntry('permit', 'internet,local-AS,no-advertise,no-export,1:2', '5')
        comm.add(comm_entry)
    
        rpm.add(route_map)
        rpm.add(pfx_v4)
        rpm.add(pfx_v6)
        rpm.add(as_path)
        rpm.add(comm) 
        
        return rpm
    
    def test_create_rpm(self):
        """ Test creating rpm """
        rpm = self.create_rpm()
        resp = rpm.get_json()
        expected_resp = ("{'rpmEntity': {'attributes': {}, 'children': [{'rtm"
                         "apRule': {'attributes': {'name': 'Test_route_map'},"
                         " 'children': [{'rtmapEntry': {'attributes': {'actio"
                         "n': 'permit', 'order': '10', 'descr': 'This is test"
                         " route-map'}, 'children': [{'rtmapMatchRtType': {'a"
                         "ttributes': {'routeT': 'local'}, 'children': []}}, "
                         "{'rtmapMatchRtTag': {'attributes': {'tag': '200'}, "
                         "'children': []}}, {'rtmapSetNhPeerAddr': {'attribut"
                         "es': {'v4PeerAddr': 'disabled'}, 'children': []}}, "
                         "{'rtmapSetNh': {'attributes': {'addr': '10.10.10.10"
                         "'}, 'children': []}}, {'rtmapSetNh': {'attributes':"
                         " {'addr': '10:20::30:40'}, 'children': []}}, {'rtma"
                         "pSetPref': {'attributes': {'localPref': '1000'}, 'c"
                         "hildren': []}}, {'rtmapSetOrigin': {'attributes': {"
                         "'originT': 'incomplete'}, 'children': []}}, {'rtmap"
                         "SetCommList': {'attributes': {'name': 'test-communi"
                         "ty', 'delete': 'enabled'}, 'children': []}}, {'rtma"
                         "pMatchAsPathAccessList': {'attributes': {}, 'childr"
                         "en': [{'rtmapRsRtAsPathAccAtt': {'attributes': {'tD"
                         "n': 'sys/rpm/accesslist-test-access-list'}, 'childr"
                         "en': []}}]}}, {'rtmapMatchRtDst': {'attributes': {}"
                         ", 'children': [{'rtmapRsRtDstAtt': {'attributes': {"
                         "'tDn': 'sys/rpm/pfxlistv4-test-prefix-v4'}, 'childr"
                         "en': []}}]}}, {'rtmapMatchRtDstV6': {'attributes': "
                         "{}, 'children': [{'rtmapRsRtDstV6Att': {'attributes"
                         "': {'tDn': 'sys/rpm/pfxlistv6-test-prefix-v6'}, 'ch"
                         "ildren': []}}]}}, {'rtmapMatchRegComm': {'attribute"
                         "s': {'criteria': 'exact'}, 'children': [{'rtmapRsRe"
                         "gCommAtt': {'attributes': {'tDn': 'sys/rpm/rtregcom"
                         "-test-community'}, 'children': []}}]}}, {'rtmapSetR"
                         "egComm': {'attributes': {'additive': 'enabled'}, 'c"
                         "hildren': [{'rtregcomItem': {'attributes': {'commun"
                         "ity': 'regular:as2-nn2:0:0'}, 'children': []}}, {'r"
                         "tregcomItem': {'attributes': {'community': 'regular"
                         ":as2-nn2:65535:65283'}, 'children': []}}, {'rtregco"
                         "mItem': {'attributes': {'community': 'regular:as2-n"
                         "n2:65535:65282'}, 'children': []}}, {'rtregcomItem'"
                         ": {'attributes': {'community': 'regular:as2-nn2:655"
                         "35:65281'}, 'children': []}}, {'rtregcomItem': {'at"
                         "tributes': {'community': 'regular:as2-nn2:1:2'}, 'c"
                         "hildren': []}}]}}]}}]}}, {'rtpfxRuleV4': {'attribut"
                         "es': {'name': 'test_prefix'}, 'children': [{'rtpfxE"
                         "ntry': {'attributes': {'action': 'permit', 'pfx': '"
                         "1.2.3.4/8', 'order': '10'}, 'children': []}}]}}, {'"
                         "rtpfxRuleV6': {'attributes': {'name': 'test_prefix'"
                         "}, 'children': [{'rtpfxEntry': {'attributes': {'act"
                         "ion': 'permit', 'pfx': 'ffff:1::2:3/8', 'order': '1"
                         "0'}, 'children': []}}]}}, {'rtlistRule': {'attribut"
                         "es': {'name': 'testAccList'}, 'children': [{'rtlist"
                         "Entry': {'attributes': {'action': 'permit', 'regex'"
                         ": '1234', 'order': '1'}, 'children': []}}]}}, {'rtr"
                         "egcomRule': {'attributes': {'name': 'comrule', 'mod"
                         "e': 'standard'}, 'children': [{'rtregcomEntry': {'a"
                         "ttributes': {'action': 'permit', 'order': '5'}, 'ch"
                         "ildren': [{'rtregcomItem': {'attributes': {'communi"
                         "ty': 'regular:as2-nn2:0:0'}, 'children': []}}, {'rt"
                         "regcomItem': {'attributes': {'community': 'regular:"
                         "as2-nn2:65535:65283'}, 'children': []}}, {'rtregcom"
                         "Item': {'attributes': {'community': 'regular:as2-nn"
                         "2:65535:65282'}, 'children': []}}, {'rtregcomItem':"
                         " {'attributes': {'community': 'regular:as2-nn2:6553"
                         "5:65281'}, 'children': []}}, {'rtregcomItem': {'att"
                         "ributes': {'community': 'regular:as2-nn2:1:2'}, 'ch"
                         "ildren': []}}]}}]}}]}}")
        self.assertEqual(str(resp), expected_resp)
        
        
class TestLiveSwitch(unittest.TestCase):
    """
    Test with a live Switch
    """
    def login_to_switch(self):
        """Login to the Switch
           RETURNS:  Instance of class Session
        """
        session = Session(URL, LOGIN, PASSWORD)
        resp = session.login()
        self.assertTrue(resp.ok)
        return session


class TestLivePortChannel(TestLiveSwitch):
    """ This class defines live testing of port channel """
    def test_get_all_portchannels(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, PortChannel.get, None)
        portchannels = PortChannel.get(session)
        for pc in portchannels:
            self.assertTrue(isinstance(pc, PortChannel))
            pc_as_a_string = str(pc)
            self.assertTrue(isinstance(pc_as_a_string, str))


class TestLiveLinkNeighbors(TestLiveSwitch):
    """ This class defines live testing of link neighbors """
    def test_get_allneighbors(self):
        session = self.login_to_switch()
        neighbors = LinkNeighbors.get(session)
        for neighbor in neighbors:
            self.assertTrue(isinstance(neighbor, LinkNeighbors))
            neighbor_string = str(neighbor)
            self.assertTrue(isinstance(neighbor_string, str))


class TestLiveHardware(TestLiveSwitch):
    """ This class defines live testing of hardware """
    def test_get_hardware(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, Hardware.get, None)
        hardwares = Hardware.get(session)
        self.assertTrue(isinstance(hardwares, Hardware))   


class TestLiveHardwareInternal(TestLiveSwitch):
    """ This class defines live testing of hardware internal """
    def test_get_hardware_internal(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, HardwareInternal.get, None)
        hardware_internal = HardwareInternal(session)  
        self.assertTrue(isinstance(hardware_internal, HardwareInternal))

        
class TestLiveLogTimeStamp(TestLiveSwitch):
    """ This class defines live testing of logging timestamp """
    def test_get_log_timestamp(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, LogTimeStamp.get, None)
        timestamp = LogTimeStamp(session)
        self.assertTrue(isinstance(timestamp, LogTimeStamp)) 

        
class TestLiveLogMonitor(TestLiveSwitch):
    """ This class defines live testing of logging monitor """ 
    def test_get_log_monitor(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, LogMonitor.get, None)
        monitor = LogMonitor(session)
        self.assertTrue(isinstance(monitor, LogMonitor))          

        
class TestLiveLogConsole(TestLiveSwitch): 
    """ This class defines live testing logging console """
    def test_get_log_console(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, LogConsole.get, None)
        console = LogConsole(session)
        self.assertTrue(isinstance(console, LogConsole))   

        
class TestLiveLogServer(TestLiveSwitch):  
    """ This class defines live testing of logging server """
    def test_get_log_server(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, LogServer.get, None)
        server = LogServer(session)
        self.assertTrue(isinstance(server, LogServer))  


class TestLiveLogSourceInterface(TestLiveSwitch):  
    """ This class defines live testing of logging source interface """
    def test_get_log_source_interface(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, LogSourceInterface.get, None)
        src_interface = LogSourceInterface(session)
        self.assertTrue(isinstance(src_interface, LogSourceInterface))  
   
        
class TestLiveLogLevel(TestLiveSwitch):  
    """ This class defines live testing of logging level """
    def test_get_log_level(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, LogLevel.get, None)
        level = LogLevel(session)
        self.assertTrue(isinstance(level, LogLevel))                                     


class TestLiveInterfaceBreakout(TestLiveSwitch):
    """ This class defines live testing of interface breakout """
    def test_get_interface_break(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, InterfaceBreakout.get, None)
        level = InterfaceBreakout(session)
        self.assertTrue(isinstance(level, InterfaceBreakout))  


class TestLiveBreakoutModule(TestLiveSwitch):
    """ This class defines live testing of breakout module """
    def test_get_breakout_module(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, BreakoutModule.get, None)
        level = BreakoutModule('1', session=session)
        self.assertTrue(isinstance(level, BreakoutModule))


class TestLiveSVI(TestLiveSwitch):
    """ This class defines live testing of svi """
    def test_get_svi(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, SVI.get, None)
        level = SVI('vlan10', 'up', 'Sample Test')
        self.assertTrue(isinstance(level, SVI))


class TestLiveInterface(TestLiveSwitch):
    """ This class defines live testing of interface """
    def test_get_interface(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, Interface.get, None)
        i_face = Interface('eth1/5')
        self.assertTrue(isinstance(i_face, Interface))
        
        
class TestLiveConfigVrrps(TestLiveSwitch):
    """ This class defines live testing of vrrps """
    def test_get_vrrps(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, ConfigVrrps.get, None)
        config_vrrp = ConfigVrrps(session)
        self.assertTrue(isinstance(config_vrrp, ConfigVrrps))


class TestLiveVrrp(TestLiveSwitch):
    """ This class defines live testing of vrrp """
    def test_get_vrrp(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, Vrrp.get, None)
        vrrp = Vrrp(session)
        self.assertTrue(isinstance(vrrp, Vrrp))
      
        
class TestLiveLacp(TestLiveSwitch):
    """ This class defines live testing of lacp """
    def test_get_lacp(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, Lacp.get, None)
        lacp = Lacp(session)
        self.assertTrue(isinstance(lacp, Lacp))


class TestLiveIPV6(TestLiveSwitch):
    """ This class defines live testing of ipv6 """
    def test_get_ipv6(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, IP.get, None)
        ipv6 = IP(version='v6', session=session)
        self.assertTrue(isinstance(ipv6, IP))


class TestLiveIP(TestLiveSwitch):
    """ This class defines live testing of ipv6 """
    def test_get_ipv4(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, IP.get, None)
        ipv6 = IP(session=session)
        self.assertTrue(isinstance(ipv6, IP))
        
        
class TestLiveFeature(TestLiveSwitch):
    """ This class defines live testing of feature """
    def test_get_feature(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, Feature.get, None)
        feature = Feature(session=session)
        self.assertTrue(isinstance(feature, Feature))


class TestLiveFeatureAttributes(TestLiveSwitch):
    """ This class defines live testing of feature attributes """
    def test_feature_attributes(self):
        session = self.login_to_switch()
        feature_attributes = FeatureAttributes(session=session)
        self.assertTrue(isinstance(feature_attributes, FeatureAttributes))
 
         
class TestLiveDhcp(TestLiveSwitch):
    """ This class defines live testing of dhcp """
    def test_get_dhcp(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, Dhcp.get, None)
        dhcp = Dhcp(session)
        self.assertTrue(isinstance(dhcp, Dhcp))
        
        
class TestLiveDhcpRelay(TestLiveSwitch):
    """ This class defines live testing of dhcp relay """
    def test_dhcp_relay(self):
        session = self.login_to_switch()
        dhcp_relay = DhcpRelay(session)
        self.assertTrue(isinstance(dhcp_relay, DhcpRelay))


class TestLiveBootNxos(TestLiveSwitch):
    """ This class defines live testing of boot nxos """
    def test_get_boot_nxos(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, BootNxos.get, None)
        boot = BootNxos('fake_image.bin', session)
        self.assertTrue(isinstance(boot, BootNxos))


class TestLiveCopy(TestLiveSwitch):
    """ This class defines live testing of copy """
    def test_get_Copy(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, Copy.get, None)
        copy = Copy(session=session)
        self.assertTrue(isinstance(copy, Copy))


class TestLiveDns(TestLiveSwitch):
    """ This class defines live testing of dns """
    def test_get_dns(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, DNS.get, None)
        dns = DNS(session)
        self.assertTrue(isinstance(dns, DNS))  


class TestLiveDnsProfile(TestLiveSwitch):
    """ This class defines live testing of dns profile """
    def test_dns_profile(self):
        session = self.login_to_switch()
        dns_prof = DnsProfile(session)
        self.assertTrue(isinstance(dns_prof, DnsProfile)) 
        
        
class TestLiveDnsHost(TestLiveSwitch):
    """ This class defines live testing of dns host """
    def test_dns_host(self):
        session = self.login_to_switch()
        dns_host = DnsHost('test_host', '1.1.1.1', session)
        self.assertTrue(isinstance(dns_host, DnsHost)) 
        

class TestLiveDnsDom(TestLiveSwitch):
    """ This class defines live testing of dns dom """
    def test_dns_dom(self):
        session = self.login_to_switch()
        dns_dom = DnsDom('test_name', session)
        self.assertTrue(isinstance(dns_dom, DnsDom))     


class TestLiveDnsDomExt(TestLiveSwitch):
    """ This class defines live testing of dns dom ext """
    def test_dns_dom_ext(self):
        session = self.login_to_switch()
        dns_dom_ext = DnsDomExt('test_name', session)
        self.assertTrue(isinstance(dns_dom_ext, DnsDomExt))


class TestLiveDnsProvider(TestLiveSwitch):
    """ This class defines live testing of dns provider """
    def test_dns_provider(self):
        session = self.login_to_switch()
        dns_provider = DnsProvider('1.1.1.2', session)
        self.assertTrue(isinstance(dns_provider, DnsProvider)) 
        

class TestLiveDnsVrf(TestLiveSwitch):
    """ This class defines live testing of dns vrf """
    def test_dns_vrf(self):
        session = self.login_to_switch()
        dns_vrf = DnsVrf('test_name', session)
        self.assertTrue(isinstance(dns_vrf, DnsVrf))  
        

class TestLiveIcmp(TestLiveSwitch):
    """ This class defines live testing of icmp """
    def test_get_icmp(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, ICMP.get, None)
        icmp = ICMP('v4', 'eth2/1', session)
        self.assertTrue(isinstance(icmp, ICMP))                   


class TestLiveUdld(TestLiveSwitch):
    """ This class defines live testing of udld """
    def test_get_udld(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, UDLD.get, None)
        udld = UDLD(session=session)
        self.assertTrue(isinstance(udld, UDLD))           
    

class TestLiveSTP(TestLiveSwitch):
    """ This class defines live testing of stp """
    def test_get_stp(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, STP.get, None)
        stp = STP(session=session)
        self.assertTrue(isinstance(stp, STP))  


class TestLiveStpInterface(TestLiveSwitch):
    """ This class defines live testing of stp interface """
    def test_stp_interface(self):
        session = self.login_to_switch()
        stp_int = StpInterface('eth1/1', session=session)
        self.assertTrue(isinstance(stp_int, StpInterface))    
        
        
class TestLiveStpVlan(TestLiveSwitch):
    """ This class defines live testing of stp vlan """
    def test_stp_vlan(self):
        session = self.login_to_switch()
        stp_vlan = StpVlan('1', session=session)
        self.assertTrue(isinstance(stp_vlan, StpVlan))
        
        
class TestLiveStpMst(TestLiveSwitch):
    """ This class defines live testing of stp mst """
    def test_stp_mst(self):
        session = self.login_to_switch()
        stp_mst = StpMst(session=session)
        self.assertTrue(isinstance(stp_mst, StpMst))
        
        
class TestLiveARP(TestLiveSwitch):
    """ This class defines live testing of arp """
    def test_get_arp(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, ARP.get, None)
        arp = ARP(session=session)
        self.assertTrue(isinstance(arp, ARP))
        

class TestLiveAaaRole(TestLiveSwitch):
    """ This class defines live testing of aaarole """
    def test_role(self):
        session = self.login_to_switch()
        role = AaaRole('test-role', session=session)
        self.assertTrue(isinstance(role, AaaRole))
        
        
class TestLiveAaaUserRole(TestLiveSwitch):
    """ This class defines live testing of user role """
    def test_user_role(self):
        session = self.login_to_switch()
        user_role = AaaUserRole('test1', 'network-admin', 
                                session=session)
        self.assertTrue(isinstance(user_role, AaaUserRole)) 
        
        
class TestLiveAaaUser(TestLiveSwitch):
    """ This class defines live testing of user """
    def test_get_user(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, AaaUser.get, None)
        user = AaaUser('test1', session=session)
        self.assertTrue(isinstance(user, AaaUser)) 
        

class TestLiveAaaRadiusProvider(TestLiveSwitch):
    """ This class defines live testing of radius provider """
    def test_radius_provider(self):
        session = self.login_to_switch()
        rad_provider = AaaRadiusProvider('1.2.3.4', session=session)
        self.assertTrue(isinstance(rad_provider, AaaRadiusProvider))
        
        
class TestLiveAaaRadius(TestLiveSwitch):
    """ This class defines live testing of radius-server """
    def test_get_radius(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, AaaRadius.get, None)
        radius = AaaRadius(session=session)
        self.assertTrue(isinstance(radius, AaaRadius)) 
        
        
class TestLiveAaaTacacsProvider(TestLiveSwitch):
    """ This class defines live testing of tacacs provider """
    def test_tacacs_provider(self):
        session = self.login_to_switch()
        tacacs_provider = AaaTacacsProvider('1.2.3.3', session=session)
        self.assertTrue(isinstance(tacacs_provider, AaaTacacsProvider))                                
    
    
class TestLiveAaaProviderRef(TestLiveSwitch):
    """ This class defines live testing of provider ref """
    def test_provider_ref(self):
        session = self.login_to_switch()
        provider_ref = AaaProviderRef(name='tac1', server='1.2.3.3', 
                                      session=session)
        self.assertTrue(isinstance(provider_ref, AaaProviderRef))
        
        
class TestLiveAaaTacacsProviderGroup(TestLiveSwitch):
    """ This class defines live testing of tacacs provider group """
    def test_tacacs_provider_group(self):
        session = self.login_to_switch()
        tacacs_prov_grp = AaaTacacsProviderGroup('tac1', session=session)
        self.assertTrue(isinstance(tacacs_prov_grp, AaaTacacsProviderGroup)) 
        
        
class TestLiveAaaTacacs(TestLiveSwitch):
    """ This class defines live testing of tacacs-server """
    def test_get_tacacs(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, AaaTacacs.get, None)
        tacacs = AaaTacacs(session=session)
        self.assertTrue(isinstance(tacacs, AaaTacacs))                    
    
    
class TestLiveAaaAaa(TestLiveSwitch):
    """ This class defines live testing of aaa """
    def test_get_aaa(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, AaaAaa.get, None)
        aaa = AaaAaa(session=session)
        self.assertTrue(isinstance(aaa, AaaAaa))    
    
    
class TestLiveRBAC(TestLiveSwitch):
    """ This class defines live testing of rbac """
    def test_get_rbac(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, RBAC.get, None)
        rbac = RBAC(session=session)
        self.assertTrue(isinstance(rbac, RBAC))
        
        
class TestLiveNdPrefix(TestLiveSwitch):
    """ This class defines live testing of nd prefix """
    def test_nd_pfx(self):
        session = self.login_to_switch()
        nd_pfx = NdPrefix('vlan123', '2000::/12', '100', '99', 
                          session=session)
        self.assertTrue(isinstance(nd_pfx, NdPrefix)) 
        
        
class TestLiveNdInterface(TestLiveSwitch):
    """ This class defines live testing of nd interface """
    def test_get_nd_interface(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, NdInterface.get, None)
        nd_int = NdInterface('vlan123', session=session)
        self.assertTrue(isinstance(nd_int, NdInterface)) 
        
        
class TestLiveND(TestLiveSwitch):
    """ This class defines live testing of neighbor discovery """
    def test_get_nd(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, ND.get, None)
        nd = ND(session=session)
        self.assertTrue(isinstance(nd, ND))                          
    

class TestLiveMatchRtType(TestLiveSwitch):
    """ This class defines live testing of match route type"""
    def test_match_rt_type(self):
        session = self.login_to_switch()
        rt_type = MatchRtType('Test_route_map', '10', 'local', 
                              session=session)
        self.assertTrue(isinstance(rt_type, MatchRtType))
        

class TestLiveMatchRtTag(TestLiveSwitch):
    """ This class defines live testing of match route tag"""
    def test_match_rt_tag(self):
        session = self.login_to_switch()
        rt_tag = MatchRtTag('Test_route_map', '10', '200', session=session)
        self.assertTrue(isinstance(rt_tag, MatchRtTag)) 
        
        
class TestLiveSetPeerAddr(TestLiveSwitch):
    """ This class defines live testing of set peer addr"""
    def test_set_peer_addr(self):
        session = self.login_to_switch()
        peer_addr = SetPeerAddr('Test_route_map', '10', session=session)
        self.assertTrue(isinstance(peer_addr, SetPeerAddr))  
        

class TestLiveSetNextHop(TestLiveSwitch):
    """ This class defines live testing of set next hop"""
    def test_set_next_hop(self):
        session = self.login_to_switch()
        next_hop = SetNextHop('Test_route_map', '10', '10.10.10.10', 
                              session=session)
        self.assertTrue(isinstance(next_hop, SetNextHop))
        
        
class TestLiveSetLocalPref(TestLiveSwitch):
    """ This class defines live testing of set local pref"""
    def test_set_local_pref(self):
        session = self.login_to_switch()
        local_pref = SetLocalPref('Test_route_map', '10', '1000', 
                                  session=session)
        self.assertTrue(isinstance(local_pref, SetLocalPref))


class TestLiveSetOrigin(TestLiveSwitch):
    """ This class defines live testing of set origin"""
    def test_set_origin(self):
        session = self.login_to_switch()
        origin = SetOrigin('Test_route_map', '10', 'incomplete', 
                           session=session)
        self.assertTrue(isinstance(origin, SetOrigin))                     


class TestLiveSetCommList(TestLiveSwitch):
    """ This class defines live testing of set comm list"""
    def test_set_comm_list(self):
        session = self.login_to_switch()
        comm_list = SetCommList('Test_route_map', '10', 'test-community', 
                                'delete', session=session)
        self.assertTrue(isinstance(comm_list, SetCommList))


class TestLiveRtMapRs(TestLiveSwitch):
    """ This class defines live testing of route maprs"""
    def test_rt_maprs(self):
        session = self.login_to_switch()
        rt_maprs = RtmapRs('Test_route_map', '10', 'rtmapRsRtAsPathAccAtt',
                           'test-access-list', session=session)
        self.assertTrue(isinstance(rt_maprs, RtmapRs))


class TestLiveRtMapMatch(TestLiveSwitch):
    """ This class defines live testing of route mapmatch"""
    def test_rt_mapmatch(self):
        session = self.login_to_switch()
        rt_mapmatch = RtmapMatch('Test_route_map', '10', 
                                 'rtmapMatchAsPathAccessList', 
                                 'test-access-list', session=session)
        self.assertTrue(isinstance(rt_mapmatch, RtmapMatch))
        

class TestLiveRegCom(TestLiveSwitch):
    """ This class defines live testing of reg com"""
    def test_reg_com(self):
        session = self.login_to_switch()
        reg_com = RegCom('Test_route_map', '10', 
                         'internet,local-AS,no-advertise,no-export,1:2', 
                         session=session)
        self.assertTrue(isinstance(reg_com, RegCom))
        
        
class TestLiveSetRegCom(TestLiveSwitch):
    """ This class defines live testing of set reg com"""
    def test_set_reg_com(self):
        session = self.login_to_switch()
        set_reg_com = SetRegCom('Test_route_map', '10', 
                         'additive,internet,local-AS,no-advertise',
                         session=session)
        self.assertTrue(isinstance(set_reg_com, SetRegCom))        


class TestLiveRouteMapEntry(TestLiveSwitch):
    """ This class defines live testing of route map entry"""
    def test_route_map_entry(self):
        session = self.login_to_switch()
        rt_map_entry = RouteMapEntry(session=session)
        self.assertTrue(isinstance(rt_map_entry, RouteMapEntry))


class TestLiveRouteMap(TestLiveSwitch):
    """ This class defines live testing of route map"""
    def test_get_route_map(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, RouteMap.get, None)
        route_map = RouteMap('Test_route_map', session=session)
        self.assertTrue(isinstance(route_map, RouteMap))
        

class TestLiveRtPrefix(TestLiveSwitch):
    """ This class defines live testing of route prefix"""
    def test_rt_prefix(self):
        session = self.login_to_switch()
        rt_pfx = RtPrefix('1.2.3.4/8', session=session)
        self.assertTrue(isinstance(rt_pfx, RtPrefix)) 
        
        
class TestLivePrefixList(TestLiveSwitch):
    """ This class defines live testing of prefix list"""
    def test_get_prefixlist(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, PrefixList.get, None)
        pfxlist = PrefixList('test_prefix', session=session)
        self.assertTrue(isinstance(pfxlist, PrefixList))               


class TestLiveAccessList(TestLiveSwitch):
    """ This class defines live testing of access list"""
    def test_access_list(self):
        session = self.login_to_switch()
        access_list = AccessList('testAccList', 'permit', '1234', 
                                 session=session)
        self.assertTrue(isinstance(access_list, AccessList))
        
        
class TestLiveAsPath(TestLiveSwitch):
    """ This class defines live testing of aspath"""
    def test_get_aspath(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, AsPath.get, None)
        aspath = AsPath('testAccList', session=session)
        self.assertTrue(isinstance(aspath, AsPath))        
        
        
class TestLiveCommunityItem(TestLiveSwitch):
    """ This class defines live testing of community item"""
    def test_community_item(self):
        session = self.login_to_switch()
        community_item = CommunityItem('internet', session=session)
        self.assertTrue(isinstance(community_item, CommunityItem)) 
        
        
class TestLiveCommunityEntry(TestLiveSwitch):
    """ This class defines live testing of community entry"""
    def test_community_entry(self):
        session = self.login_to_switch()
        community_entry = CommunityEntry('permit', 'internet,local-AS', 
                                         session=session)
        self.assertTrue(isinstance(community_entry, CommunityEntry))
        
        
class TestLiveCommunityList(TestLiveSwitch):
    """ This class defines live testing of community list"""
    def test_get_comm_list(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, CommunityList.get, None)
        Comm_list = CommunityList('comrule', 'standard', session=session)
        self.assertTrue(isinstance(Comm_list, CommunityList))
                
        
class TestLiveRPM(TestLiveSwitch):
    """ This class defines live testing of rpm"""
    def test_rpm(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, RPM.get, None)
        rpm = RPM(session=session)
        self.assertTrue(isinstance(rpm, RPM))
                

if __name__ == '__main__':
    
    offline = unittest.TestSuite()
    offline.addTest(unittest.makeSuite(TestPortChannel))
    offline.addTest(unittest.makeSuite(TestLogging))
    offline.addTest(unittest.makeSuite(TestL2BD))
    offline.addTest(unittest.makeSuite(TestL3Inst))
    offline.addTest(unittest.makeSuite(TestInterfaceBreakout))
    offline.addTest(unittest.makeSuite(TestSVI))
    offline.addTest(unittest.makeSuite(TestInterface))
    offline.addTest(unittest.makeSuite(TestConfigVrrps))
    offline.addTest(unittest.makeSuite(TestLacp))
    offline.addTest(unittest.makeSuite(TestIPV6))
    offline.addTest(unittest.makeSuite(TestIPV6Route))
    offline.addTest(unittest.makeSuite(TestLFeature))
    offline.addTest(unittest.makeSuite(TestDhcp))
    offline.addTest(unittest.makeSuite(TestBootNxos))
    offline.addTest(unittest.makeSuite(TestDns))
    offline.addTest(unittest.makeSuite(TestDnsVrf))
    offline.addTest(unittest.makeSuite(TestIcmp))
    offline.addTest(unittest.makeSuite(TestIP))
    offline.addTest(unittest.makeSuite(TestIPRoute))
    offline.addTest(unittest.makeSuite(TestSTP))
    offline.addTest(unittest.makeSuite(TestUdld))
    offline.addTest(unittest.makeSuite(TestArp))
    offline.addTest(unittest.makeSuite(TestRBAC))
    offline.addTest(unittest.makeSuite(TestND))
    offline.addTest(unittest.makeSuite(TestRPM))
    
    live = unittest.TestSuite()
    live.addTest(unittest.makeSuite(TestLivePortChannel))
    live.addTest(unittest.makeSuite(TestLiveLinkNeighbors))
    live.addTest(unittest.makeSuite(TestLiveHardware))
    live.addTest(unittest.makeSuite(TestLiveHardwareInternal))
    live.addTest(unittest.makeSuite(TestLiveLogTimeStamp))
    live.addTest(unittest.makeSuite(TestLiveLogMonitor))
    live.addTest(unittest.makeSuite(TestLiveLogConsole))
    live.addTest(unittest.makeSuite(TestLiveLogServer))
    live.addTest(unittest.makeSuite(TestLiveLogSourceInterface))
    live.addTest(unittest.makeSuite(TestLiveLogLevel))
    live.addTest(unittest.makeSuite(TestLiveInterfaceBreakout))
    live.addTest(unittest.makeSuite(TestLiveBreakoutModule))
    live.addTest(unittest.makeSuite(TestLiveSVI))
    live.addTest(unittest.makeSuite(TestLiveInterface))
    live.addTest(unittest.makeSuite(TestLiveConfigVrrps))
    live.addTest(unittest.makeSuite(TestLiveVrrp))
    live.addTest(unittest.makeSuite(TestLiveLacp))
    live.addTest(unittest.makeSuite(TestLiveIPV6))
    live.addTest(unittest.makeSuite(TestLiveFeature))
    live.addTest(unittest.makeSuite(TestLiveFeatureAttributes))
    live.addTest(unittest.makeSuite(TestLiveDhcp))
    live.addTest(unittest.makeSuite(TestLiveDhcpRelay))
    live.addTest(unittest.makeSuite(TestLiveBootNxos))
    live.addTest(unittest.makeSuite(TestLiveDnsProfile))
    live.addTest(unittest.makeSuite(TestLiveDnsHost))
    live.addTest(unittest.makeSuite(TestLiveDnsDom))
    live.addTest(unittest.makeSuite(TestLiveDnsDomExt))
    live.addTest(unittest.makeSuite(TestLiveDnsProvider))
    live.addTest(unittest.makeSuite(TestLiveDnsVrf))
    live.addTest(unittest.makeSuite(TestLiveIcmp))
    live.addTest(unittest.makeSuite(TestLiveUdld))
    live.addTest(unittest.makeSuite(TestLiveSTP))
    live.addTest(unittest.makeSuite(TestLiveStpInterface))
    live.addTest(unittest.makeSuite(TestLiveStpVlan))
    live.addTest(unittest.makeSuite(TestLiveStpMst))
    live.addTest(unittest.makeSuite(TestLiveARP))
    live.addTest(unittest.makeSuite(TestLiveAaaRole))
    live.addTest(unittest.makeSuite(TestLiveAaaUserRole))
    live.addTest(unittest.makeSuite(TestLiveAaaUser))
    live.addTest(unittest.makeSuite(TestLiveAaaRadiusProvider))
    live.addTest(unittest.makeSuite(TestLiveAaaRadius))
    live.addTest(unittest.makeSuite(TestLiveAaaTacacsProvider))
    live.addTest(unittest.makeSuite(TestLiveAaaProviderRef))
    live.addTest(unittest.makeSuite(TestLiveAaaTacacsProviderGroup))
    live.addTest(unittest.makeSuite(TestLiveAaaTacacs))
    live.addTest(unittest.makeSuite(TestLiveAaaAaa))
    live.addTest(unittest.makeSuite(TestLiveRBAC))
    live.addTest(unittest.makeSuite(TestLiveNdPrefix))
    live.addTest(unittest.makeSuite(TestLiveNdInterface))
    live.addTest(unittest.makeSuite(TestLiveND))
    live.addTest(unittest.makeSuite(TestLiveMatchRtType))
    live.addTest(unittest.makeSuite(TestLiveMatchRtTag))
    live.addTest(unittest.makeSuite(TestLiveSetPeerAddr))
    live.addTest(unittest.makeSuite(TestLiveSetNextHop))
    live.addTest(unittest.makeSuite(TestLiveSetLocalPref))
    live.addTest(unittest.makeSuite(TestLiveSetOrigin))
    live.addTest(unittest.makeSuite(TestLiveSetCommList))
    live.addTest(unittest.makeSuite(TestLiveRtMapRs))
    live.addTest(unittest.makeSuite(TestLiveRtMapMatch))
    live.addTest(unittest.makeSuite(TestLiveRegCom))
    live.addTest(unittest.makeSuite(TestLiveSetRegCom))
    live.addTest(unittest.makeSuite(TestLiveRouteMapEntry))
    live.addTest(unittest.makeSuite(TestLiveRouteMap))
    live.addTest(unittest.makeSuite(TestLiveRtPrefix))
    live.addTest(unittest.makeSuite(TestLivePrefixList))
    live.addTest(unittest.makeSuite(TestLiveAccessList))
    live.addTest(unittest.makeSuite(TestLiveAsPath))
    live.addTest(unittest.makeSuite(TestLiveCommunityItem))
    live.addTest(unittest.makeSuite(TestLiveCommunityEntry))
    live.addTest(unittest.makeSuite(TestLiveCommunityList))
    live.addTest(unittest.makeSuite(TestLiveRPM))
    
    
    full = unittest.TestSuite([live, offline])
    # Add tests to this suite while developing the tests
    # This allows only these tests to be run
    develop = unittest.TestSuite()

    unittest.main(defaultTest='offline')
