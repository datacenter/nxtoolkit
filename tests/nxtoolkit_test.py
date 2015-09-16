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
    SVI, ConfigInterfaces, ConfigVrrps, Vrrp, VrrpID, Lacp, IPV6, IPV6Route,
    Feature, FeatureAttributes, Dhcp, DhcpRelay, BootNxos, Copy, 
    RunningToStartUp, DNS, DnsProfile, DnsHost, DnsDomExt, DnsDom, 
    DnsProvider, DnsVrf, ICMP, ConfigBDs)

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
        ipv6 = IPV6()
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
        ipv6 = IPV6()
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
        route = IPV6Route('2000:0::0/12')
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
        self.assertRaises(TypeError, IPV6.get, None)
        ipv6 = IPV6(session=session)
        self.assertTrue(isinstance(ipv6, IPV6))
        
        
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
    
    full = unittest.TestSuite([live, offline])
    # Add tests to this suite while developing the tests
    # This allows only these tests to be run
    develop = unittest.TestSuite()

    unittest.main(defaultTest='offline')
