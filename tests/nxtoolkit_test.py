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
    Feature, FeatureAttributes)

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
    Test the PortChannel class
    """
    def create_pc(self):
        """
        Create a basic PortChannel used as setup for test cases
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
        # Create one port channel
        pc1 = PortChannel('444')
        # Enable above created vlans on the port channel
        pc1.set_access_vlan('vlan-111')
        return pc1
    
    def test_config_vlan(self):
        pc = self.config_vlan()
        resp = pc.get_json()
        expected_json = ("{'pcAggrIf': {'attributes': {'pcId': '444', 'access"
                         "Vlan': 'vlan-111', 'name': 'po444', 'id': 'po444'},"
                         " 'children': []}}")
        self.assertEqual(str(resp), expected_json)
        
        
class TestLogging(unittest.TestCase):
    """
    Test Logging class
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
    Test L2BD class
    """
    def create_l2bd(self):
        return L2BD('vlan-111')
                
    def test_create_l2bd(self):
        l2bd = self.create_l2bd()
        resp = l2bd.get_json()
        expected_resp = ("{'l2BD': {'attributes': {'fabEncap': 'vlan-111', 'n"
                         "ame': 'vlan-111', 'unkMacUcastAct': 'flood', 'admin"
                         "St': 'active', 'id': '111', 'unkMcastAct': 'flood'}"
                         ", 'children': []}}")
        self.assertEqual(str(resp), expected_resp)
        

class TestL3Inst(unittest.TestCase):
    """
    Create L3Inst class
    """
    def create_l3inst(self):
        # Create vlans
        vlan1 = L2BD('vlan-111')
        
        # Create L3 instance
        l3inst = L3Inst('test-l3-inst')
    
        # Attach L2DB instance or created VLANS
        l3inst.add_l2bd(vlan1)

        return l3inst
    
    def test_create_l3inst(self):
        l3inst = self.create_l3inst()
        resp = l3inst.get_json()
        expected_json = ("{'l3Inst': {'attributes': {'name': 'test-l3-inst'},"
                         " 'children': [{'l2BD': {'attributes': {'fabEncap': "
                         "'vlan-111', 'name': 'vlan-111', 'unkMacUcastAct': '"
                         "flood', 'adminSt': 'active', 'id': '111', 'unkMcast"
                         "Act': 'flood'}, 'children': []}}]}}")
        self.assertEqual(str(resp), expected_json)
        

class TestInterfaceBreakout(unittest.TestCase):
    """Create base breakout object"""
    
    def create_breakout(self):
        brkout = InterfaceBreakout()
    
        module1 = BreakoutModule('1')
        module1.add_port_map('1', '10g-4x')
        
        module2 = BreakoutModule('2')
        module2.add_port_map('1', '10g-4x')
        
        brkout.add_module(module1)
        brkout.add_module(module2)
        
        return brkout
    
    def test_interface_breakout(self):
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
        brkout = InterfaceBreakout()
        expected_url  = '/api/mo/sys/breakout/module-1/fport-1.json'
        self.assertEqual(expected_url, brkout.get_delete_url('1', '1'))


class TestSVI(unittest.TestCase):
    
    def create_svi(self):
        svi10 = SVI('vlan10', admin_st='up', descr='Sample test')
        return svi10
    
    def create_svi_multiple(self):
        config = ConfigInterfaces()
        # Create SVI objects providing vlans
        svi1 = SVI('vlan10')
        svi2 = SVI('vlan20')
        # Add svis to the config
        config.add_svis(svi1)
        config.add_svis(svi2)
        return config
    
    def test_config_svi_one(self):
        svi = self.create_svi()
        resp = svi.get_json()
        expected_json = ("{'sviIf': {'attributes': {'id': 'vlan10', 'descr':"
                         " 'Sample test', 'adminSt': 'up'}, 'children': []}}")
        self.assertEqual(str(resp), expected_json)
    
    def test_config_svi_multiple(self):
        config = self.create_svi_multiple()
        resp = config.get_json()
        expected_json = ("{'interfaceEntity': {'attributes': {}, 'children': "
                         "[{'sviIf': {'attributes': {'id': 'vlan10'}, 'childr"
                         "en': []}}, {'sviIf': {'attributes': {'id': 'vlan20'"
                         "}, 'children': []}}]}}")
        self.assertEqual(str(resp), expected_json)

       
class TestInterface(unittest.TestCase):
    
    def create_interfcae(self):
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
    Test the ConfigVrrps class
    """
    
    def create_vrrps(self):
        """
        Create a VRRP used as setup for test cases
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
    
    def test_create_pc(self):
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
    Test the Lacp class
    """
    def create_lacp(self):
        """
        Create a Lacp used as setup for test cases
        """
        int = Interface('eth1/1')
        lacp = Lacp(rate='fast', interface=int)
        return lacp
    
    def test_create_lacp(self):
        lacp = self.create_lacp()
        resp = lacp.get_json()
        expected_resp = ("{'lacpIf': {'attributes': {'txRate': 'fast', 'id': "
                         "'eth1/1'}, 'children': []}}")
        self.assertEqual(str(resp), expected_resp)


class TestIPV6(unittest.TestCase):
    
    def create_ipv6(self):
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
        ipv6 = IPV6()
        resp = ipv6.get_delete_url('eth1/1')
        expected_resp = '/api/node/mo/sys/ipv6/inst/dom-default/if-[eth1/1].json'
        self.assertEqual(str(resp), expected_resp)


class TestIPV6Route(unittest.TestCase):
    def create_ipv6_route(self):
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
    
    def feature_status(self):
        feature = Feature()
        feature.enable('bgp')
        feature.disable('dhcp')
        return feature
    
    def test_feature_status(self):
        feature = self.feature_status()
        resp = feature.get_json()
        expected_resp = ("{'fmEntity': {'attributes': {}, 'children': [{'fmBg"
                         "p': {'attributes': {'adminSt': 'enabled'}}}, {'fmDh"
                         "cp': {'attributes': {'adminSt': 'disabled'}}}]}}")
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
    
    def test_get_all_portchannels(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, PortChannel.get, None)
        portchannels = PortChannel.get(session)
        for pc in portchannels:
            self.assertTrue(isinstance(pc, PortChannel))
            pc_as_a_string = str(pc)
            self.assertTrue(isinstance(pc_as_a_string, str))


class TestLiveLinkNeighbors(TestLiveSwitch):
    
    def test_get_allneighbors(self):
        session = self.login_to_switch()
        neighbors = LinkNeighbors.get(session)
        for neighbor in neighbors:
            self.assertTrue(isinstance(neighbor, LinkNeighbors))
            neighbor_string = str(neighbor)
            self.assertTrue(isinstance(neighbor_string, str))


class TestLiveHardware(TestLiveSwitch):
    def test_hardware(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, Hardware.get, None)
        hardwares = Hardware.get(session)
        self.assertTrue(isinstance(hardwares, Hardware))   


class TestLiveHardwareInternal(TestLiveSwitch):
    def test_hardware_internal(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, HardwareInternal.get, None)
        hardware_internal = HardwareInternal(session)  
        self.assertTrue(isinstance(hardware_internal, HardwareInternal))

        
class TestLiveLogTimeStamp(TestLiveSwitch):  
    def test_log_timestamp(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, LogTimeStamp.get, None)
        timestamp = LogTimeStamp(session)
        self.assertTrue(isinstance(timestamp, LogTimeStamp)) 

        
class TestLiveLogMonitor(TestLiveSwitch):  
    def test_log_monitor(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, LogMonitor.get, None)
        monitor = LogMonitor(session)
        self.assertTrue(isinstance(monitor, LogMonitor))          

        
class TestLiveLogConsole(TestLiveSwitch):  
    def test_log_console(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, LogConsole.get, None)
        console = LogConsole(session)
        self.assertTrue(isinstance(console, LogConsole))   

        
class TestLiveLogServer(TestLiveSwitch):  
    def test_log_server(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, LogServer.get, None)
        server = LogServer(session)
        self.assertTrue(isinstance(server, LogServer))  


class TestLiveLogSourceInterface(TestLiveSwitch):  
    def test_log_source_interface(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, LogSourceInterface.get, None)
        src_interface = LogSourceInterface(session)
        self.assertTrue(isinstance(src_interface, LogSourceInterface))  
   
        
class TestLiveLogLevel(TestLiveSwitch):  
    def test_log_level(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, LogLevel.get, None)
        level = LogLevel(session)
        self.assertTrue(isinstance(level, LogLevel))                                     


class TestLiveInterfaceBreakout(TestLiveSwitch):
    
    def test_interface_break_get(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, InterfaceBreakout.get, None)
        level = InterfaceBreakout(session)
        self.assertTrue(isinstance(level, InterfaceBreakout))  


class TestLiveBreakoutModule(TestLiveSwitch):
    
    def test_breakout_module(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, BreakoutModule.get, None)
        level = BreakoutModule('1', session=session)
        self.assertTrue(isinstance(level, BreakoutModule))


class TestLiveSVI(TestLiveSwitch):
    
    def test_config_svi(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, SVI.get, None)
        level = SVI('vlan10', 'up', 'Sample Test')
        self.assertTrue(isinstance(level, SVI))


class TestLiveInterface(TestLiveSwitch):
    
    def test_config_interface(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, Interface.get, None)
        i_face = Interface('eth1/5')
        self.assertTrue(isinstance(i_face, Interface))
        
        
class TestLiveConfigVrrps(TestLiveSwitch):
    
    def test_config_vrrps(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, ConfigVrrps.get, None)
        config_vrrp = ConfigVrrps(session)
        self.assertTrue(isinstance(config_vrrp, ConfigVrrps))


class TestLiveVrrp(TestLiveSwitch):
    
    def test_vrrp(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, Vrrp.get, None)
        vrrp = Vrrp(session)
        self.assertTrue(isinstance(vrrp, Vrrp))
      
        
class TestLiveLacp(TestLiveSwitch):
    
    def test_lacp(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, Lacp.get, None)
        lacp = Lacp(session)
        self.assertTrue(isinstance(lacp, Lacp))


class TestLiveIPV6(TestLiveSwitch):
    
    def test_ipv6_get(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, IPV6.get, None)
        ipv6 = IPV6(session=session)
        self.assertTrue(isinstance(ipv6, IPV6))
        
        
class TestLiveFeature(TestLiveSwitch):
    
    def test_feature(self):
        session = self.login_to_switch()
        self.assertRaises(TypeError, Feature.get, None)
        feature = Feature(session=session)
        self.assertTrue(isinstance(feature, Feature))


class TestLiveFeatureAttributes(TestLiveSwitch):
    
    def test_feature_attributes(self):
        session = self.login_to_switch()
        feature_attributes = FeatureAttributes(session=session)
        self.assertTrue(isinstance(feature_attributes, FeatureAttributes))
          

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
    
    
    full = unittest.TestSuite([live, offline])
    # Add tests to this suite while developing the tests
    # This allows only these tests to be run
    develop = unittest.TestSuite()

    unittest.main(defaultTest='offline')
        
    

