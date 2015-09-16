#!/usr/bin/env python
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
"""
Simple application that logs on to the Switch and configure DHCP relay
"""
import sys
import nxtoolkit.nxtoolkit as NX


def main():
    """
    Main execution routine

    :return: None
    """
    # Take login credentials from the command line if provided
    # Otherwise, take them from your environment variables file ~/.profile
    description = '''Simple application that logs on to the
                    Switch and config DHCP relay on an interface.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
    
    # Create DHCP instance
    dhcp = NX.Dhcp()
    dhcp.set_v4relay_st('yes')
    dhcp.set_v6relay_st('no')
    
    relay1 = NX.DhcpRelay('eth2/1')
    relay1.add_relay_address('1.1.1.1')
    relay1.add_relay_address('23ad:33::faa', 'test_vrf')
    dhcp.add_relay(relay1)
    
    relay2 = NX.DhcpRelay('eth2/2')
    relay2.add_relay_address('2.2.2.1')
    relay2.add_relay_address('23ad:33::fbb', 'test_vrf')
    dhcp.add_relay(relay2)
    
    # Push dhcp configuration to the switch
    resp = session.push_to_switch(dhcp.get_url(), dhcp.get_json())
    if not resp.ok:
        print resp.text
        print ('Could not create port-channel')
        exit(0)
        
    for data in dhcp.get(session):
        template = "{0:18} {1:18} {2:18}"
        print template.format("Interface", "Relay Address", "VRF Name")
        print template.format("----------", "----------", "----------")
        
        for relay in data.dhcp_relays:
            for (address, vrf) in zip(relay.relay_address, relay.vrf_name):
                print template.format(relay.interface, address, vrf)
                
    # Uncomment below lines to delete Dhcp Relay configuration 
    '''
    resp = session.delete(dhcp.get_url())
    if not resp.ok:
        print('%% Could not configure the Switch')
        sys.exit(0)
    '''

if __name__ == '__main__':
    main()