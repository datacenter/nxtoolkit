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
Simple application that logs on to the Switch and configure ipv6 on the 
Interfaces.
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
    description = '''Simple application that logs on to the Switch and 
                configure ipv6 on the Interfaces.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
    
    # Creating interface objects
    # Note: interfaces should be L3 interface
    int1 = NX.Interface('eth2/1')
    int2 = NX.Interface('eth2/3')
    
    # Create a L3 port channel
    pc1 = NX.PortChannel('211', layer='Layer3')
    
    # Create the port channel in the switch 
    # Note:(port channel should be exist in the switch before 
    # assigning IPv6 to it)
    resp = session.push_to_switch(pc1.get_url(), pc1.get_json())
    if not resp.ok:
        print ('%% Could create port channel in the Switch')
        print resp.text
        sys.exit(0)
    
    ipv6 = NX.IPV6()

    # Add interfaces
    ipv6.add_interface_address(int1, '2004:0DB8::1/10', link_local='FE83::1')
    ipv6.add_interface_address(int2, '2104:0DB8::1/11')
    ipv6.add_interface_address(int2, '2002:0DB8::1/12')
    
    # Add port channel
    ipv6.add_interface_address(pc1, '2022:0DB8::1/13')
    
    # Configure IPv6 route and Nexthop information
    r1 = NX.IPV6Route('2000:0::0/12')
    r1.add_next_hop('234E:44::1', int1, vrf='default', track_id='0', tag='1')
    r1.add_next_hop('234E:44::2', int2)
    r1.add_next_hop('234E:44::4', pc1, vrf='default', track_id='1', tag='2')

    # Add route to IPv6
    ipv6.add_route(r1)
      
    resp = session.push_to_switch(ipv6.get_url(), ipv6.get_json())
    if not resp.ok:
        print ('%% Could not push to Switch')
        print resp.text
        sys.exit(0)

    # Uncomment below lines to delete IPv6 from all the interface
    # Note: Use ipv6.get_delete_url('eth1/1') instead of ipv6.get_url()
    # to delete ipv6 of specific interface
    '''
    resp = session.delete(ipv6.get_url())
    if not resp.ok:
        print ('%% Could not delete from Switch')
        print resp.text
        sys.exit(0)
    '''


if __name__ == '__main__':
    main()