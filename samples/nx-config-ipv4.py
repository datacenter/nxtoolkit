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
Simple application that logs on to the Switch and configure ipv4 on the 
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
                configure ipv4 on the Interfaces.'''
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
    int1 = NX.Interface('eth1/20')
    
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
    
    # Create IPv4 instance
    ipv4 = NX.IP()
    
    # Enable ip directed broadcast on the interface
    ipv4.enable_directed_broadcast(int1)
    
    # Add interfaces
    ipv4.add_interface_address(int1, '1.1.1.1/20')
    
    # Add port channel
    ipv4.add_interface_address(pc1, '3.3.3.211/13')

    # Configure IPv4 route and Nexthop information
    r1 = NX.IPRoute('4.4.4.4/32')
    r1.add_next_hop('5.5.5.5', int1, vrf='default', track_id='0', tag='1')
    r1.add_next_hop('7.7.7.7', pc1, vrf='default', track_id='1', tag='2')

    # Add route to IPv4
    ipv4.add_route(r1)
    
    print ipv4.get_url()
    print ipv4.get_json()
    resp = session.push_to_switch(ipv4.get_url(), ipv4.get_json())
    if not resp.ok:
        print ('%% Could not push to Switch.')
        print resp.text
        sys.exit(0)

    # Uncomment below to delete the resources
    '''
    # Delete IP route
    resp = session.delete(r1.get_delete_url())
    if not resp.ok:
        print ('%% Could not delete from Switch')
        print resp.text
        sys.exit(0)
   
    # Delete from interface
    resp = session.delete(ipv4.get_delete_url('eth1/20'))
    if not resp.ok:
        print ('%% Could not delete from Switch')
        print resp.text
        sys.exit(0)

    resp = session.delete(ipv4.get_url())
    if not resp.ok:
        print ('%% Could not delete from Switch')
        print resp.text
        sys.exit(0)
    '''


if __name__ == '__main__':
    main()