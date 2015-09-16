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
Simple application to login into the switch and configure icmp 
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
    description = '''Simple application to login into the switch and configure
                    icmp.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()
    
    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
    
    # Create an instance of interface
    int1 = NX.Interface('eth1/20')
    int1.set_layer('Layer3')
    
    # Push the configuration to the switch to make the interface L3
    resp = session.push_to_switch(int1.get_url(), int1.get_json())
    if not resp.ok:
        print ('%% Could not push to Switch')
        print resp.text
        sys.exit(0)
    
    # Create an instance of icmp
    icmp = NX.ICMP('v4', int1, 'redirect')
    
    resp = session.push_to_switch(icmp.get_url(), icmp.get_json())
    if not resp.ok:
        print ('%% Could not push to Switch')
        print resp.text
        sys.exit(0)

    # Uncomment below lines to delete Icmp from the given interface
    '''
    resp = session.delete(icmp.get_url())
    if not resp.ok:
        print ('%% Could not delete from Switch')
        print resp.text
        sys.exit(0)
    '''
        
    # To get the redirection state
    icmps = NX.ICMP.get(session)
    
    template = "{0:16} {1:16} {2:16}"
    print template.format("Interface/Vlan", "Redirect state", "Version")
    print template.format("---------------", "---------------", "---------------")
    for icmp in icmps:
        print template.format(icmp.id, icmp.status, icmp.version) 
        


if __name__ == '__main__':
    main()