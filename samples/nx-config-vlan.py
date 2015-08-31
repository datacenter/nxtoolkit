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
from nxtoolkit.nxtoolkit import ConfigInterfaces
"""
Simple application that logs on to the Switch and create vlan
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
                    Switch and create vlan.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
    
    # Create vlans
    vlan1 = NX.L2BD('vlan-111')
    vlan2 = NX.L2BD('vlan-222')
        
    # Create L3 instance
    l3inst = NX.L3Inst('default')
    
    # Attach L2DB instance or created VLANS
    l3inst.add_l2bd(vlan1)
    l3inst.add_l2bd(vlan2)
    
    # Configures the switch
    resp = session.push_to_switch(l3inst.get_url(), l3inst.get_json())
    if not resp.ok:
        print resp.text
        print ('Could not create vlans')
        exit(0)

    int1 = NX.Interface('eth1/15')
    int2 = NX.Interface('eth1/16')
    
    # Enable above created vlans on the interfaces
    int1.set_access_vlan('vlan-111')
    int2.set_access_vlan('vlan-222')
    
    #ConfigInterfaces class is used to configure multiple interfaces at a time
    config = ConfigInterfaces()
    config.add_interface(int1)
    config.add_interface(int2)

    # Push all interface configuration to the switch
    resp = session.push_to_switch(config.get_url(), config.get_json())
    if not resp.ok:
        print resp.text
        print ('Could not create port-channel')
        exit(0)


if __name__ == '__main__':
    main()
