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
    
    # Create L2BD objects
    vlan1 = NX.L2BD('vlan-112')
    vlan2 = NX.L2BD('vlan-223')
        
    # Create a ConfigBDs object to configure multiple l2bd at a time
    bds = NX.ConfigBDs()
 
    # Attach L2DB instance or created VLANS
    bds.add_l2bds(vlan1)
    bds.add_l2bds(vlan2)

    # Configures the switch
    # Note: vlan1.get_json() and vlan1.get_url() methods can be used to 
    #       configure a single vlan instead of bds.get_url(), bds.get_json()
    resp = session.push_to_switch(bds.get_url(), bds.get_json())
    if not resp.ok:
        print resp.text
        print ('Could not create vlans')
        exit(0)
    
    # Create interface objects
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
