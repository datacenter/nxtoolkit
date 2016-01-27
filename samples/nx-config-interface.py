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
Simple application that logs on to the Switch and configure the Interfaces.
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
                    configure the Interfaces.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)

    int1 = NX.Interface('eth1/6')
    int2 = NX.Interface('eth1/7')
    
    # ConfigInterfacs object is used to configure multiple 
    # interfaces at a time (No need of multiple REST calls)
    # Note: Using Interface object also an interface can be configured
    config = NX.ConfigInterfaces()
    
    # Adding interfaces to be configured
    config.add_interface(int1)
    config.add_interface(int2)
    
    # Setting interface attributes 
    # Note: if attributes are not set, then default values will be used
    int1.set_admin_status('up')
    int1.set_layer('Layer2')
    int1.set_duplex('auto')
    int1.set_link_log('default')
    int1.set_mode('access')
    int1.set_speed('10G')
    int1.set_access_vlan('vlan-100')
    int1.set_trunk_log('default')
    int1.set_link_log('default')

    # Push entire configuration to the switch
    # Note:To configure only one interface use int1.get_url() & int1.get_json()
    resp = session.push_to_switch(config.get_url(), config.get_json())
    if not resp.ok:
        print ('%% Could not push to Switch')
        print resp.text
        sys.exit(0)

    ethpm = NX.Ethpm()
    ethpm.set_default_admin_st('up')
    ethpm.set_default_layer('Layer2')
    ethpm.set_jumbomtu('9216')
    ethpm.set_unsupported_transceiver('yes')

    resp = session.push_to_switch(ethpm.get_url(), ethpm.get_json())
    if not resp.ok:
        print ('%% Could not push to Switch')
        print resp.text
        sys.exit(0)
    
    # Uncomment below lines to get the configured ethpm
    '''   
    resp = NX.Ethpm.get(session)
    print "Ethpm :\n======="
    print "Admin status             :", resp.get_default_admin_st()
    print "Default layer            :", resp.get_default_layer()
    print "Jumbo mtu                :", resp.get_jumbomtu()
    print "Unsupported-transceiver: :", resp.get_unsupported_transceiver()
    '''

if __name__ == '__main__':
    main()
