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
Simple application that logs on to the Switch and Configure Neighbor Discovery
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
                    Switch and Configure Neighbor Discovery.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    ''' Login to Switch '''
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
    
    nd = NX.ND() # Create ND instance
    
    nd_int = NX.NdInterface('vlan123')
    nd_int.disable_redirect()
    nd_int.set_ra_interval('600')
    nd_int.set_prefix('2000::/12', '100', '99')
    
    nd.add(nd_int)
    
    print nd.get_json()
    ''' Push ND configuration to the switch '''
    resp = session.push_to_switch(nd.get_url(), nd.get_json())
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)
        
    # Uncomment below lines to delete nd configuration of specific interface
    '''
    nd_int = NX.NdInterface('vlan123')
    resp = session.delete(nd_int.get_url())
    if not resp.ok:
        print('%% Could not delete from Switch')
        sys.exit(0)
    '''
        
    template = "{0:20} {1:20} {2:20}"
    print template.format("Interface/Vlan", "Ra Interval", 
                          "Redirection State")
    print template.format("===============", "===============",
                          "===============")
    nd_data = NX.ND.get(session)
    for int in nd_data.interfaces:
        print template.format(int.id, int.ra_interval, int.redirect_st)
        for prefix in int.prefixes:
            print ("Prefix Address:%s\tlifetime:%s\tpreferred lifetime:%s" 
                   % (prefix.address, prefix.lifetime, prefix.pref_lifetime))
        print ("\n")
        
    # Uncomment below lines to get specific interface details
    '''
    int_data = NX.NdInterface.get(session, 'vlan123')
    print template.format("Interface/Vlan", "Ra Interval", 
                          "Redirection State")
    print template.format("===============", "===============", 
                          "===============")
    print template.format(int_data.id, int_data.ra_interval, 
                          int_data.redirect_st)
    for prefix in int_data.prefixes:
        print ("Prefix Address:%s\tlifetime:%s\tpreferred lifetime:%s" 
               % (prefix.address, prefix.lifetime, prefix.pref_lifetime))
    '''
    
        
if __name__ == '__main__':
    main()
