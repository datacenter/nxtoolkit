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
Sample of configuring VRRP parameters
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
            Switch and configure VRRP'''
    creds = NX.Credentials('switch', description)
    args = creds.get()
    
    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
         
    # Object to create multiple VRRP's
    vrrp = NX.ConfigVrrps(session)
    
    # Create interface object
    int1 = NX.Interface('eth1/12')
    
    # Make it L3 interface
    int1.set_layer('Layer3')
    
    # Push interface configuration to the switch
    resp = session.push_to_switch(int1.get_url(), int1.get_json())
    if not resp.ok:
        print('%% Error: Could not push configuration to Switch')
        print(resp.text)
    
    # Create VRRP object for interface
    vrrp_int1 = NX.Vrrp(int1)

    #create vrrpID
    vrrp_id1 = NX.VrrpID('50')
    
    # Set the parameter in VrrpID
    vrrp_id1.set_primary('10.10.0.11')
    vrrp_id1.set_secondary('10.10.1.12')

    # Attach vrrpID to vrrp interface
    vrrp_int1.add_vrrp_id(vrrp_id1)
    
    # Attach the modules to VRRP object
    vrrp.add_vrrp(vrrp_int1)
    
    # Uncomment the below two lines to print url and json response
    # print vrrp.get_url()
    # print vrrp.get_json()
           
    # Push entire configuration to the switch
    resp = session.push_to_switch(vrrp.get_url(), vrrp.get_json())
    if not resp.ok:
        print('%% Error: Could not push configuration to Switch')
        print(resp.text)
        
    
if __name__ == '__main__':
    main()    