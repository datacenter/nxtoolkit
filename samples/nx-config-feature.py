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
Simple application that logs on to the Switch and enable features
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
                Switch and enable features'''
    creds = NX.Credentials('switch', description)
    args = creds.get()
    
    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)  
    
    #Create Feature Base object
    feature = NX.Feature(session)

    feature.enable('bgp')
    feature.enable('dhcp')
    feature.enable('interface-vlan')
    feature.disable('udld')
    feature.enable('vrrp')
    feature.enable('nxapi')
    feature.enable('tacacsplus')
    feature.enable('lacp')
    
    # Push entire configuration to switch
    resp = session.push_to_switch(feature.get_url(), feature.get_json())
    if not resp.ok:
        print('%% Error: Could not push configuration to Switch')
        print(resp.text)
    
    template = "{0:20} {1:16} {2:16}"
    print(template.format("Feature Name", "Instance", "state"))
    print(template.format("------------", "------------", 
                          "------------"))
    

    for data in feature.get():
        print(template.format(data.name, data.instance, data.admin_st))
    

if __name__ == '__main__':
    main()    

