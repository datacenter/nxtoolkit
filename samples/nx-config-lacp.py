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
Simple application to login into the switch and configure lacp rate on
the interface
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
                    lacp rate on the interface'''
    creds = NX.Credentials('switch', description)
    args = creds.get()
    
    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
    
    int1 = NX.Interface('eth1/2')
    lacp = NX.Lacp(rate='fast', interface=int1, session=session)
           
    # Push entire configuration to switch
    resp = session.push_to_switch(lacp.get_url(), lacp.get_json())
    if not resp.ok:
        print('%% Error: Could not push configuration to Switch')
        print(resp.text)
        
    # Uncomment below line to get the configuration of all interfaces from
    # switch get_data = NX.Lacp.get(session)
    
    # Get LACP rate configuration from the switch
    get_data = NX.Lacp.get(session)
    template = "{0:16} {1:16}"
    print(template.format("Interface", "rate"))
    print(template.format("-------------", "-------------"))
    for data in get_data:
        print(template.format(data.interface, data.rate))
        

if __name__ == '__main__':
    main() 
