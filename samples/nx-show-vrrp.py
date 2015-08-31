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
from nxtoolkit.nxtoolkit import Vrrp
"""
Sample of configuring logging parameters
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
    description = 'Simple application that shows the Switch\
                    vrrp configuration'
    creds = NX.Credentials('switch', description)
    args = creds.get()
    
    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
        
    template = "{0:16} {1:16} {2:16} {3:16} {4:16}"
    print(template.format("Interface", "VRRP ID", "priority", "Primary ip", 
                              "secondary ip"))
    print(template.format("------------", "------------", "------------",
                              "------------", "------------"))
    
    # To get details of vrrp of all the interfaces 
    for vrrp in NX.Vrrp.get(session):
        for id in vrrp.vrrp_ids:
            print(template.format(vrrp.interface, id.vrrp_id, id.get_priority(), 
                                   id.get_primary(), id.get_secondary()))


if __name__ == '__main__':
    main() 