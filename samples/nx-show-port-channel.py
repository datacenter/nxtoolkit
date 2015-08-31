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
Simple application that logs on to the Switch and show port channels
"""
import sys
import nxtoolkit.nxtoolkit as NX
import time

def main():
    """
    Main execution routine

    :return: None
    """
    # Take login credentials from the command line if provided
    # Otherwise, take them from your environment variables file ~/.profile
    description = '''Simple application that logs on to the Switch
                and show port channels'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
    
    pc_list = []
    port_channels = NX.PortChannel.get(session)
    template = "{0:16} {1:15} {2:16} {3:16} {4:16}"
    print(template.format(" Group   ", " Port channel ", " Layer ",
                          "Port channel Mode", " Members "))
    print(template.format("---------", " ------------ ", " ----- ",
                          "-----------------", " --------"))
    for pc in port_channels:
        pc_list.append((pc.pc_id, pc.name, pc.layer, pc.pc_mode,
                        [str(iface.if_name) for iface in pc._interfaces]))
    
    # Display all the downloaded data
    for rec in pc_list:
        print(template.format(*rec))
        
    
if __name__ == '__main__':
    main()
