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
Simple application that logs on to the Switch and displays the
hardware buffer information.
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
    description = """Simple application that logs on to the Switch and
                displays the hardware buffer information."""
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
    print "\t \t Output Shared Service Pool Buffer Utilization (in cells)"
    
    template = "{0:20} {1:20} {2:20} {3:20} {4:20}"
    print(template.format(" Pool ", " Total_instant_usage ",
                          " Rem_instant_usage ", " Max_cell_usage ",
                          " Switch_cell_count "))
    print(template.format("------------ ", "------------ ", "------------ ",
                          "---------------", "---------------"))
    hardware = NX.Hardware.get(session)
    resp = hardware.internal.get()
    for index in range (0,4):
        print(template.format('SP-'+str(index),
                              resp.buffer['total_instant'][index],
                              resp.buffer['rem_instant'][index],
                              resp.buffer['max_cell'][index],
                              resp.buffer['switch_cell'][index]))    
    

if __name__ == '__main__':
    main()
