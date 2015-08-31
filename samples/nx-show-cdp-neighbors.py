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
Simple application that logs on to the Switch and displays the cdp neighbors.
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
                displays the cdp neighbors'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)

    cdp_detail = NX.LinkNeighbors.get(session)
    data = []
    if not len(cdp_detail):
        print "NO CDP entry found for given interface."
        exit()
    else:
        for cdp in cdp_detail:
            data.append((cdp.attributes['devId'],
                         cdp.attributes['id'],
                         cdp.attributes['Hldtme'],
                         cdp.attributes['cap'],
                         cdp.attributes['platId'],
                         cdp.attributes['portId']))

    # Display the data downloaded
    template = "{0:35} {1:13} {2:6} {3:40} {4:20} {5:10} "
    print(template.format("Device-ID", "Local Iface", "Hldtme", "Capability",
                          "Platform", "Port ID"))
    print(template.format("---------", "-----------", "------", "----------",
                          "--------", "--------",))
    for rec in data:
        print(template.format(*rec))

if __name__ == '__main__':
    main()
