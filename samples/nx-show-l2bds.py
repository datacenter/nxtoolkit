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
Simple application that logs on to the Switch and displays all
of the l2bd's.
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
    description = '''Simple application that logs on to the Switch
                    and displays all of the l2bd's.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)

    # Download all of the interfaces
    # and store the data as tuples in a list
    data = []
    l2BDs = NX.L2BD.get(session)
    for l2BD in l2BDs:
        data.append((l2BD.id,
                          l2BD.bridgeMode,
                          l2BD.adminSt,
                          l2BD.operSt,
                          l2BD.unkMacUcastAct,
                          l2BD.unkMcastAct))

    data = sorted(data)

    # Display the data downloaded
    template = "{0:5} {1:12} {2:^11} {3:^10} {4:9} {5:8}"
    print(template.format("ID", "Bridge Mode", "ADMIN STATE", "OPER STATE",
                          "UNK UCAST", "UNK MCAST"))
    print(template.format("----", "------------", "-----------", "----------",
                          "---------", "--------"))
    for rec in data:
        print(template.format(*rec))


if __name__ == '__main__':
    main()
