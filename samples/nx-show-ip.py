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
Simple application that logs on to the Switch and get ipv6 details.
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
                    Switch and get ipv6 details.'''
    creds = NX.Credentials('switch', description)
    
    creds.add_argument('-v', '--version', type=str, default='v4',
                       help='''IP version (Example: v4, v6), By default its v4''')

    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)

    # Get IP infos. from the switch(default version is v4)
    ipv = NX.IP.get(session, args.version)

    # Display ip interface details
    template = "{0:15} {1:15} {2:32}"
    print(template.format(" Interface ", " Admin status ",
                          " IP%s addresses %s" % (args.version,
                ('/ Link-local address' if 'v6' in args.version else ''))))
    print(template.format("-----------", "--------------",
                          "------------------------------------"))
    for iface in ipv.interfaces:
        print(template.format(iface.get_if_name(), iface.get_admin_st(),
                              iface.get_address()))
    
    # Display ip route details
    template = "{0:20} {1:15} {2:15} {3:15} {4:15}"
    for route in ipv.routes:
        print "\nRoute prefix : %s" % (route.prefix)
        for n_hop in route.next_hops:
            print(template.format("\tNext Hop Addr ", " Interface    ",
                                  " Vrf  ", " Tag ", " Track Id"))
            print(template.format("\t--------------", "--------------",
                                  "------", "-----", "---------"))
            print(template.format("\t"+n_hop.addr, n_hop.i_face, n_hop.vrf,
                                  n_hop.tag, n_hop.track_id))


if __name__ == '__main__':
    main()