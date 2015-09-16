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
Simple application that logs on to the Switch and displays BGP
session information.
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
                displays BGP session information.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)

    bgpSessions = NX.BGPSession.get(session)

    print("BGP Instance")
    print("------------")

    for bgpSession in bgpSessions:
        print bgpSession.get_as_num()

    for bgpSession in bgpSessions:
        bgpDoms = NX.BGPDomain.get(session, bgpSession)

        for bgpDom in bgpDoms:
            dom_data = []
            dom_template = "{0:5} {1:20} {2:15}"
            print(dom_template.format("", "Domain Name", "Router ID"))
            print(dom_template.format("", "-----------", "-------------"))

            print(dom_template.format("", bgpDom.get_name(),
                                      bgpDom.get_router_id()))

            dom_peer_data = []
            dom_peer_template = "{0:5} {1:20} {2:15} {3:6}"
            print(dom_peer_template.format("", "", "Peer Address", "AS Num"))
            print(dom_peer_template.format("", "", "-------------", "------"))

            bgpDomPeers = NX.BGPPeer.get(session, bgpDom)
            for bgpDomPeer in bgpDomPeers:
                dom_peer_data.append(("", "", bgpDomPeer.get_addr(), 
                                      bgpDomPeer.get_remote_as()))

            for peer_rec in dom_peer_data:
                print(dom_peer_template.format(*peer_rec))

            bgpDomAfs = NX.BGPDomainAF.get(session, bgpDom)
            dom_af_data = []
            dom_af_template = "{0:5} {1:20} {2:15}"
            print(dom_af_template.format("", "", "Address Family"))
            print(dom_af_template.format("", "", "-------------"))

            for bgpDomAf in bgpDomAfs:
                dom_af_data.append(("", "", bgpDomAf.get_type()))

            for af_rec in dom_af_data:
                print(dom_af_template.format(*af_rec))


if __name__ == '__main__':
    main()
