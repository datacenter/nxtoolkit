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
Simple application that logs on to the Switch and configure BGP session.
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
            configure BGP session.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)

    bgpSession = NX.BGPSession("20")

    bgpDom= NX.BGPDomain("default")
    bgpDom.set_router_id("10.0.0.14")

    bgpPeer = NX.BGPPeer("10.0.0.1", bgpDom)
    bgpPeer.set_remote_as("1")
    bgpDom.add_peer(bgpPeer)

    bgpPeerAf = NX.BGPPeerAF('ipv4-ucast', bgpPeer)

    bgpPeer = NX.BGPPeer("192.168.45.25", bgpDom)
    bgpPeer.set_remote_as("2")
    bgpPeer.add_af(bgpPeerAf)
    bgpDom.add_peer(bgpPeer)

    bgpDomAf = NX.BGPDomainAF('ipv4-ucast', bgpDom)

    advPrefix = NX.BGPAdvPrefix("10.0.0.11/32", bgpDomAf)
    bgpDomAf.add_adv_prefix(advPrefix)

    advPrefix = NX.BGPAdvPrefix("10.0.0.12/32", bgpDomAf)
    bgpDomAf.add_adv_prefix(advPrefix)

    advPrefix = NX.BGPAdvPrefix("10.0.0.13/32", bgpDomAf)
    bgpDomAf.add_adv_prefix(advPrefix)

    advPrefix = NX.BGPAdvPrefix("10.0.0.14/32", bgpDomAf)
    bgpDomAf.add_adv_prefix(advPrefix)

    bgpDom.add_af(bgpDomAf)
    bgpSession.add_domain(bgpDom)

    print bgpSession.get_url(bgpSession)
    print bgpSession.get_json()

    # Push the bgpSession to the Switch
    resp = session.push_to_switch(bgpSession.get_url(bgpSession),
                                bgpSession.get_json())
    
    if not resp.ok:
        print('%% Error: Could not push configuration to Switch')
        print(resp.text)

if __name__ == '__main__':
    main()
