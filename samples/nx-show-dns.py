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
Simple application that logs on to the Switch and displays the DNS details.
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
                    Switch and displays the DNS details.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)


    dns = NX.DNS.get(session)
    print "Dns lookup state:", dns.get_admin_st()
    for prof in dns.profiles:
        print "\nDns profile name:", prof.name
        for provider in prof.providers:
            print "\tProvider ip:", provider.address
        for domain in prof.domains:
            print "\tDomain name:", domain.name
        for domain_ext in prof.domain_exts:
            print "\tDomain list name:", domain_ext.name
        for host in prof.hosts:
            print "\tHost name:%s\t\tAddress:%s"% (host.name, host.address) 
        for vrf in prof.vrfs:
            for provider in vrf.providers:
                print "\tVrf name:%s\tProvider ip:%s"% (vrf.name, 
                                                          provider.address)
            for domain in vrf.domains:
                print "\tVrf name:%s\tDomain name:%s"% (vrf.name, 
                                                          domain.name)
            for domain_ext in vrf.domain_exts:
                print "\tVrf name:%s\tDomain list name:%s"% (vrf.name, 
                                                             domain_ext.name)
    
if __name__ == '__main__':
    main()