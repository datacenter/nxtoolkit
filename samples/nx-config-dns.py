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
Simple application that logs on to the Switch and configure DNS
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
                    Switch and configure DNS.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
    
    # Create DNS instance
    dns = NX.DNS()
    dns.enable_lookup()
    
    prof1 = NX.DnsProfile()
    
    dns_provider = NX.DnsProvider('1.1.1.2')
    prof1.add(dns_provider)
    
    dns_domain = NX.DnsDom('name')
    prof1.add(dns_domain)
    
    dns_dmn_ext = NX.DnsDomExt('name1')
    prof1.add(dns_dmn_ext)
    
    dns_host = NX.DnsHost('name2', '1:1::12')
    prof1.add(dns_host)
    
    # Create VRF instance
    vrf1 = NX.DnsVrf('test_vrf1')
    vrf2 = NX.DnsVrf('test_vrf2')
    
    vrf1.use_in(dns_provider)
    vrf2.use_in(dns_dmn_ext)
    
    # Add VRF to DNS
    prof1.add(vrf1)
    prof1.add(vrf2)
    
    dns.add_profile(prof1)
    
    # Push DNS configuration to the switch
    resp = session.push_to_switch(dns.get_url(), dns.get_json())
    if not resp.ok:
        print resp.text
        print ('Could not configure DNS')
        exit(0)
    
    # Uncomment below lines to delete the dns configuration
    '''
    resp = session.delete(dns.get_url())
    if not resp.ok:
        print('%% Could not delete from Switch')
        sys.exit(0)
    '''
    
        
if __name__ == '__main__':
    main()