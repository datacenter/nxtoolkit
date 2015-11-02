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
Simple application that logs on to the Switch and Configure Arp
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
                    Switch and Configure Arp.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    ''' Login to Switch '''
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
    
    arp = NX.ARP() # Create ARP instance
    arp.set_timeout('100')
    
    ''' Push ARP configuration to the switch '''
    resp = session.push_to_switch(arp.get_url(), arp.get_json())
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)
        
    # To remove the configuration do the post request without setting timeout
        
    arp_data = NX.ARP.get(session)
    print "IP ARP Timeout: ", arp_data.timeout
    
        
if __name__ == '__main__':
    main()
