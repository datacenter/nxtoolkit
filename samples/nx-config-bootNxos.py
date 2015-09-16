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
Simple application that logs on to the Switch and set the boot variable
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
                    Switch and set the boot variable.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
    
    # Create Boot instance
    boot = NX.BootNxos('n9000-dk9.7.0.3.I2.0.551')
    
    # Push boot configuration to the switch
    resp = session.push_to_switch(boot.get_url(), boot.get_json())
    if not resp.ok:
        print resp.text
        print ('Could not set the boot variable')
        exit(0)
        
    boot_nxos = boot.get(session)
    print "Current Boot Variables:"
    print "Sup1"
    print "NXOS variable = ", boot_nxos.sup1
    print "Boot Variables on next reload:"
    print "Sup2"
    print "NXOS variable = ", boot_nxos.sup2
        
    # Uncomment below lines to delete unset the boot variable 
    '''
    resp = session.delete(boot.get_url())
    if not resp.ok:
        print('%% Could not delete from Switch')
        sys.exit(0)
    '''
    

if __name__ == '__main__':
    main()
