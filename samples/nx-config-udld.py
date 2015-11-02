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
Simple application that logs on to the Switch and Configure UDLD
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
                    Switch and Configure UDLD.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    ''' Login to Switch '''
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
    
    udld = NX.UDLD() # Create UDLD instance
    
    int = NX.Interface('eth1/2')
    
    udld.enable_aggress()
    udld.disable_aggress(int)
    
    ''' Push UDLD configuration to the switch '''
    resp = session.push_to_switch(udld.get_url(), udld.get_json())
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)

    # Uncomment below lines to delete UDLD configuration 
    '''
    resp = session.delete(udld.get_url())
    if not resp.ok:
        print('%% Could not delete from Switch')
        sys.exit(0)
    '''
        
    udld_data = NX.UDLD.get(session) # Pass interface to get specific 
                                     # interface details
    print "UDLD global configuration mode aggressive:", udld_data.aggress
    print "UDLD global message interval:", udld_data.g_msg_int
    template = "{0:12} {1:12}"
    print template.format("Interface", "aggress")
    print template.format("----------", "----------")
    for (id, aggress) in zip(udld_data.i_faces,  udld_data.int_aggresses):
        print template.format(id, aggress)


if __name__ == '__main__':
    main()
