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
Simple application that logs on to the Switch and configure interface breakout.
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
            configure interface breakout.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)

    brkout = NX.InterfaceBreakout()
    
    module1 = NX.BreakoutModule('1')
    module1.add_port_map('1', '10g-4x')
    module1.add_port_map('2', '10g-4x')
    
    module2 = NX.BreakoutModule('2')
    module2.add_port_map('1', '10g-4x')
    
    brkout.add_module(module1)
    brkout.add_module(module2)

    resp = session.push_to_switch(brkout.get_url(), brkout.get_json())
    if not resp.ok:
        print resp.text
        print('%% Could not configure the Switch')
        sys.exit(0)

    # Display all the data
    brk = NX.InterfaceBreakout.get(session)
    
    # Get list of BreakoutModule object
    modules = brk.modules.get()
    for module in modules:
        print "Module %s:\n========" % (module.module_num)
        # Get list of breakout ports under module
        ports = module.ports.get() 
        for port in ports:
            print "Port:", port.id
            print "Map :", port.map
            print ""

    # Uncomment below lines to delete breakout configuration for port 
    # 1 of module 1
    '''
    resp = session.delete(brkout.get_delete_url(module='1', port='1'))
    if not resp.ok:
        print('%% Could not configure the Switch')
        sys.exit(0)
    '''

    # Uncomment below lines to delete all the breakout module
    '''
    resp = session.delete(brkout.get_url())
    if not resp.ok:
        print('%% Could not configure the Switch')
        sys.exit(0)
    '''
    
    
if __name__ == '__main__':
    main()
