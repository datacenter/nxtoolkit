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
Sample of displaying the logging parameters
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
    description = 'Simple application that logs on to the Switch and\
                    display the Syslogs parameters'
    creds = NX.Credentials('switch', description)
    args = creds.get()
    
    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
    
    # Create logging object (Note: Currently one string has to be passed as 
    # parameter while creating  Logging object)
    log = NX.Logging.get(session)
    
    timestamp = log.timestamp.get()
    if timestamp:
        data = []
        data.append((timestamp.format, ""))
        print "TimeStamp :\n==========="
        template = "{0:17}"
        print(template.format("Format     "))
        print(template.format("-----------"))
        for rec in data:
            print(template.format(*rec))
        print ""

    monitor = log.monitor.get()
    if monitor:
        data = []
        data.append((monitor.admin_st, monitor.severity))
        print "Monitor :\n==========="
        template = "{0:17} {1:17}"
        print(template.format("adminState     ", "  severity  "))
        print(template.format("---------------", "  ----------"))
        for rec in data:
            print(template.format(*rec))
        print ""
    
    console = log.console.get()
    if console:
        data = []
        data.append((console.admin_st, console.severity))
        print "Console :\n==========="
        template = "{0:17} {1:17}"
        print(template.format("adminState     ", "  severity  "))
        print(template.format("---------------", "  ----------"))
        for rec in data:
            print(template.format(*rec))
        print ""
    
    server = log.server.get()
    if server:
        data = []
        data.append((server.host, monitor.severity, server.fwd_facility,
                     server.vrf_name))
        print "Server :\n==========="
        template = "{0:17} {1:17} {2:16} {3:16}"
        print(template.format("host              ", "  severity  ",
                              " fwd-facility", "vrf-name"))
        print(template.format("------------------", "  ----------",
                              " ------------", "--------"))
        for rec in data:
            print(template.format(*rec))
        print ""
    
    level = log.level.get()
    if level:
        data = []
        data.append((level.severity, level.facility))
        print "Level :\n==========="
        template = "{0:17} {1:17}"
        print(template.format("Severity     ", "  Facility  "))
        print(template.format("---------------", "  ----------"))
        for rec in data:
            print(template.format(*rec))
        print ""
    
    interface = log.src_iface.get()
    if interface:
        data = []
        data.append((interface.admin_st, interface.if_name))
        print "Source Interface :\n=============="
        template = "{0:17} {1:17}"
        print(template.format("adminState     ", "  interface-name  "))
        print(template.format("---------------", "  ----------------"))
        for rec in data:
            print(template.format(*rec)) 
        print ""
    
    
if __name__ == '__main__':
    main()    
