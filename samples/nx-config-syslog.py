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
Sample of configuring logging parameters
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
                    configure Syslogs'''
    creds = NX.Credentials('switch', description)
    args = creds.get()
    
    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)  
    
    # Create Logging object
    log = NX.Logging()
    
    # Create  timestamp
    timestamp = NX.LogTimeStamp(format='milliseconds')
    
    # Create logging console
    console = NX.LogConsole(admin_st='1', severity='2')
    
    # Create logging monitor
    monitor = NX.LogMonitor(admin_st='1', severity='2')
    
    # Create source interface logs
    source_iface = NX.LogSourceInterface(admin_st='1', if_name='lo 2')
    
    # Create logging level
    level = NX.LogLevel(severity='2', facility='local5')
    
    # Create server logs
    server = NX.LogServer(host='10.10.1.12', severity='2', 
                      vrf_name='management', fwd_facility='auth')
    
    # Attach or set all the log 
    log.add_log(timestamp)
    log.add_log(console)
    log.add_log(monitor)
    log.add_log(source_iface)
    log.add_log(level)
    log.add_log(server)
   
    # Push entire configuration to switch
    resp = session.push_to_switch(log.get_url(), log.get_json())
    if not resp.ok:
        print('%% Error: Could not push configuration to Switch')
        print(resp.text)

if __name__ == '__main__':
    main()    
