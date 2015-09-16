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
Simple application that logs on to the Switch and create port channel
and attach the specified interfaces to that port channel
"""
import sys
import nxtoolkit.nxtoolkit as NX
import time

def main():
    """
    Main execution routine

    :return: None
    """
    # Take login credentials from the command line if provided
    # Otherwise, take them from your environment variables file ~/.profile
    description = 'create port channel and attach interface'
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
    
    # ConfigInterfaces instance is required to configure multiple port 
    # channel at a time
    config = NX.ConfigInterfaces()
    
    
    # Create a POrtChannels object
    pc1 = NX.PortChannel('444')
    pc2 = NX.PortChannel('445')
    
    int1 = NX.Interface('eth1/5')
    int2 = NX.Interface('eth1/8')
    int3 = NX.Interface('eth1/9')
    
    # Attach interfaces to the port channel
    pc1.attach(int1)
    pc1.attach(int2)
    pc2.attach(int3)
    
    # Add port channels to the config object
    config.add_port_channel(pc1)
    config.add_port_channel(pc2)
    
    # Push/ create the port channel object to the switch
    # Note: To configure only single port channel use pc1.get_url() and 
    # pc1.get_json() instead of config.get_url() and config.get_json()
    resp = session.push_to_switch(config.get_url(), config.get_json())
    if not resp.ok:
        print resp.text
        print('%% Could not push to Switch: %s' % (resp.text))
        sys.exit(0)
    

    # To delete the created port-channel (Uncomment below lines to
    # delete the port channel)
    # resp = session.delete(pc1.get_url())
    #if not resp.ok:
    #    print('%% Could not push to Switch: %s' % (resp.text))
    #    sys.exit(0)
    
if __name__ == '__main__':
    main()
