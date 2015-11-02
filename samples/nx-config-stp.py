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
Simple application that logs on to the Switch and Configure STP
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
                    Switch and Configure STP.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    ''' Login to Switch '''
    session = NX.Session(args.url, args.login, args.password) 
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
    
    stp = NX.STP() # Create STP instance
    stp.set_mode('pvrst')
    
    stp.add_port_type('bpdufilter')
    stp.add_port_type('bpduguard')
    stp.add_port_type('edge')
    stp.add_port_type('network')
    
    mst_etity = NX.StpMst()
    mst_etity.set_simulate('disabled')
    
    vlan = NX.StpVlan('222')
    vlan.set_admin_st('enabled')
    vlan.set_bdg_priority('12288')
    
    int = NX.Interface('eth1/20')
    i_face = NX.StpInterface(int)
    
    i_face.set_mode('network')  # Mode can be network/edge/normal only for l2
                                # interface
    
    stp.add(mst_etity)
    stp.add(vlan)
    stp.add(i_face)
    
    ''' Push STP configuration to the switch '''
    resp = session.push_to_switch(stp.get_url(), stp.get_json())
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)

    '''
    # Delete interface STP configuration
    resp = session.delete(i_face.get_url())
    if not resp.ok:
        print('%% Could not delete from Switch')
        sys.exit(0)
    

    # Uncomment below lines to delete all the STP configuration
    resp = session.delete(stp.get_url())
    if not resp.ok:
        print('%% Could not delete from Switch')
        sys.exit(0)
    '''

    # Get the STP details
    data = NX.STP.get(session)
    print "STP Mode:\t", data.mode
    print "STP Port type:\t", data.port_type
    for mst in data.msts:
        print "MSt state:\t", mst.simulate
        print "Hello time:\t", mst.hello_time
        print "Forward time:\t", mst.fwd_delay
        print "Maximum age:\t", mst.max_age
    
    template = "{0:14} {1:14} {2:14} {3:14}"
    print (template.format("Interface", "Mode", "Priority", "Cost"))
    print (template.format("-----------", "-----------", "-----------", 
                           "-----------"))
    for i_face in data.i_faces:
        print (template.format(i_face.id, i_face.mode, i_face.priority, 
                               i_face.cost))
    
    for vlan in data.vlans:
        print "\n"
        print ("Vlan-%s, Admin State: %s, Protocol: %s" % (vlan.id,
                                                           vlan.admin_st,
                                                           vlan.protocol))
        print ("Root:: Address: %s\tPriority: %s\tCost: %s\tPort Number: %s" %
               (vlan.root_addr, vlan.root_priority, vlan.root_cost, 
                vlan.root_port_no))
        print ("Bridge:: Address: %s\tPriority: %s" % (vlan.bdg_addr,
                                                       vlan.bdg_priority))
        

if __name__ == '__main__':
    main()
