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
Simple application that logs on to the Switch and Configure Route Processor 
Module
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
                    Switch and Configure Route Processor Module.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    ''' Login to Switch '''
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
        
    rpm = NX.RPM()

    route_map = NX.RouteMap('Test_route_map') 
    # Note: Sequence number must not be present in the switch    
    map_entry = NX.RouteMapEntry('permit', '10') 
    map_entry.set_descr('This is test route-map')
    map_entry.match_rt_type('local')     
    map_entry.match_rt_tag('200')        
    map_entry.disable_nh_peer('v4')  
    map_entry.set_next_hop('10.10.10.10') 
    map_entry.set_next_hop('10:20::30:40')
    map_entry.set_local_pref('1000')            
    map_entry.set_origin('incomplete')            
    map_entry.set_comm_list('test-community', 'delete')     

    map_entry.match_as_path('test-access-list')
    map_entry.match_pfxlistv4('test-prefix-v4')
    map_entry.match_pfxlistv6('test-prefix-v6')
    map_entry.match_comm('test-community', 'exact')

    map_entry.set_comm('additive,internet,local-AS,no-advertise,1:2')
    
    route_map.add(map_entry)
    
    pfx_v4 = NX.PrefixList('test_prefix')
    # Note: Sequence number must not be present in the switch 
    pfx_v4.set_prefix('1.2.3.4/8', 'permit', '10')
    
    pfx_v6 = NX.PrefixList('test_prefix', 'v6')
    # Note: Sequence number must not be present in the switch 
    pfx_v6.set_prefix('fff:1::2:3/8', 'permit', '10')
    
    as_path = NX.AsPath('testAccList')
    as_path.set_access_list('permit', '1234')
    
    comm = NX.CommunityList('comrule', 'standard')
    # Note: Sequence number must not be present in the switch 
    comm_entry = NX.CommunityEntry('permit', 
                    'internet,local-AS,no-advertise,no-export,1:2', '5')
    comm.add(comm_entry)
    
    rpm.add(route_map)
    rpm.add(pfx_v4)
    rpm.add(pfx_v6)
    rpm.add(as_path)
    rpm.add(comm)
    print rpm.get_json()
    
    ''' Push RPM configuration to the switch '''
    resp = session.push_to_switch(rpm.get_url(), rpm.get_json())
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)
        
    # Uncomment below two lines to delete specific route-map
    '''
    resp = session.delete(route_map.get_url())
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)
    '''
    
    # Uncomment below two lines to delete specific ip prefix-list
    '''
    resp = session.delete(pfx_v4.get_url())
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)
    '''
        
    # Uncomment below two lines to delete specific ipv6 prefix-list
    '''
    print pfx_v6.get_url()
    resp = session.delete(pfx_v6.get_url())
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)
    '''
        
    # Uncomment below two lines to delete specific AsPath access-list
    '''
    resp = session.delete(as_path.get_url())
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)
    '''
        
    # Uncomment below two lines to delete specific community-list
    '''
    resp = session.delete(comm.get_url())
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)
    '''
        
        
if __name__ == '__main__':
    main()
