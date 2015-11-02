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
Simple application that logs on to the Switch and displays RPM details.
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
                    Switch and displays RPM details.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
        
        
    print "Specific Route-map details:"
    print "============================"
    rt_map = NX.RouteMap.get(session, 'Test_route_map')
    print "Name:", rt_map.name
    for entry in rt_map.rt_map_entries:
        print ("Action:%s\tSequence number:%s" % (entry.action, entry.seq_no))
        print "Description: ", entry.descr
        print "Match Clauses:"
        for as_path in entry.as_paths:
            for name in as_path.matches:
                print "\tas-path (as-path filter): ", name.rs_name
        
        for prefix in entry.v4_prefix_list:
            for name in prefix.matches:
                print "\tip address prefix-lists: ", name.rs_name
                
        for prefix in entry.v6_prefix_list:
            for name in prefix.matches:
                print "\tipv6 address prefix-lists: ", name.rs_name
        
        for rt_tags in entry.rt_tags:
            print "\ttag: ", rt_tags.tag
            
        for comm in entry.community:
            for name in comm.matches:
                print "\tcommunity  (community-list filter): ", name.rs_name
            
        for rt_type in entry.rt_types:
            print "\troute-type: ", rt_type.type
            
        print "Set Clauses:"
        for hop in entry.next_hops:
            print "\tip next-hop ", hop.addr
        for pref in entry.local_preferences:
            print "\tlocal-preference ", pref.local_pref
        for origin in entry.origin:
            print "\torigin ", origin.origin
        for community in entry.comm_list:
            print "\tcomm-list ", community.comm_name
           
            
    print "Specific IP Prefix-list details:"
    print "============================"
    pfx = NX.PrefixList.get(session, 'test_prefix')
    print "Name:", pfx.name
    for prefix in pfx.prefix_list:
        print ("Prefix Address:%s\tAction:%s\tSequence number:%s" % 
               (prefix.pfx_addr, prefix.action, prefix.seq_no))
        
    print "Specific IPV6 Prefix-list details:"
    print "============================"
    pfx = NX.PrefixList.get(session, 'test_prefix', 'v6')
    print "Name:", pfx.name
    for prefix in pfx.prefix_list:
        print ("Prefix Address:%s\tAction:%s\tSequence number:%s" % 
               (prefix.pfx_addr, prefix.action, prefix.seq_no))


    print "Specific AS-Path Access-list details:"
    print "====================================="
    as_path = NX.AsPath.get(session, 'testAccList')
    print "Name:", as_path.name
    for access in as_path.access_lists:
        print ("Action:%s\tRegex:%s\tSequence number:%s" % (access.action,
                access.regex, access.seq_no))
    
    
    print "Specific Community-list details:"
    print "================================="
    comm_list = NX.CommunityList.get(session, 'comrule')
    print "Name", comm_list.name
    for entry in comm_list.comm_entries:
        print "Action:%s\tSequence number:%s" % (entry.action, entry.seq_no)
        for item in entry.comm_items:
            print item.community
        
        
if __name__ == '__main__':
    main()        