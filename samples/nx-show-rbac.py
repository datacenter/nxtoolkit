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
Simple application that logs on to the Switch and displays RBAC details.
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
                    Switch and displays RBAC details.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
        
    rbac = NX.RBAC.get(session)
    print "Password Max Length:", rbac.pwd_max_len
    print "Password Min Length:", rbac.pwd_min_len
    print "Password Secure Mode Enabled:", rbac.pwd_secure_mode 
    print "Password Strength Check Enabled:", rbac.pwd_strength_check
    
    print "List of roles:"
    print "==============="
    for role in rbac.roles:
        print role
    
    # Uncomment the below lines to get specific role 
    '''  
    rbac = NX.RBAC.get(session, role_name='test-role')
    for role in rbac.roles:
        print role
    '''
    
    print "List of users and user details:"
    print "==============================="
    for user in rbac.users:
        print "User:", user.name
        print "Roles:"
        for role in user.user_roles: print role
        print "Ssh key:", user.ssh_key
    
    # Uncomment below lines to get specific user details
    '''
    print "User Details"
    print "============="
    user  = NX.AaaUser.get(session, 'test1')
    print "User:", user.name
    print "Roles:"
    for role in user.user_roles: print role
    print "Ssh key:", user.ssh_key
    '''
    
    print "Radius Server Details"
    print "========================="
    rad = NX.AaaRadius.get(session)
    print "timeout value:", rad.timeout
    print "retransmission count:", rad.retries
    print "source interface:", rad.src_int
        
    print "total number of servers:", len(rad.servers)
    print "following RADIUS servers are configured:"
    for provider in rad.servers:
        print provider.name
        print "\ttimeout:", provider.timeout
        print "\tretries:", provider.retries
        
    # To get specific host details from Radius server
    '''
    rad = NX.AaaRadius.get(session, host_name='1.2.3.4')
    for provider in rad.servers:
        print provider.name
        print "\ttimeout:", provider.timeout
        print "\tretries:", provider.retries
    '''
            
    print "Tacacs+ Server Details"
    print "========================="
    tac = NX.AaaTacacs.get(session)
    print "timeout value:", tac.timeout
    print "deadtime value:", tac.deadtime
    print "source interface:", tac.src_int
        
    print "total number of servers:", len(tac.servers)
    print "following TACACS+ servers are configured:"
    for provider in tac.servers:
        print provider.name
        print "\tavailable on port:", provider.port
        print "\ttimeout:", provider.timeout
            
    print "total number of groups:",len(tac.groups)
    print "following TACACS+ server groups are configured:" 
    for group in tac.groups:
        print "group name:", group.name
        print "\tdeadtime is ", group.deadtime
        print "\tvrf is ", group.vrf
        for servers in group.grp_servers:
            print "\t\tserver", servers.server
            
    # To get specific host details from Tacacs+ server
    '''
    tac_host = NX.AaaTacacs.get(session, host_name='1.2.3.4')
    for provider in tac_host.servers:
        print provider.name
        print "\tavailable on port:", provider.port
        print "\ttimeout:", provider.timeout
    '''
            
    # To get specific group details from Tacacs+ server
    '''
    tac_grp = NX.AaaTacacs.get(session, grp_name='tac1')
    for group in tac_grp.groups:
        print "group name:", group.name
        print "\tdeadtime is ", group.deadtime
        print "\tvrf is ", group.vrf
        for servers in group.grp_servers:
            print "\t\tserver", servers.server
    '''
            
    print "AAA Details"
    print "============="
    aaa  = NX.AaaAaa.get(session)
    print ("Authentication Details")
    print ("Default provider group:%s\tProtocol:%s\tError-enabled:%s" %
           (aaa.auth_prov_grp, aaa.auth_protocol, aaa.errEn))
    print ("Authorization Details")
    print ("Default provider group:%s\tCommand type:%s" % 
           (aaa.author_prov_grp, aaa.cmd_type))
    print ("Accounting Details")
    print ("Default provider group:%s" % aaa.acc_prov_grp)
    
    
if __name__ == '__main__':
    main()