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
Simple application that logs on to the Switch and Configure RBAC
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
                    Switch and Configure RBAC.'''
    creds = NX.Credentials('switch', description)
    args = creds.get()

    ''' Login to Switch '''
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
        
    rbac = NX.RBAC()
    rbac.create_role('test-role')
    rbac.enable_pwd_strength_check()
    rbac.enable_pwd_secure_mode()
    rbac.set_pwd_max_length('127')
    rbac.set_pwd_min_length('4')
    
    #user = NX.AaaUser(name='test1', password='Test1', role='network-admin') 
    user = NX.AaaUser(name='test1', password='Test1', role='network-admin', 
                      ssh_key='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDczcGut'
                      'F5w331l0bNAeDSqKmwzLYYjElGIEogIE04rE0kX+CaWP/nDVEwETT'
                      'sKlp5w4gi0mA9/4kpk7gDGRCmAiNT8MWaTYt4ewGj+dZ+fbpUUf5t'
                      'v1DwLvxcQOoQ3qvxazOQWOLxwSW7zrJBpSokEtDNyY6BlsXP33q2h'
                      'gOBeAw==')
    
    rad_server = NX.AaaRadius()
    rad_server.set_retries('4')
    rad_server.set_timeout('30')
    rad_server.set_src_interface('lo0')
    rad_server.set_key(key='cisco', key_enc='7')
    rad_server.add_host('1.2.3.4', key='cisco', key_enc='7', timeout='5', 
                        retries='3')
    
    tacacs = NX.AaaTacacs()
    tacacs.set_deadtime('10')
    tacacs.set_timeout('20')
    tacacs.set_src_interface('mgmt 0')
    tacacs.set_key(key='cisco', key_enc='7')
    tacacs.add_host('1.2.3.3', key='cisco', key_enc='7', port='50', 
                    timeout='30')
    tacacs.add_group('tac1', vrf='management', deadtime='10', 
                     server='1.2.3.3')
    
    aaa = NX.AaaAaa()
    aaa.disable_auth_login('error-enable')
    aaa.enable_auth_login('ascii-authentication')
    aaa.set_auth_default_grp('tac1') #pass default group name
    aaa.set_author_default_grp() #pass default group name and cmd type
    aaa.set_acc_default_grp('tac1') #pass default group name
    
    rbac.add(user)
    rbac.add(rad_server)
    rbac.add(tacacs)
    rbac.add(aaa)
    
    print rbac.get_json()
    ''' Push RBAC configuration to the switch '''
    resp = session.push_to_switch(rbac.get_url(), rbac.get_json())
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)
     
  
    # NOTE: Complete deletion of rbac configuration will delete admin 
    #Configuration as well
    
    # Uncomment below two lines to delete specific role
    '''
    rbac = NX.RBAC.get(session)
    resp = session.delete(rbac.roles[0].get_delete_url('test-role'))
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)
    '''
        
    # Uncomment the below lines to delete specific user
    '''
    user = NX.AaaUser.get(session, 'test1')
    resp = session.delete(user.get_url())
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)
    '''
    
    # Uncomment below two lines to delete radius-server host
    '''
    radius = NX.AaaRadius.get(session)
    resp = session.delete(radius.servers[0].get_delete_url('1.2.3.4'))
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)
    '''
    
    # Uncomment below lines to delete tacacs-server details
    '''
    tacacs = NX.AaaTacacs.get(session)
    # To delete tacacs-server host
    resp = session.delete(tacacs.servers[0].get_delete_url('1.2.3.3'))
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)
        
    # To delete tacacs-server group
    resp = session.delete(tacacs.groups[0].get_delete_url('name'))
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)
        
    # To delete tacacs-server group host
    resp = session.delete(tacacs.groups[0].grp_servers[0].get_delete_url(
                                                    'tac1', '1.2.3.3'))
    if not resp.ok:
        print resp.text
        print ('Could not push to Switch')
        exit(0)
    '''
    
    
if __name__ == '__main__':
    main()
 
    