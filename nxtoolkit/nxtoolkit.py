###############################################################################
#                                                                             #
# Copyright (c) 2015 Cisco Systems                                            #
# All Rights Reserved.                                                        #
#                                                                             #
#    Licensed under the Apache License, Version 2.0 (the "License"); you may  #
#    not use this file except in compliance with the License. You may obtain  #
#    a copy of the License at                                                 #
#                                                                             #
#        http://www.apache.org/licenses/LICENSE-2.0                           #
#                                                                             #
#    Unless required by applicable law or agreed to in writing, software      #
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT#
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the #
#    License for the specific language governing permissions and limitations  #
#    under the License.                                                       #
#                                                                             #
###############################################################################
"""  Main NX Toolkit module
     This is the main module that comprises the NX Toolkit.
"""
import sys
from .nxTable import Table
from .nxphysobject import *
from .nxbaseobject import BaseNXObject, BaseRelation, BaseInterface
from .nxsession import Session
from .nxtoolkitlib import Credentials
import logging
import json
import socket


def cmdline_login_to_apic(description=''):
    # Take login credentials from the command line if provided
    # Otherwise, take them from your environment variables file ~/.profile
    creds = Credentials('apic', description)
    args = creds.get()

    # Login to Switch
    session = Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)
    return session


class Subnet(BaseNXObject):
    """ Subnet :  roughly equivalent to fvSubnet """

    def __init__(self, subnet_name, parent=None):
        """
        :param subnet_name: String containing the name of this Subnet instance
        :param parent: An instance of BridgeDomain class representing the\
                       BridgeDomain which contains this Subnet.
        """
        super(Subnet, self).__init__(subnet_name, parent)
        self._addr = None
        self._scope = None

    @classmethod
    def _get_switch_classes(cls):
        """
        Get the Switch classes used by this nxtoolkit class.

        :returns: list of strings containing Switch class names
        """
        resp = []
        resp.append('fvSubnet')
        return resp

    def get_addr(self):
        """
        Get the subnet address

        :returns: The subnet address as a string in the form of <ipaddr>/<mask>
        """
        return self._addr

    def set_addr(self, addr):
        """
        Set the subnet address

        :param addr: The subnet address as a string in the form\
                     of <ipaddr>/<mask>
        """
        if addr is None:
            raise TypeError('Address can not be set to None')
        self._addr = addr

    def get_scope(self):
        """
        Get the subnet scope

        :returns: The subnet scope as a string
        """
        return self._scope

    def set_scope(self, scope):
        """
        Set the subnet address

        :param scope: The subnet scope. It can be either "public", "private" or "shared".
        """
        if scope is None:
            raise TypeError('Scope can not be set to None')
        self._scope = scope

    def get_json(self):
        """
        Returns json representation of the subnet

        :returns: json dictionary of subnet
        """
        attributes = self._generate_attributes()
        if self.get_addr() is None:
            raise ValueError('Subnet address is not set')
        attributes['ip'] = self.get_addr()
        if self.get_scope() is not None:
            attributes['scope'] = self.get_scope()
        return super(Subnet, self).get_json('fvSubnet', attributes=attributes)

    def _populate_from_attributes(self, attributes):
        """
        Sets the attributes when creating objects from the Switch.
        Called from the base object when calling the classmethod get()
        """
        self.set_addr(str(attributes.get('ip')))

    @classmethod
    def get(cls, session, bridgedomain, tenant):
        """
        Gets all of the Subnets from the Switch for a particular tenant and
        bridgedomain.

        :param session: the instance of Session used for Switch communication
        :param bridgedomain: the instance of BridgeDomain used to limit the\
                             Subnet instances retreived from the Switch
        :param tenant: the instance of Tenant used to limit the Subnet\
                       instances retreived from the Switch
        :returns: List of Subnet objects

        """
        return BaseNXObject.get(session, cls, 'fvSubnet',
                                 parent=bridgedomain, tenant=tenant)


class L3Inst(BaseNXObject):
    """ L3Inst or VRF:  roughly equivalent to ACI Context """

    def __init__(self, l3inst_name, parent=None):
        """
        :param l3inst_name: String containing the L3Inst name
        :param parent: An instance of Tenant class representing the Tenant
                       which contains this L3Inst.

        """
        super(L3Inst, self).__init__(l3inst_name, parent)
        self.name = l3inst_name
        self.adminState = 'admin-up'
        self._children = []

    def add_l2bd(self, l2bd_obj=None):

        if not isinstance(l2bd_obj, L2BD):
            raise TypeError('A L2BD object required')

        self._children.append(l2bd_obj)

    @classmethod
    def _get_switch_classes(cls):
        """
        Get the Switch classes used by this nxtoolkit class.

        :returns: list of strings containing Switch class names
        """
        resp = []
        resp.append('l3Inst')
        return resp

    @classmethod
    def _get_toolkit_to_switch_classmap(cls):
        """
        Gets the Nexus class to an nxtoolkit class mapping dictionary

        :returns: dict of Switch class names to nxtoolkit classes
        """
        return {}

    @staticmethod
    def _get_parent_class():
        """
        Gets the class of the parent object

        :returns: class of parent object
        """
        return None

    @staticmethod
    def get_url(fmt='json'):
        """
        Get the URL used to push the configuration to the Switch
        if no format parameter is specified, the format will be 'json'
        otherwise it will return '/api/mo/uni.' with the format string
        appended.

        :param fmt: optional format string, default is 'json'
        :returns: URL string
        """
        return '/api/mo/sys.' + fmt

    @staticmethod
    def _get_parent_dn(dn):
        return dn.split('/ctx-')[0]

    @staticmethod
    def _get_name_from_dn(dn):
        return dn.split('/ctx-')[1].split('/')[0]

    @staticmethod
    def _get_tenant_from_dn(dn):
        """
        Get the tenant name from the DN

        :param dn: String containing the DN
        :return: string containing the tenant name
        """
        return dn.split('/tn-')[1].split('/')[0]

    def _populate_from_attributes(self, attributes):
        """
        Sets the attributes when creating objects from the Switch.
        Called from the base object when calling the classmethod get()
        """
        self.descr = attributes.get('descr')
        self.known_mcast = attributes.get('knwMcastAct')
        self.modified_time = attributes.get('modTs')
        self.name = attributes.get('name')
        self.class_id = attributes.get('pcTag')
        self.scope = attributes.get('scope')
        self.vnid = attributes.get('seg')
        dn = attributes.get('dn')
        if dn is not None:
            self.tenant = self._get_tenant_from_dn(dn)
        else:
            self.tenant = None
        if attributes.get('pcEnfPref') == 'unenforced':
            allow_all = True
        else:
            allow_all = False
        self.set_allow_all(allow_all)

    def get_json(self):
        """
        Returns json representation of fvCtx object

        :returns: json dictionary of fvCtx object
        """
        attributes = self._generate_attributes()
        return super(L3Inst, self).get_json(self._get_switch_classes()[0],
                                             attributes=attributes)

    @classmethod
    def get(cls, session, tenant=None):
        """
        Gets all of the L3Insts from the Switch.

        :param session: the instance of Session used for Switch communication
        :param tenant: the instance of Tenant used to limit the L3Insts\
                       retreived from the Switch
        :returns: List of L3Inst objects
        """
        return BaseNXObject.get(session, cls, cls._get_switch_classes()[0],
                                 tenant, tenant)

    @staticmethod
    def get_table(l3insts, title=''):
        """
        Will create table of l3inst information
        :param title:
        :param l3insts:
        """

        headers = ['Tenant',
                   'L3Inst',
                   'VNID', 'Scope', 'Class ID',
                   'Allow All',
                   'Known MCST', 'Modified Time',
                   ]
        data = []
        for l3inst in sorted(l3insts):
            data.append([
                l3inst.get_parent().name,
                l3inst.name,
                l3inst.vnid,
                l3inst.scope,
                l3inst.class_id,
                l3inst.allow_all,
                l3inst.known_mcast,
                l3inst.modified_time
            ])

        data = sorted(data)
        table = Table(data, headers, title=title + 'L3Inst')
        return [table, ]


class L2BD(BaseNXObject):
    """
    L2BD:  roughly equivalent to ACI BD
    """

    def __init__(self, bd_name, parent=None):
        """
        :param bd_name:  String containing the name of this L2BD
                         object.
        :param parent: An instance of Tenant class representing the Tenant
                       which contains this L2BD.
        """
        super(L2BD, self).__init__(bd_name, parent)
        self.adminSt = 'active'
        self.operSt = 'Down'
        self.fabEncap = bd_name
        self.bd_name = bd_name
        self.unkMacUcastAct = 'flood'
        self.unkMcastAct = 'flood'

    @classmethod
    def _get_switch_classes(cls):
        """
        Get the Switch classes used by this nxtoolkit class.

        :returns: list of strings containing Switch class names
        """
        resp = []
        resp.append('l2BD')
        return resp

    @classmethod
    def _get_toolkit_to_switch_classmap(cls):
        """
        Gets the Switch class to an nxtoolkit class mapping dictionary

        :returns: dict of Switch class names to nxtoolkit classes
        """
        return {'fvSubnet': Subnet, }

    @staticmethod
    def _get_parent_class():
        """
        Gets the class of the parent object

        :returns: class of parent object
        """
        return L3Inst

    @staticmethod
    def _get_parent_dn(dn):
        return dn.split('/bd-')[0]

    @staticmethod
    def _get_name_from_dn(dn):
        return dn.split('/bd-')[1].split('/')[0].split('[')[1].split(']')[0]

    def set_unknown_mac_unicast(self, unicast):
        """
        Set the unknown mac unicast for this BD

        :param unicast: Unicast to assign this L2BD
        """
        valid_unicast = ('flood')
        if unicast not in valid_unicast:
            raise ValueError('unknown MAC unicast must be of: %s or %s' % valid_unicast)
        self.unkMacUcastAct = unicast

    def get_unknown_mac_unicast(self):
        """
        Gets the unknown mac unicast for this BD

        :returns: unknown mac unicast of the L2BD
        """
        return self.unkMacUcastAct

    def set_unknown_multicast(self, multicast):
        """
        Set the unknown multicast for this BD

        :param multicast: Multicast to assign this L2BD
        """
        valid_multicast = ('flood', 'opt-flood')
        if multicast not in valid_multicast:
            raise ValueError('unknown multicast must be of: %s or %s' % valid_multicast)
        self.unkMcastAct = multicast

    def get_unknown_multicast(self):
        """
        Gets the unknown multicast for this BD

        :returns: unknown multicast of the L2BD
        """
        return self.unkMcastAct

    def get_json(self):
        """
        Returns json representation of the bridge domain

        :returns: json dictionary of bridge domain
        """
        children = []
        attr = self._generate_attributes()
        attr['unkMacUcastAct'] = self.unkMacUcastAct
        attr['unkMcastAct'] = self.unkMcastAct
        attr['adminSt'] = self.adminSt
        attr['fabEncap'] = self.fabEncap
        attr['id'] = self.bd_name.split('-')[1]
        return super(L2BD, self).get_json(self._get_switch_classes()[0],
                                                  attributes=attr,
                                                  children=children)

    def _extract_relationships(self, data):
        vrf_children = data[0]['l3Inst']['children']
        for child in vrf_children:
            if 'l2BD' in child:
                bd_name = child['l2BD']['attributes']['name']
                if bd_name == self.name:
                    bd_children = child['l2BD']['children']
                    for bd_child in bd_children:
                        bd_name = self.name
                    break
        super(L2BD, self)._extract_relationships(data)

    # Subnet
    def add_subnet(self, subnet):
        """
        Add a subnet to this BD.

        :param subnet: Instance of Subnet class to add to this L2BD.
        """
        if not isinstance(subnet, Subnet):
            raise TypeError('add_subnet requires a Subnet instance')
        if subnet.get_addr() is None:
            raise ValueError('Subnet address is not set')
        if subnet in self.get_subnets():
            return
        self.add_child(subnet)

    def remove_subnet(self, subnet):
        """
        Remove a subnet from this BD

        :param subnet: Instance of Subnet class to remove from this\
                       L2BD.
        """
        if not isinstance(subnet, Subnet):
            raise TypeError('remove_subnet requires a Subnet instance')
        self.remove_child(subnet)

    def get_subnets(self):
        """
        Get all of the subnets on this BD.

        :returns: List of Subnet instances assigned to this L2BD.
        """
        resp = []
        children = self.get_children()
        for child in children:
            if isinstance(child, Subnet):
                resp.append(child)
        return resp

    def has_subnet(self, subnet):
        """
        Check if the BD has this particular subnet.

        :returns: True or False.  True if this L2BD has this\
                  particular Subnet.
        """
        if not isinstance(subnet, Subnet):
            raise TypeError('has_subnet requires a Subnet instance')
        if subnet.get_addr() is None:
            raise ValueError('Subnet address is not set')
        return self.has_child(subnet)

    @classmethod
    def get(cls, session):
        """
        Gets all of the Bridge Domains from the Switch.

        :param session: the instance of Session used for Switch communication
        :returns: List of L2BD objects
        """
        return BaseNXObject.get(session, cls, cls._get_switch_classes()[0])

    def _get_url_extension(self):
        return '/bd-[%s]' % self.name
    
    def get_url(self, fmt='.json'):
        
        # Default inst is used
        return '/api/node/mo/sys/inst-default' + self._get_url_extension() + fmt

    def _populate_from_attributes(self, attributes):
        """
        Populates various attributes
        :param attributes:
        :return:
        """
        self.class_id = attributes.get('pcTag')
        self.bridgeMode = attributes.get('bridgeMode')
        self.hw_id = attributes.get('hwId')
        self.id = attributes.get('id')
        self.adminSt = attributes.get('adminSt')
        self.operSt = attributes.get('operSt')
        self.unkMacUcastAct = attributes.get('unkMacUcastAct')
        self.unkMcastAct = attributes.get('unkMcastAct')
        self.modified_time = attributes.get('modTs')

    @staticmethod
    def get_table(bridge_domains, title=''):
        """
        Will create table of l3inst information
        :param title:
        :param bridge_domains:
        """

        headers = ['ID',
                   'HW ID',
                   'Admin',
                   'Oper',
                   'Subnets',
                   'Bridge Mode',
                   'Unknown UCST',
                   'Unknown MCST',
                   ]
        data = []
        for bridge_domain in sorted(bridge_domains):

            subnets = bridge_domain.get_subnets()
            subnet_str = []
            for subnet in subnets:
                subnet_str.append(subnet.get_addr())

            data.append([
                bridge_domain.id,
                bridge_domain.hwId,
                bridge_domain.adminSt,
                bridge_domain.operSt,
                ', '.join(subnet_str),
                bridge_domain.bridgeMode,
                bridge_domain.unkMacUcastAct,
                bridge_domain.unkMcastAct,
            ])

        data = sorted(data)
        table = Table(data, headers, title=title + 'Bridge Domains')
        return [table, ]


class BGPPeerAF(BaseNXObject):
    """ BGPPeerAF :  roughly equivalent to bgpPeerAf """

    def __init__(self, type, parent=None):
        """
        :param subnet_name: String containing the name of this BGPPeer instance.
        :param parent: An instance of BGPPeer class representing the\
                       BGPPeer which contains this BGPPeerAf.
        """
        if not isinstance(parent, BGPPeer):
            raise TypeError('Parent of BGPPeerAF class must be BGPPeer')
        super(BGPPeerAF, self).__init__(type, parent)
        self._type = type

    @classmethod
    def _get_switch_classes(cls):
        """
        Get the Switch classes used by this nxtoolkit class.

        :returns: list of strings containing Switch class names
        """
        resp = []
        resp.append('bgpPeerAf')
        return resp

    @staticmethod
    def _get_parent_class():
        """
        Gets the nxtoolkit class of the parent object

        :returns: class of parent object
        """
        return BGPPeer

    @classmethod
    def _get_toolkit_to_switch_classmap(cls):
        """
        Gets the Switch class to an nxtoolkit class mapping dictionary

        :returns: dict of Switch class names to nxtoolkit classes
        """
        return {}

    @classmethod
    def _get_url_extension(self):
        return '/af-%s' % self._af_type

    def get_type(self):
        """
        Get the bgpPeerAf type

        :returns: The bgpPeerAf type as a string
        """
        return self._type

    def set_type(self, af_type):
        """
        Set the bgpPeer type

        :param type: The bgpPeerAf type as a string
        """
        if af_type is None:
            raise TypeError('AF Type can not be set to None')
        valid_af_types = ['ipv4-ucast', 'l2vpn-evpn']
        if af_type not in valid_af_types:
            raise ValueError('AF type specified is not valid')
        self._type = af_type

    def get_json(self):
        """
        Returns json representation of the bgpPeer

        :returns: json dictionary of subnet
        """
        attributes = self._generate_attributes()
        if self.get_type() is None:
            raise ValueError('BGPPeer AF is not set')
        attributes['type'] = self.get_type()
        return super(BGPPeerAF, self).get_json('bgpPeerAf', attributes=attributes)

    def _populate_from_attributes(self, attributes):
        """
        Sets the attributes when creating objects from the Switch.
        Called from the base object when calling the classmethod get()
        """
        self.set_type(str(attributes.get('type')))

    @classmethod
    def get(cls, session, bgppeer, tenant):
        """
        Gets all of the BGPPeerAFs from the Switch for a particular BGPPeer

        :param session: the instance of Session used for Switch communication
        :param bgppeer: the instance of BGPPeer using the AF
        :returns: List of BGPPeerAF objects

        """
        return BaseNXObject.get(session, cls, 'bgpPeerAf', parent=bgppeer)


class BGPPeer(BaseNXObject):
    """ BGPPeer :  roughly equivalent to bgpPeer """

    def __init__(self, addr, parent=None):
        """
        :param subnet_name: String containing the name of this BGPPeer
                    instance.
        :param parent: An instance of BGPDomain class representing the\
                       BGPDomain which contains this BGPPeer.
        """

        #TBD: Validation of address

        if not isinstance(parent, BGPDomain):
            raise TypeError('Parent of BGPPeer class must be BGPDomain')
        super(BGPPeer, self).__init__(addr, parent)
        self._addr = addr
        self._remote_as = None
        self._adminSt = 'enabled'
        self._src_if = None

    @classmethod
    def _get_switch_classes(cls):
        """
        Get the Switch classes used by this nxtoolkit class.

        :returns: list of strings containing Switch class names
        """
        resp = []
        resp.append('bgpPeer')
        return resp

    @staticmethod
    def _get_parent_class():
        """
        Gets the nxtoolkit class of the parent object

        :returns: class of parent object
        """
        return BGPDomain

    @classmethod
    def _get_toolkit_to_switch_classmap(cls):
        """
        Gets the Switch class to an nxtoolkit class mapping dictionary

        :returns: dict of Switch class names to nxtoolkit classes 
        """
        return {'bgpPeerAf': BGPPeerAF}

    @staticmethod
    def _get_url_extension(self):
        return '/peer-[%s]' % self._addr

    def get_addr(self):
        """
        Get the bgpPeer address

        :returns: The bgpPeer address as a string in the form of <ipaddr>/<mask>
        """
        return self._addr

    def set_addr(self, addr):
        """
        Set the bgpPeer address

        :param addr: The bgpPeer address as a string in the form\
                     of <ipaddr>/<mask>
        """
        if addr is None:
            raise TypeError('Address can not be set to None')
        self._addr = addr

    def get_remote_as(self):
        """
        Get the bgpPeer remote-as

        :returns: The bgpPeer remote-as as a string
        """
        return self._remote_as

    def set_remote_as(self, remote_as):
        """
        Set the bgpPeer remote-as

        :param remote-as: The bgpPeer remote-as.
        """
        if remote_as is None:
            raise TypeError('remote-as can not be set to None')
        self._remote_as = remote_as

    def get_src_if(self):
        """
        Get the bgpPeer source interface

        :returns: The bgpPeer source interface as a string
        """
        return self._src_if

    def set_src_if(self, src_if):
        """
        Set the bgpPeer source interface

        :param src_if: The bgpPeer source interface
        """
        if src_if is None:
            raise TypeError('src-if can not be set to None')
        self._src_if = src_if

    # AF
    def add_af(self, af):
        """
        Add a af to this BGP Peer.

        :param af: Instance of BGPPeerAF class to add to this bgpInst.
        """
        if not isinstance(af, BGPPeerAF):
            raise TypeError('add_af requires a BGPPeerAF instance')
        if af.get_type() is None:
            raise ValueError('BGPPeerAF Type is not set')
        if af in self.get_afs():
            return
        self.add_child(af)

    def remove_af(self, af):
        """
        Remove a af from this BGP Peer

        :param af: Instance of BGPPeerAF class to remove from this\
                       bgpInst.
        """
        if not isinstance(af, BGPPeerAF):
            raise TypeError('remove_af requires a BGPPeerAF instance')
        self.remove_child(af)

    def get_afs(self):
        """
        Get all of the afs on this BGP Peer.

        :returns: List of BGPPeerAF instances assigned to this bgpInst.
        """
        resp = []
        children = self.get_children()
        for child in children:
            if isinstance(child, BGPPeerAF):
                resp.append(child)
        return resp

    def has_af(self, af):
        """
        Check if the BGP Peer has this particular af.

        :returns: True or False.  True if this bgpInst has this\
                  particular BGPPeerAF.
        """
        if not isinstance(af, BGPPeerAF):
            raise TypeError('has_af requires a BGPPeerAF instance')
        if af.get_type() is None:
            raise ValueError('BGPPeerAF type is not set')
        return self.has_child(af)

    def get_json(self):
        """
        Returns json representation of the bgpPeer

        :returns: json dictionary of subnet
        """
        attributes = self._generate_attributes()
        if self.get_addr() is None:
            raise ValueError('BGPPeer address is not set')
        attributes['addr'] = self.get_addr()
        if self.get_remote_as() is not None:
            attributes['asn'] = self.get_remote_as()
        if self.get_src_if() is not None:
            attributes['srcIf'] = self.get_src_if()
        return super(BGPPeer, self).get_json('bgpPeer', attributes=attributes)

    def _populate_from_attributes(self, attributes):
        """
        Sets the attributes when creating objects from the Switch.
        Called from the base object when calling the classmethod get()
        """
        self.set_addr(str(attributes.get('addr')))
        self.set_remote_as(str(attributes.get('asn')))
        self.set_src_if(str(attributes.get('srcIf')))

    @classmethod
    def get(cls, session, bgpdomain):
        """
        Gets all of the BGPPeers from the Switch for a particular BGPDomain

        :param session: the instance of Session used for Switch communication
        :param bgpdomain: the instance of BGPDomain used to limit the\
                             BGPPeer instances retreived from the Switch
        :returns: List of BGPPeer objects

        """
        return  BaseNXObject.get_filtered(session, cls,
                                          cls._get_switch_classes()[0], bgpdomain)


class BGPAdvPrefix(BaseNXObject):
    """ BGPAdvPrefix :  roughly equivalent to bgpAdvPrefix """

    def __init__(self, addr, parent=None):
        """
        :param addr: String containing the address of this Prefix
        :param parent: An instance of BGPDomainAF class representing the\
                       BGPDomain Address Family which contains this prefix.
        """

        #TBD: Validation of address

        if not isinstance(parent, BGPDomainAF):
            raise TypeError('Parent of BGPAdvPrefix class must be BGPDomainAF')
        super(BGPAdvPrefix, self).__init__(addr, parent)
        self._addr = addr

    @classmethod
    def _get_switch_classes(cls):
        """
        Get the Switch classes used by this nxtoolkit class.

        :returns: list of strings containing Switch class names
        """
        resp = []
        resp.append('bgpAdvPrefix')
        return resp

    @staticmethod
    def _get_parent_class():
        """
        Gets the nxtoolkit class of the parent object

        :returns: class of parent object
        """
        return BGPDomainAF

    @classmethod
    def _get_toolkit_to_switch_classmap(cls):
        """
        Gets the Switch class to an nxtoolkit class mapping dictionary

        :returns: dict of Switch class names to nxtoolkit classes
        """
        return {}

    @staticmethod
    def _get_url_extension(self):
        return '/prefix-[%s]' % self._addr

    def get_addr(self):
        """
        Get the bgpPeer address

        :returns: The bgpPeer address as a string in the form of <ipaddr>/<mask>
        """
        return self._addr

    def set_addr(self, addr):
        """
        Set the bgpPeer address

        :param addr: The bgpPeer address as a string in the form\
                     of <ipaddr>/<mask>
        """
        if addr is None:
            raise TypeError('Address can not be set to None')
        self._addr = addr

    def get_json(self):
        """
        Returns json representation of the bgpPeer

        :returns: json dictionary of subnet
        """
        attributes = self._generate_attributes()
        if self.get_addr() is None:
            raise ValueError('BGPAdvPrefix address is not set')
        attributes['addr'] = self.get_addr()
        return super(BGPAdvPrefix, self).get_json('bgpAdvPrefix', attributes=attributes)

    def _generate_attributes(self):
        attributes = {}
        attributes['addr'] = self._addr
        return attributes

    def _populate_from_attributes(self, attributes):
        """
        Sets the attributes when creating objects from the Switch.
        Called from the base object when calling the classmethod get()
        """
        self.set_addr(str(attributes.get('addr')))

    @classmethod
    def get(cls, session, bgpdomainaf):
        """
        Gets all of the BGPAdvPrefix from the Switch for a particular BGPDomainAF

        :param session: the instance of Session used for Switch communication
        :param bgpdomainaf: the instance of BGPDomainAF used to limit the\
                             BGPAdvPrefix instances retreived from the Switch
        :returns: List of BGPAdvPrefix objects

        """
        return BaseNXObject.get(session, cls, 'bgpAdvPrefix', parent=bgpdomainaf)


class BGPDomainAF(BaseNXObject):
    """ BGPDomainAF :  roughly equivalent to bgpDomAf """

    def __init__(self, af_type, parent=None):
        """
        :param subnet_name: String containing the name of this BGPPeer
                instance.
        :param parent: An instance of BGPPeer class representing the\
                       BGPPeer which contains this BGPPeerAf.
        """
        if not isinstance(parent, BGPDomain):
            raise TypeError('Parent of BGPDomainAF class must be BGPDomain')
        super(BGPDomainAF, self).__init__(af_type, parent)
        self._type = af_type

    @classmethod
    def _get_switch_classes(cls):
        """
        Get the Switch classes used by this nxtoolkit class.

        :returns: list of strings containing Switch class names
        """
        resp = []
        resp.append('bgpDomAf')
        return resp

    @staticmethod
    def _get_parent_class():
        """
        Gets the nxtoolkit class of the parent object

        :returns: class of parent object
        """
        return BGPDomain

    @classmethod
    def _get_toolkit_to_switch_classmap(cls):
        """
        Gets the Switch class to an nxtoolkit class mapping dictionary

        :returns: dict of Switch class names to nxtoolkit classes
        """
        return {'bgpAdvPrefix': BGPAdvPrefix}

    @staticmethod
    def _get_url_extension(self):
        return '/af-%s' % self.name

    def get_type(self):
        """
        Get the bgpDomAf type

        :returns: The bgpDomAf type as a string
        """
        return self._type

    def set_type(self, af_type):
        """
        Set the bgpDomAf type

        :param type: The bgpDomAf type as a string
        """
        if af_type is None:
            raise TypeError('AF Type can not be set to None')
        valid_af_types = ['ipv4-ucast', 'l2vpn-evpn']
        if af_type not in valid_af_types:
            raise ValueError('AF type specified is not valid')
        self._type = af_type

    # BGPAdvPrefix
    def add_adv_prefix(self, adv_prefix):
        """
        Add a adv_prefix to this BGPDomainAF.

        :param adv_prefix: Instance of BGPAdvPrefix class to add to this BGPDomainAF.
        """
        if not isinstance(adv_prefix, BGPAdvPrefix):
            raise TypeError('add_adv_prefix requires a BGPAdvPrefix instance')
        if adv_prefix.get_addr() is None:
            raise ValueError('BGPAdvPrefix address is not set')
        if adv_prefix in self.get_adv_prefixs():
            return
        self.add_child(adv_prefix)

    def remove_adv_prefix(self, adv_prefix):
        """
        Remove a adv_prefix from this BGPDomainAF

        :param adv_prefix: Instance of BGPAdvPrefix class to remove from this\
                       BGPDomainAF.
        """
        if not isinstance(adv_prefix, BGPAdvPrefix):
            raise TypeError('remove_adv_prefix requires a BGPAdvPrefix instance')
        self.remove_child(adv_prefix)

    def get_adv_prefixs(self):
        """
        Get all of the adv_prefixs on this BGPDomainAF.

        :returns: List of BGPAdvPrefix instances assigned to this BGPDomainAF.
        """
        resp = []
        children = self.get_children()
        for child in children:
            if isinstance(child, BGPAdvPrefix):
                resp.append(child)
        return resp

    def has_adv_prefix(self, adv_prefix):
        """
        Check if the BGPDomainAF has this particular adv_prefix.

        :returns: True or False.  True if this BGPDomainAF has this\
                  particular BGPAdvPrefix.
        """
        if not isinstance(adv_prefix, BGPAdvPrefix):
            raise TypeError('has_adv_prefix requires a BGPAdvPrefix instance')
        if adv_prefix.get_addr() is None:
            raise ValueError('BGPAdvPrefix address is not set')
        return self.has_child(adv_prefix)

    def get_json(self):
        """
        Returns json representation of the bgpDomAf

        :returns: json dictionary of adv_prefix
        """
        attributes = self._generate_attributes()
        if self.get_type() is None:
            raise ValueError('BGPPeer AF is not set')
        attributes['type'] = self.get_type()
        return super(BGPDomainAF, self).get_json('bgpDomAf', attributes=attributes)

    def _populate_from_attributes(self, attributes):
        """
        Sets the attributes when creating objects from the Switch.
        Called from the base object when calling the classmethod get()
        """
        self.set_type(str(attributes.get('type')))

    @classmethod
    def get(cls, session, bgpdomain):
        """
        Gets all of the BGPDomainAF from the Switch for a particular BGPDomain

        :param session: the instance of Session used for Switch communication
        :param bgpdomain: the instance of BGPDomain using the AF
        :returns: List of BGPDomainAF objects

        """
        return  BaseNXObject.get_filtered(session, cls,
                                               cls._get_switch_classes()[0], bgpdomain)


class BGPDomain(BaseNXObject):
    """
    Creates an BGP router interface that can be attached to a L3 interface.
    This interface defines the BGP AS, authentication, etc.
    """

    def __init__(self, name, parent=None):
        """
        :param name:  String containing the name of this BGPDomain object.
        :param as_num: String containing the IPv4 as_num
        :param peer_ip: String containing the IP address of the BGP peer
                        Default is None.
        :param node_id: String Containing the node-id (e.g. '101')
        """
        super(BGPDomain, self).__init__(name, parent)
        self._name = name
        self.options = ''
        self.networks = []

    @staticmethod
    def is_bgp():
        """
        :returns: True if this interface is an BGP Session.  In the case\
                  of BGPDomain instances, this is always True.
        """
        return True

    @classmethod
    def _get_switch_classes(cls):
        """
        Get the Switch classes used by this nxtoolkit class.

        :returns: list of strings containing Switch class names
        """
        resp = []
        resp.append('bgpDom')
        return resp

    @classmethod
    def _get_parent_class():
        """
        Gets the nxtoolkit class of the parent object

        :returns: class of parent object
        """
        return BGPSession

    @classmethod
    def _get_toolkit_to_switch_classmap(cls):
        """
        Gets the Switch class to an nxtoolkit class mapping dictionary

        :returns: dict of Switch class names to nxtoolkit classes
        """
        return {'bgpDomAf': BGPDomainAF,
                'bgpPeer': BGPPeer}

    @staticmethod
    def _get_url_extension(self):
        return '/dom-%s' % self._name

    # Name
    
    def get_name(self):
        """
        Get the bgpDomain Name

        :returns: The bgpDomain Name as a string
        """
        return self._name

    def set_name(self, name):
        """
        Set the bgpDomain Name

        :param as_num: The bgpDomain Name as a string
        """
        if name is None:
            raise TypeError('Name can not be set to None')
        self._name = name

    # Router ID
    def get_router_id(self):
        """
        Get the bgpPeer address

        :returns: The bgpPeer address as a string in the form of <ipaddr>/<mask>
        """
        return self._router_id

    def set_router_id(self, addr):
        """
        Set the bgpPeer address

        :param addr: The bgpPeer address as a string in the form\
                     of <ipaddr>/<mask>
        """
        if addr is None:
            raise TypeError('Address can not be set to None')
        self._router_id = addr

    # Peer
    def add_peer(self, peer):
        """
        Add a peer to this BGP Domain.

        :param peer: Instance of BGPPeer class to add to this bgpInst.
        """
        if not isinstance(peer, BGPPeer):
            raise TypeError('add_peer requires a BGPPeer instance')
        if peer.get_addr() is None:
            raise ValueError('BGPPeer address is not set')
        if peer.get_remote_as() is None:
            raise ValueError('BGPPeer remote-as is not set')
        if peer in self.get_peers():
            return
        self.add_child(peer)

    def remove_peer(self, peer):
        """
        Remove a peer from this bgpInst

        :param peer: Instance of BGPPeer class to remove from this\
                       bgpInst.
        """
        if not isinstance(peer, BGPPeer):
            raise TypeError('remove_peer requires a BGPPeer instance')
        self.remove_child(peer)

    def get_peers(self):
        """
        Get all of the peers on this bgpInst.

        :returns: List of BGPPeer instances assigned to this bgpInst.
        """
        resp = []
        children = self.get_children()
        for child in children:
            if isinstance(child, BGPPeer):
                resp.append(child)
        return resp

    def has_peer(self, peer):
        """
        Check if the bgpInst has this particular peer.

        :returns: True or False.  True if this bgpInst has this\
                  particular BGPPeer.
        """
        if not isinstance(peer, BGPPeer):
            raise TypeError('has_peer requires a BGPPeer instance')
        if peer.get_addr() is None:
            raise ValueError('BGPPeer address is not set')
        if peer.get_remote_as() is None:
            raise ValueError('BGPPeer remote-as is not set')
        return self.has_child(peer)

    # AF
    def add_af(self, af):
        """
        Add a af to this BGP Domain.

        :param af: Instance of BGPDomainAF class to add to this bgpInst.
        """
        if not isinstance(af, BGPDomainAF):
            raise TypeError('add_af requires a BGPDomainAF instance')
        if af.get_type() is None:
            raise ValueError('BGPDomainAF Type is not set')
        if af in self.get_afs():
            return
        self.add_child(af)

    def remove_af(self, af):
        """
        Remove a af from this bgpInst

        :param af: Instance of BGPDomainAF class to remove from this\
                       bgpInst.
        """
        if not isinstance(af, BGPDomainAF):
            raise TypeError('remove_af requires a BGPDomainAF instance')
        self.remove_child(af)

    def get_afs(self):
        """
        Get all of the afs on this bgpInst.

        :returns: List of BGPDomainAF instances assigned to this bgpInst.
        """
        resp = []
        children = self.get_children()
        for child in children:
            if isinstance(child, BGPDomainAF):
                resp.append(child)
        return resp

    def has_af(self, af):
        """
        Check if the bgpInst has this particular af.

        :returns: True or False.  True if this bgpInst has this\
                  particular BGPDomainAF.
        """
        if not isinstance(af, BGPDomainAF):
            raise TypeError('has_af requires a BGPDomainAF instance')
        if af.get_type() is None:
            raise ValueError('BGPDomainAF type is not set')
        return self.has_child(af)

    @classmethod
    def get_deep(cls, session, names=[], limit_to=[], subtree='full', config_only=False):
        resp = []
        assert isinstance(names, list), ('names should be a list'
                                         ' of strings')

        # If no tenant names passed, get all tenant names from Switch
        if len(names) == 0:
            bgpdomains = BGPDomain.get(session)
            for bgpdomain in bgpdomains:
                names.append(bgpdomain.name)

        if len(limit_to):
            limit = '&rsp-subtree-class='
            for class_name in limit_to:
                limit += class_name + ','
            limit = limit[:-1]
        else:
            limit = ''
        for name in names:
            query_url = ('/api/mo/sys/bgp/inst/dom-%s.json?query-target=self&'
                         'rsp-subtree=%s' % (name, subtree))
            query_url += limit
            if config_only:
                query_url += '&rsp-prop-include=config-only'
            ret = session.get(query_url)

            # the following works around a bug encountered in the json returned from the Switch
            ret._content = ret._content.replace("\\\'", "'")

            data = ret.json()['imdata']
            if len(data):
                obj = super(BGPDomain, cls).get_deep(full_data=data,
                                                  working_data=data,
                                                  parent=None,
                                                  limit_to=limit_to,
                                                  subtree=subtree,
                                                  config_only=config_only)
                obj._extract_relationships(data)
                resp.append(obj)
        return resp


    def _generate_attributes(self):
        attributes = super(BGPDomain, self)._generate_attributes()
        attributes['rtrId'] = self._router_id
        attributes['name'] = self._name
        return attributes

    def _populate_from_attributes(self, attributes):
        self._router_id = str(attributes['rtrId'])
        self._name = str(attributes['name'])

    def get_json(self):
        """
        Returns json representation of BGPDomain

        :returns: json dictionary of BGP Domain
        """

        attr = self._generate_attributes()
        return super(BGPDomain, self).get_json(self._get_switch_classes()[0],
                                                attributes=attr)

    @classmethod
    def get(cls, session, parent=None):
        """
        Gets all of the BGP Domains from the Switch.

        :param parent: Parent object of the BGPDomain
        :param session: the instance of Session used for Switch communication
        :returns: a list of BGPDomain objects
        """
        bgpdomains = BaseNXObject.get_filtered(session, cls, 
                                               cls._get_switch_classes()[0], parent)

        if parent:
            if isinstance(parent, BGPSession):
                for bgpdomain in bgpdomains:
                    parent.add_child(bgpdomain)

        return bgpdomains

    @classmethod
    def exists(cls, session, bgpdomain):
        """
        Check if a bgpdomain exists on the Switch.

        :param session: the instance of Session used for Switch communication
        :param bgpdomain: the instance of BGPDomain to check if exists on the Switch
        :returns: True or False
        """
        sw_bgpdomains = cls.get(session)
        for sw_bgpdomain in sw_bgpdomains:
            if bgpdomain == sw_bgpdomain:
                return True
        return False

    @staticmethod
    def get_identifier(cls):
        return cls._name

    @staticmethod
    def get_url(str, fmt='json'):
        """
        Get the URL used to push the configuration to the Switch
        if no format parameter is specified, the format will be 'json'
        otherwise it will return '/api/mo/sys/bgp/inst.' with the format string
        appended.

        :param fmt: optional format string, default is 'json'
        :returns: URL string
        """
        return '/api/mo/sys/bgp/inst/dom-%s/.' % (str) + fmt

    @staticmethod
    def get_table(bgpdomains, title=''):
        """
        Will create table of switch context information
        :param title:
        :param bgpdomains:
        """

        headers = ['ROUTER ID']
        data = []
        for bgpdomain in sorted(bgpdomains):
            data.append([
                bgpdomain._router_id])

        data = sorted(data)
        table = Table(data, headers, title=title + 'BGP Domains')
        return [table, ]


class BGPSession(BaseNXObject):
    """
    Creates an BGP router interface that can be attached to a L3 interface.
    This interface defines the BGP AS, authentication, etc.
    """

    def __init__(self, as_num, parent=None):
        """
        :param as_num: String containing the IPv4 as_num
        """
        super(BGPSession, self).__init__(as_num)
        self._as_num = as_num
        self.options = ''

    @staticmethod
    def is_bgp():
        """
        :returns: True if this interface is an BGP Session.  In the case\
                  of BGPSession instances, this is always True.
        """
        return True

    @classmethod
    def _get_switch_classes(cls):
        """
        Get the Switch classes used by this nxtoolkit class.

        :returns: list of strings containing Switch class names
        """
        resp = []
        resp.append('bgpInst')
        return resp

    @staticmethod
    def _get_parent_class():
        """
        Gets the nxtoolkit class of the parent object

        :returns: class of parent object
        """
        return LogicalModel

    @staticmethod
    def _get_url_extension(self):
        return '/bgp/inst'
    
    @staticmethod
    def get_identifier(cls):
        return cls._as_num

    # AS Num
    def get_as_num(self):
        """
        Get the bgpSession AS Number

        :returns: The bgpSession AS Number as a string
        """
        return self._as_num

    def set_as_num(self, as_num):
        """
        Set the bgpSession AS Num

        :param as_num: The bgpSession AS Number as a string
        """
        if as_num is None:
            raise TypeError('AS Number can not be set to None')
        self._as_num = as_num

    # Domains
    def add_domain(self, domain):
        """
        Add a BGP Domain to this BGP Session.

        :param domain: Instance of BGPDomain class to add to this bgpInst.
        """
        if not isinstance(domain, BGPDomain):
            raise TypeError('add_domain requires a BGPDomain instance')
        if domain.get_name() is None:
            raise ValueError('BGPDomain name is not set')
        if domain.get_router_id() is None:
            raise ValueError('BGPDomain router-id is not set')
        if domain in self.get_domains():
            return
        self.add_child(domain)

    def remove_domain(self, domain):
        """
        Remove a domain from this bgpInst

        :param domain: Instance of BGPDomain class to remove from this\
                       bgpInst.
        """
        if not isinstance(domain, BGPDomain):
            raise TypeError('remove_domain requires a BGPDomain instance')
        self.remove_child(domain)

    def get_domains(self):
        """
        Get all of the domains on this bgpInst.

        :returns: List of BGPDomain instances assigned to this bgpInst.
        """
        resp = []
        children = self.get_children()
        for child in children:
            if isinstance(child, BGPDomain):
                resp.append(child)
        return resp

    def has_domain(self, domain):
        """
        Check if the bgpInst has this particular domain.

        :returns: True or False.  True if this bgpInst has this\
                  particular BGPDomain.
        """
        if not isinstance(domain, BGPDomain):
            raise TypeError('has_domain requires a BGPDomain instance')
        if domain.get_name() is None:
            raise ValueError('BGPDomain name is not set')
        if domain.get_router_id() is None:
            raise ValueError('BGPDomain router-id is not set')
        return self.has_child(domain)

    @classmethod
    def get_deep(cls, session, names=[], limit_to=[], subtree='full', config_only=False):
        resp = []
        assert isinstance(names, list), ('names should be a list'
                                         ' of strings')

        # If no tenant names passed, get all tenant names from Switch
        if len(names) == 0:
            bgpsessions = BGPSession.get(session)
            for bgpsession in bgpsessions:
                names.append(bgpsession.name)

        if len(limit_to):
            limit = '&rsp-subtree-class='
            for class_name in limit_to:
                limit += class_name + ','
            limit = limit[:-1]
        else:
            limit = ''
        for name in names:
            query_url = ('/api/mo/sys/bgp/inst.json?query-target=self&'
                         + 'rsp-subtree=%s' % (subtree))
            query_url += limit
            if config_only:
                query_url += '&rsp-prop-include=config-only'
            ret = session.get(query_url)

            # the following works around a bug encountered in the json returned from the Switch
            ret._content = ret._content.replace("\\\'", "'")

            data = ret.json()['imdata']
            if len(data):
                obj = super(BGPSession, cls).get_deep(full_data=data,
                                                  working_data=data,
                                                  parent=None,
                                                  limit_to=limit_to,
                                                  subtree=subtree,
                                                  config_only=config_only)
                obj._extract_relationships(data)
                resp.append(obj)
        return resp

    def _generate_attributes(self):
        attributes = {}
        attributes['asn'] = self._as_num
        return attributes

    def _populate_from_attributes(self, attributes):
        self._as_num = str(attributes['asn'])
    
    def get_json(self):
        """
        Returns json representation of BGPSession

        :returns: json dictionary of BGP Session
        """

        attr = self._generate_attributes()
        bgp_inst = super(BGPSession, self).get_json(self._get_switch_classes()[0],
                                                attributes=attr)

        return {'bgpEntity': {'attributes': {},
                       'children': [bgp_inst]}}

    @classmethod
    def get(cls, session, parent=None):
        """
        Gets all of the BGP Sessions from the Switch.

        :param parent: Parent object of the BGPSession
        :param session: the instance of Session used for Switch communication
        :returns: a list of BGPSession objects
        """
        bgpsessions = BaseNXObject.get(session, cls, cls._get_switch_classes()[0])

        if parent:
            if isinstance(parent, LogicalModel):
                for bgpsession in bgpsessions:
                    parent.add_child(bgpsession)
        return bgpsessions

    @classmethod
    def exists(cls, session, bgpsession):
        """
        Check if a bgpsession exists on the Switch.

        :param session: the instance of Session used for Switch communication
        :param bgpsession: the instance of BGPSession to check if exists on the Switch
        :returns: True or False
        """
        sw_bgpsessions = cls.get(session)
        for sw_bgpsession in sw_bgpsessions:
            if bgpsession == sw_bgpsession:
                return True
        return False

    @staticmethod
    def get_url(str, fmt='json'):
        """
        Get the URL used to push the configuration to the Switch
        if no format parameter is specified, the format will be 'json'
        otherwise it will return '/api/mo/sys/bgp/inst.' with the format string
        appended.

        :param fmt: optional format string, default is 'json'
        :returns: URL string
        """
        return '/api/mo/sys/bgp/.' + fmt

    @staticmethod
    def get_table(bgpsessions, title=''):
        """
        Will create table of switch context information
        :param title:
        :param bgpsessions:
        """

        headers = ['AS NUM']
        data = []
        for bgpsession in sorted(bgpsessions):
            data.append([bgpsession._as_num])

        data = sorted(data)
        table = Table(data, headers, title=title + 'BGP Sessions')
        return [table, ]


class FilterEntry(BaseNXObject):
    """ FilterEntry :  roughly equivalent to vzEntry """

    def __init__(self, name, parent, applyToFrag='0', arpOpc='0',
                 dFromPort='0', dToPort='0', etherT='0', prot='0',
                 sFromPort='0', sToPort='0', tcpRules='0'):
        """
        :param name: String containing the name of this FilterEntry instance.
        :param applyToFrag: True or False.  True indicates that this\
                            FilterEntry should be applied to IP fragments.
        :param arpOpc: 'req' or 'reply'.  Indicates that this FilterEntry\
                       should be applied to ARP Requests or ARP replies.
        :param dFromPort: String containing the lower L4 destination port\
                          number of the L4 destination port number range.
        :param dToPort: String containing the upper L4 destination port\
                        number of the L4 destination port number range.
        :param etherT: String containing the EtherType of the frame to be\
                       matched by this FilterEntry.
        :param prot: String containing the L4 protocol number to be\
                     matched by this FilterEntry.
        :param sFromPort: String containing the lower L4 source port\
                          number of the L4 source port number range.
        :param sToPort: String containing the upper L4 source port\
                        number of the L4 source port number range.
        :param tcpRules: Bit mask consisting of the TCP flags to be matched\
                         by this FilterEntry.
        """
        self.applyToFrag = applyToFrag
        self.arpOpc = arpOpc
        self.dFromPort = dFromPort
        self.dToPort = dToPort
        self.etherT = etherT
        self.prot = prot
        self.sFromPort = sFromPort
        self.sToPort = sToPort
        self.tcpRules = tcpRules
        super(FilterEntry, self).__init__(name, parent)

    def _generate_attributes(self):
        attributes = super(FilterEntry, self)._generate_attributes()
        attributes['applyToFrag'] = self.applyToFrag
        attributes['arpOpc'] = self.arpOpc
        attributes['dFromPort'] = self.dFromPort
        attributes['dToPort'] = self.dToPort
        attributes['etherT'] = self.etherT
        attributes['prot'] = self.prot
        attributes['sFromPort'] = self.sFromPort
        attributes['sToPort'] = self.sToPort
        attributes['tcpRules'] = self.tcpRules
        return attributes

    def _populate_from_attributes(self, attributes):
        self.applyToFrag = str(attributes['applyToFrag'])
        self.arpOpc = str(attributes['arpOpc'])
        self.dFromPort = str(attributes['dFromPort'])
        self.dToPort = str(attributes['dToPort'])
        self.etherT = str(attributes['etherT'])
        self.prot = str(attributes['prot'])
        self.sFromPort = str(attributes['sFromPort'])
        self.sToPort = str(attributes['sToPort'])
        self.tcpRules = str(attributes['tcpRules'])

    def get_json(self):
        """
        Returns json representation of the FilterEntry

        :returns: json dictionary of the FilterEntry
        """
        attr = self._generate_attributes()
        text = super(FilterEntry, self).get_json('vzEntry',
                                                 attributes=attr)
        filter_name = self.get_parent().name + self.name
        text = {'vzFilter': {'attributes': {'name': filter_name},
                             'children': [text]}}
        return text

    @classmethod
    def get(cls, session, parent, tenant):
        """
        To get all of nxtoolkit style Filter Entries Switch class.

        :param session:  the instance of Session used for Switch communication
        :param parent:  Object to assign as the parent to the created objects.
        :param tenant:  Tenant object to assign the created objects.
        """

        apic_class = 'vzRsSubjFiltAtt'

        if isinstance(tenant, str):
            raise TypeError
        logging.debug('%s.get called', cls.__name__)
        if tenant is None:
            tenant_url = ''
        else:
            tenant_url = '/tn-%s' % tenant.name
            if parent is not None:
                tenant_url = tenant_url + parent._get_url_extension()
        query_url = ('/api/mo/uni%s.json?query-target=subtree&'
                     'target-subtree-class=%s' % (tenant_url, apic_class))
        ret = session.get(query_url)
        data = ret.json()['imdata']
        logging.debug('response returned %s', data)
        resp = []
        for object_data in data:
            dn = object_data['vzRsSubjFiltAtt']['attributes']['dn']
            tDn = object_data['vzRsSubjFiltAtt']['attributes']['tDn']
            tRn = object_data['vzRsSubjFiltAtt']['attributes']['tRn']
            if dn.split('/')[2][4:] == parent.name and \
               dn.split('/')[4][len(apic_class) - 1:] == dn.split('/')[3][5:] and \
               dn.split('/')[3][5:] == tDn.split('/')[2][4:] and tDn.split('/')[2][4:] == tRn[4:]:
                filter_name = str(object_data[apic_class]['attributes']['tRn'][4:])
                contract_name = filter_name[:len(parent.name)]
                entry_name = filter_name[len(parent.name):]
                if contract_name == parent.name and entry_name != '':
                    query_url = ('/api/mo/uni%s/flt-%s.json?query-target=subtree&'
                                 'target-subtree-class=vzEntry&'
                                 'query-target-filter=eq(vzEntry.name,"%s")' % (tenant_url, filter_name, entry_name))
                    ret = session.get(query_url)
                    filter_data = ret.json()['imdata']
                    if len(filter_data) == 0:
                        continue
                    logging.debug('response returned %s', filter_data)
                    resp = []
                    obj = cls(entry_name, parent)
                    attribute_data = filter_data[0]['vzEntry']['attributes']
                    obj._populate_from_attributes(attribute_data)
                    resp.append(obj)
        return resp

    @classmethod
    def create_from_apic_json(cls, data, parent):
        """
        create from the apic json

        :param data: json dictionary
        :param parent: parent object
        :return: object created from json dictionary
        """
        attributes = data['vzEntry']['attributes']
        entry = cls(name=str(attributes.get('name')),
                    parent=parent)
        entry._populate_from_attributes(attributes)
        return entry

    @staticmethod
    def get_table(filters, title=''):
        """
        Will create table of filter information for a given tenant
        :param title:
        :param filters:
        """

        headers = ['Filter', 'EtherType',
                   'Protocol', 'Arp Opcode', 'L4 DPort', 'L4 SPort', 'TCP Flags', 'Apply to Fragment']

        data = []
        for filter in sorted(filters, key=lambda x: (x.name)):
            data.append([
                filter.name,
                filter.etherT,
                filter.prot,
                filter.arpOpc,
                FilterEntry._get_port(filter.dFromPort, filter.dToPort),
                FilterEntry._get_port(filter.sFromPort, filter.sToPort),
                filter.tcpRules,
                filter.applyToFrag,
            ])
        data = sorted(data)
        table = Table(data, headers, title=title + 'Filters')
        return [table, ]

    @staticmethod
    def _get_port(from_port, to_port):
        """
        will build a string that is a port range or a port number
        depending upon the from_port and to_port value
        """
        if from_port == to_port:
            return str(from_port)
        return '{0}-{1}'.format(str(from_port), str(to_port))

    def __eq__(self, other):
        if type(self) is not type(other):
            return False
        if self.applyToFrag != other.applyToFrag:
            return False
        if self.arpOpc != other.arpOpc:
            return False
        if self.dFromPort != other.dFromPort:
            return False
        if self.dToPort != other.dToPort:
            return False
        if self.etherT != other.etherT:
            return False
        if self.prot != other.prot:
            return False
        if self.sFromPort != other.sFromPort:
            return False
        if self.sToPort != other.sToPort:
            return False
        if self.tcpRules != other.tcpRules:
            return False
        return True


class PortChannel(BaseInterface):
    """
    This class defines a port channel interface.
    """

    def __init__(self, pc_id, admin_st=None, delay=None, descr=None,
                 layer=None, duplex=None, mtu=None,
                 snmp_trap=None, speed=None, link_log=None,
                 session=None, mode=None, min_link=None, interfaces=None,
                 pc_mode=None):
        
        if not isinstance(pc_id, str):
            raise TypeError ('string expected')
        self.if_name = 'po' + pc_id
        super(PortChannel, self).__init__(name=self.if_name)
        
        self.pc_id = pc_id
        self.admin_st = admin_st
        self.delay = delay
        self.descr = descr
        self.layer = layer
        self.duplex = duplex
        self.link_log = link_log
        self.mtu = mtu
        self.snmp_trap = snmp_trap
        self.speed = speed
        self._session = session
        self.mode = mode
        self.min_link = min_link
        self.access_vlan = None
        self.pc_mode = pc_mode
        if interfaces is None:
            self._interfaces = []
        else:
            self._interfaces = copy.deepcopy(interfaces)

        self._nodes = []

    def attach(self, interface):
        """Attach an interface to this PortChannel"""
        if interface not in self._interfaces:
            self._interfaces.append(interface)
            
    def set_access_vlan(self, access):
        """Set vlans for port channel"""
        self.access_vlan = access

    def detach(self, interface):
        """Detach an interface from this PortChannel"""
        if interface in self._interfaces:
            self._interfaces.remove(interface)

    def is_vpc(self):
        """Returns True if the PortChannel is a VPC"""
        return len(self._interfaces) > 1

    def is_interface(self):
        """Returns True since a PortChannel is an interface"""
        return True

    def _get_interfaces(self):
        """ Returns a single node id or multiple node ids in the
            case that this is a VPC
        """
        return self._interfaces
    
    def _get_attributes(self):

        attributes = {}
        attributes['pcId'] = self.pc_id
        if self.admin_st:
            attributes['adminSt'] = self.admin_st
        if self.delay:
            attributes['delay'] = self.delay
        if self.descr:
            attributes['descr'] = self.descr
        if self.duplex:
            attributes['duplex'] = self.duplex
        if self.layer:
            attributes['layer'] = self.layer
        if self.link_log:
            attributes['linkLog'] = self.link_log
        if self.mtu:
            attributes['mtu'] = self.mtu
        if self.snmp_trap:
            attributes['snmpTrapSt'] = self.snmp_trap
        if self.speed:
            attributes['speed'] = self.speed
        if self.mode:
            attributes['mode'] = self.mode
        if self.min_link:
            attributes['minLinks'] = self.min_link
        if self.pc_mode:
            attributes['pcMode'] = self.pc_mode
        if self.if_name:
            attributes['name'] = self.if_name
        attributes['id'] = self.if_name
        if self.access_vlan:
            attributes['accessVlan'] = self.access_vlan

        return attributes

    def get_url(self, fmt='json'):
        """
        Get the URLs used to push the configuration to the Switch
        if no format parameter is specified, the format will be 'json'
        otherwise it will return '/api/mo/uni.' with the format string
        appended.
        :param fmt: optional format string, default is 'json'
        :returns: URL string
        """
        #return '/api/mo/sys/aggr-[po%s].json' % (self.pc_id)
        return '/api/mo/sys/intf/aggr-[po%s].json' % (self.pc_id)

    def get_json(self):
        """
        Returns json representation of the PortChannel

       :returns: json dictionary of the PortChannel
        """  
        attributes = self._get_attributes()
        
        children = []
        for interface in self._interfaces:
            att = {'tDn': 'sys/intf/phys-[%s]' % (interface.if_name)}
            child = BaseNXObject.get_json(self, 'pcRsMbrIfs', attributes=att)
            children.append(child)
            
        return super(PortChannel, self).get_json('pcAggrIf',
                                                 attributes=attributes,
                                                 children=children)

    @staticmethod
    def get(session, pc_id=None):
        """Gets all of the port channel interfaces from the Switch
        
        :param session: the instance of Session used for switch communication
        :param pc_id: string port channel id
        :return list of PortChannel objects
        """
        
        if not isinstance(session, Session):
            raise TypeError('An instance of Session class is required')
        
        if pc_id:
            if not isinstance(pc_id, str):
                raise TypeError('When specifying a specific port channel id'
                            'the port id must be a identified by a str')
            query_url = '/api/mo/sys/aggr-[po%s].json?rsp-subtree=full'\
                                                        % str(pc_id)
        else:
            query_url = '/api/class/pcAggrIf.json?rsp-subtree=full'

        pc_list = []
        
        port_chs = session.get(query_url).json()['imdata']
        for pc in port_chs:
            pc_id = str(pc['pcAggrIf']['attributes']['pcId'])
            layer = str(pc['pcAggrIf']['attributes']['layer'])
            admin_st = str(pc['pcAggrIf']['attributes']['adminSt'])
            desc = str(pc['pcAggrIf']['attributes']['descr'])
            duplex = str(pc['pcAggrIf']['attributes']['duplex'])
            delay = str(pc['pcAggrIf']['attributes']['duplex'])
            link_log = str(pc['pcAggrIf']['attributes']['linkLog'])
            mtu = str(pc['pcAggrIf']['attributes']['mtu'])
            snmp_trap = str(pc['pcAggrIf']['attributes']['snmpTrapSt'])
            speed = str(pc['pcAggrIf']['attributes']['speed'])
            session = session
            mode = str(pc['pcAggrIf']['attributes']['mode'])
            min_link = str(pc['pcAggrIf']['attributes']['minLinks'])
            pc_mode = str(pc['pcAggrIf']['attributes']['pcMode'])
            access_vlan = str(pc['pcAggrIf']['attributes']['accessVlan'])
            trunk_vlans = str(pc['pcAggrIf']['attributes']['trunkVlans'])
            
            interfaces = []
            for int in pc['pcAggrIf']['children']:
                if int.get('pcRsMbrIfs'):
                    interface = str(int['pcRsMbrIfs']['attributes']['tSKey'])
                    #module = interface.replace('eth', '').split('/')[0]
                    #port = interface.replace('eth', '').split('/')[1]
                    #interfaces.append(Interface('eth', module, port))
                    interfaces.append(Interface(interface))
                    
            new_pc = PortChannel(pc_id=pc_id, admin_st=admin_st,
                                       layer=layer, descr=desc, duplex=duplex,
                                       delay=delay, link_log=link_log,
                                       mtu=mtu, snmp_trap=snmp_trap,
                                       speed=speed, session=session, mode=mode,
                                       min_link=min_link, interfaces=interfaces,
                                       pc_mode=pc_mode)
            new_pc.set_access_vlan(access_vlan)
   
            pc_list.append(new_pc)
        return pc_list


class L2ExtDomain(BaseNXObject):
    """
    L2ExtDomain class
    """

    def __init__(self, name, parent):
        """
        :param name: String containing the L2ExtDomain name
        :param parent: An instance of DomP class representing
        """
        self.dn = None
        self.lcOwn = None
        self.childAction = None
        self.name = name
        super(L2ExtDomain, self).__init__(name, parent)

    def get_json(self):
        """
        Returns json representation of the l2extDomP object

        :returns: A json dictionary of fvTenant
        """
        attr = self._generate_attributes()
        return super(L2ExtDomain, self).get_json(self._get_switch_classes()[0],
                                                 attributes=attr)

    def _generate_attributes(self):
        """
        Gets the attributes used in generating the JSON for the object
        """
        attributes = dict()
        if self.name:
            attributes['name'] = self.name
        if self.dn:
            attributes['dn'] = self.dn
        if self.lcOwn:
            attributes['lcOwn'] = self.lcOwn
        if self.childAction:
            attributes['childAction'] = self.childAction
        return attributes

    @classmethod
    def _get_switch_classes(cls):
        """
        Get the Switch classes used by this nxtoolkit class.

        :returns: list of strings containing Switch class names
        """
        resp = []
        resp.append('l2extDomP')
        return resp

    def get_parent(self):
        """
        :returns: Parent of this object.
        """
        return self._parent

    @classmethod
    def get(cls, session):

        """
        Gets all of the L2Ext Domains from the Switch

        :param session: the instance of Session used for Switch communication
        :returns: List of L2ExtDomain objects

        """
        toolkit_class = cls
        apic_class = cls._get_switch_classes()[0]
        parent = None
        logging.debug('%s.get called', cls.__name__)
        query_url = (('/api/mo/uni.json?query-target=subtree&'
                      'target-subtree-class=') + str(apic_class))
        ret = session.get(query_url)
        data = ret.json()['imdata']
        logging.debug('response returned %s', data)
        resp = []
        for object_data in data:
            name = str(object_data[apic_class]['attributes']['name'])
            obj = toolkit_class(name, parent)
            attribute_data = object_data[apic_class]['attributes']
            obj._populate_from_attributes(attribute_data)
            obj.dn = object_data[apic_class]['attributes']['dn']
            obj.lcOwn = object_data[apic_class]['attributes']['lcOwn']
            obj.childAction = object_data[apic_class]['attributes']['childAction']
            resp.append(obj)
        return resp

    @classmethod
    def get_by_name(cls, session, infra_name):

        """
        Gets all of the Physical Domainss from the Switch

        :param session: the instance of Session used for Switch communication
        :returns: List of L2ExtDomain objects

        """
        toolkit_class = cls
        apic_class = cls._get_switch_classes()[0]
        parent = None
        logging.debug('%s.get called', cls.__name__)
        query_url = (('/api/mo/uni.json?query-target=subtree&'
                      'target-subtree-class=') + str(apic_class))
        ret = session.get(query_url)
        data = ret.json()['imdata']
        logging.debug('response returned %s', data)

        for object_data in data:
            name = str(object_data[apic_class]['attributes']['name'])
            obj = toolkit_class(name, parent)
            attribute_data = object_data[apic_class]['attributes']
            obj._populate_from_attributes(attribute_data)
            obj.dn = object_data[apic_class]['attributes']['dn']
            obj.lcOwn = object_data[apic_class]['attributes']['lcOwn']
            obj.childAction = object_data[apic_class]['attributes']['childAction']

            if name == infra_name:
                return obj
        return None


class L3ExtDomain(BaseNXObject):
    """
    L3ExtDomain class
    """

    def __init__(self, name, parent):
        """
        :param name: String containing the name of the external routed domain
        :param parent: An instance of DomP class
        """
        self.dn = None
        self.lcOwn = None
        self.childAction = None
        self.name = name
        super(L3ExtDomain, self).__init__(name, parent)

    def get_json(self):
        """
        Returns json representation of the fvTenant object

        :returns: A json dictionary of fvTenant
        """
        attr = self._generate_attributes()
        return super(L3ExtDomain, self).get_json(self._get_switch_classes()[0],
                                                 attributes=attr)

    def _generate_attributes(self):
        """
        Gets the attributes used in generating the JSON for the object
        """
        attributes = dict()
        if self.name:
            attributes['name'] = self.name
        if self.dn:
            attributes['dn'] = self.dn
        if self.lcOwn:
            attributes['lcOwn'] = self.lcOwn
        if self.childAction:
            attributes['childAction'] = self.childAction
        return attributes

    @classmethod
    def _get_switch_classes(cls):
        """
        Get the Switch classes used by this nxtoolkit class.

        :returns: list of strings containing Switch class names
        """
        resp = []
        resp.append('l3extDomP')
        return resp

    def get_parent(self):
        """
        :returns: Parent of this object.
        """
        return self._parent

    @classmethod
    def get(cls, session):

        """
        Gets all of the Physical Domains from the Switch

        :param session: the instance of Session used for Switch communication
        :returns: List of L3Ext Domain objects

        """
        toolkit_class = cls
        apic_class = cls._get_switch_classes()[0]
        parent = None
        logging.debug('%s.get called', cls.__name__)
        query_url = (('/api/mo/uni.json?query-target=subtree'
                      '&target-subtree-class=') + str(apic_class))
        ret = session.get(query_url)
        data = ret.json()['imdata']
        logging.debug('response returned %s', data)
        resp = []
        for object_data in data:
            name = str(object_data[apic_class]['attributes']['name'])
            obj = toolkit_class(name, parent)
            attribute_data = object_data[apic_class]['attributes']
            obj._populate_from_attributes(attribute_data)
            obj.dn = object_data[apic_class]['attributes']['dn']
            obj.lcOwn = object_data[apic_class]['attributes']['lcOwn']
            obj.childAction = object_data[apic_class]['attributes']['childAction']

            resp.append(obj)
        return resp

    @classmethod
    def get_by_name(cls, session, infra_name):

        """
        Gets all of the L3Ext Domains from the Switch

        :param session: the instance of Session used for Switch communication
        :returns: List of L3Ext Domain objects

        """
        toolkit_class = cls
        apic_class = cls._get_switch_classes()[0]
        parent = None
        logging.debug('%s.get called', cls.__name__)
        query_url = (('/api/mo/uni.json?query-target=subtree&'
                      'target-subtree-class=') + str(apic_class))
        ret = session.get(query_url)
        data = ret.json()['imdata']
        logging.debug('response returned %s', data)

        for object_data in data:
            name = str(object_data[apic_class]['attributes']['name'])
            obj = toolkit_class(name, parent)
            attribute_data = object_data[apic_class]['attributes']
            obj._populate_from_attributes(attribute_data)
            obj.dn = object_data[apic_class]['attributes']['dn']
            obj.lcOwn = object_data[apic_class]['attributes']['lcOwn']
            obj.childAction = object_data[apic_class]['attributes']['childAction']

            if name == infra_name:
                return obj
        return None


class NetworkPool(BaseNXObject):
    """This class defines a pool of network ids
    """

    def __init__(self, name, encap_type, start_id, end_id, mode):
        super(NetworkPool, self).__init__(name)
        valid_encap_types = ['vlan', 'vxlan']
        if encap_type not in valid_encap_types:
            raise ValueError('Encap type specified is not a valid encap type')
        self.encap_type = encap_type
        self.start_id = start_id
        self.end_id = end_id
        valid_modes = ['static', 'dynamic']
        if mode not in valid_modes:
            raise ValueError('Mode specified is not a valid mode')
        self.mode = mode

    def get_json(self):
        from_id = self.encap_type + '-' + self.start_id
        to_id = self.encap_type + '-' + self.end_id
        fvnsEncapBlk = {'fvnsEncapBlk': {'attributes': {'name': 'encap',
                                                        'from': from_id,
                                                        'to': to_id},
                                         'children': []}}
        if self.encap_type == 'vlan':
            fvnsEncapInstP_string = 'fvnsVlanInstP'
        elif self.encap_type == 'vxlan':
            fvnsEncapInstP_string = 'fvnsVxlanInstP'
        fvnsEncapInstP = {fvnsEncapInstP_string: {'attributes': 
                                                  {'name': self.name,
                                                    'allocMode': self.mode},
                                                  'children': [fvnsEncapBlk]}}
        infra = {'infraInfra': {'attributes': {},
                                'children': [fvnsEncapInstP]}}
        return infra


class Search(BaseNXObject):
    """This is an empty class used to create a search object for use with
       the "find" method.

       Attaching attributes to this class and then invoking find will return
       all objects with matching attributes in the object hierarchy at and
       below where the find is invoked.
    """

    def __init__(self):
        pass


class BaseMonitorClass(object):
    """ Base class for monitoring policies. These are methods that can be
        used on all monitoring objects.
    """

    def set_name(self, name):
        """
        Sets the name of the MonitorStats.

       :param name: String to use as the name
        """
        self.name = str(name)
        self.modified = True

    def set_description(self, description):
        """
        Sets the description of the MonitorStats.

       :param description: String to use as the description
        """
        self.description = description
        self.modified = True

    def isModified(self):
        """
        Returns True if this policy and any children have been modified or
        created and not been written to the Switch
        """
        for child in self._children:
            if child.isModified():
                return True

        return self.modified

    def get_parent(self):
        """
       :returns: parent object
        """
        return self._parent

    def add_stats(self, stat_obj):
        """
        Adds a stats family object.

        :param stat_obj: Statistics family object of type MonitorStats.
        """
        self.monitor_stats[stat_obj.scope] = stat_obj
        self.modified = True

    def remove_stats(self, stats_family):
        """
        Remove a stats family object.  The object to remove is identified by
        a string, e.g. 'ingrPkts', or 'egrTotal'.  This string can be found
        in the 'MonitorStats.scope' attribute of the object.

        :param stats_family: Statistics family string.
        """
        if not isinstance(stats_family, str):
            raise TypeError('MonitorStats must be identified by a string')

        if stats_family in self.monitor_stats:
            self.monitor_stats.remove(stats_family)
            self.modified = True

    def add_target(self, target_obj):
        """
        Add a target object.

        :param target_obj: target object of type MonitorTarget
        """
        self.monitor_target[target_obj.scope] = target_obj
        self.modified = True

    def remove_target(self, target):
        """
        Remove a target object.  The object to remove is identified by
        a string, e.g 'l1PhysIf'.  This string can be found
        in the 'MonitorTarget.scope' attribute of the object.

        :param target: target to remove.
        """
        if not isinstance(target, str):
            raise TypeError('MonitorTarget must be identified by a string')

        if target in self.monitor_target:
            self.monitor_target.remove(target)
            self.modified = True

    def add_collection_policy(self, coll_obj):
        """
        Add a collection policy.

        :param coll_obj :  A collection policy object of type CollectionPolicy
        """
        self.collection_policy[coll_obj.granularity] = coll_obj
        self.modified = True

    def remove_collection_policy(self, collection):
        """
        Remove a collection_policy object.  The object to remove is identified
        by its granularity, e.g. '5min', '15min', etc.  This string can be
        found in the 'CollectionPolicy.granularity' attribute of the object.

        :param collection: CollectionPolicy to remove.
        """
        if collection not in CollectionPolicy.granularityEnum:
            raise TypeError(('CollectionPolicy must be identified by its'
                             'granularity'))

        if collection in self.collection_policy:
            self.collection_policy.remove(collection)
            self.modified = True


class MonitorPolicy(BaseMonitorClass):
    """
    This class is the top-most container for a monitoring policy that controls
    how statistics are gathered. It has immediate children, CollectionPolicy
    objects, that control the default behavior for any network element that
    uses this monitoring policy.  It may optionally have MonitorTarget objects
    as children that are used to override the default behavior for a
    particular target class such as Interfaces.  There can be further 
    granularity of control through children of the MonitorTarget sub-objects.

    Children of the MonitorPolicy will be CollectionPolicy objects that define
    the collection policy plus optional MonitorTarget objects that allow finer
    grained control over specific target Switch objects such as 'l1PhysIf'
    (layer 1 physical interface).

    The CollectionPolicy children are contained in a dictionary called
    "collection_policy" that is indexed by the granulariy of the
    CollectionPolicy, e.g. '5min', '15min', etc.

    The MonitorTarget children are contained in a dictionary called
    "monitor_target" that is indexed by the name of the target object,
    e.g. 'l1PhysIf'.

    To make a policy take effect for a particular port, for example, you must
    attach that monitoring policy to the port.

    Note that the name of the MonitorPolicy is used to construct the dn of the
    object in the Switch.  As a result, the name cannot be changed. 
    If you read a policy from the Switch, change the name, and write it back,
    it will create a new policy with the new name and leave the old, original
    policy, in place with its original name.

    A description may be optionally added to the policy.
    """

    def __init__(self, policyType, name):
        """
        The MonitorPolicy is initialized with simply a policy type and a name.
        There are two policy types: 'fabric' and 'access'.  The 'fabric'
        monitoring policies can be applied to certain MonitorTarget types and
        'access' monitoring policies can be applied to other MonitorTarget
        types. Initially however, both policies can have l1PhysIf as targets.

        A name must be specified because it is used to build the distinguising
        name (dn) along with the policyType in the Switch.  The dn for
        "fabric" policies will be /uni/fabric/monfabric-[name] and for "access"
        policies it will be /uni/infra/moninfra-[name] in the Switch.

        :param policyType:  String specifying whether this is a fabric or\
                            access policy
        :param name:        String specifying a name for the policy.
        """
        policyTypeEnum = ['fabric', 'access']

        if policyType not in policyTypeEnum:
            raise ValueError('Policy Type must be one of:', policyTypeEnum)

        self.name = name
        self.policyType = policyType
        self.descr = ''
        self.collection_policy = {}
        self.monitor_target = {}

        # assume that it has not been written to Switch.  This is cleared if the
        # policy is just loaded from Switch or the policy is written to the Switch.
        self.modified = True

    @classmethod
    def get(cls, session):
        """
        get() will get all of the monitor policies from the Switch and return
        them as a list.  It will get both fabric and access (infra) policies
        including default policies.

       :param session: the instance of Session used for Switch communication
       :returns: List of MonitorPolicy objects
        """
        result = []
        nxObjects = cls._getClass(session, 'monInfraPol')
        for data in nxObjects:
            name = str(data['monInfraPol']['attributes']['name'])
            policyObject = MonitorPolicy('access', name)
            policyObject.set_description(data['monInfraPol']['attributes']['descr'])
            cls._getPolicy(policyObject, session,
                           data['monInfraPol']['attributes']['dn'])
            result.append(policyObject)

        nxObjects = cls._getClass(session, 'monFabricPol')
        for data in nxObjects:
            name = str(data['monFabricPol']['attributes']['name'])
            policyObject = MonitorPolicy('fabric', name)
            policyObject.set_description(data['monFabricPol']['attributes']['descr'])
            cls._getPolicy(policyObject, session,
                           data['monFabricPol']['attributes']['dn'])
            result.append(policyObject)
        return result

    @staticmethod
    def _getClass(session, nxClass):
        """
        Get the class from the Switch

        :param session: Session object instance
        :param nxClass: string containing classname
        :return: JSON dictionary containing class instances
        """
        prefix = '/api/node/class/'
        suffix = '.json?query-target=self'
        class_query_url = prefix + nxClass + suffix
        ret = session.get(class_query_url)
        data = ret.json()['imdata']
        return data

    @classmethod
    def _getPolicy(cls, policyObject, session, dn):
        """
        Get the policy

        :param policyObject: policyObject
        :param session: Session class instance
        :param dn: string containing the distinguished name
        :return: None
        """
        children = cls._getChildren(session, dn)
        for child in children:
            if child[0] == 'statsHierColl':
                granularity = str(child[1]['attributes']['granularity'])
                adminState = str(child[1]['attributes']['adminState'])
                retention = str(child[1]['attributes']['histRet'])
                collPolicy = CollectionPolicy(policyObject, granularity,
                                              retention, adminState)
                collPolicy.set_name(child[1]['attributes']['name'])
                collPolicy.set_description(child[1]['attributes']['descr'])

            if child[0] in ['monFabricTarget', 'monInfraTarget']:
                scope = str(child[1]['attributes']['scope'])

                # initially only l1PhysIf is supported as a target
                if scope == 'l1PhysIf':
                    target = MonitorTarget(policyObject, scope)
                    target.set_name(str(child[1]['attributes']['name']))
                    target.set_description(str(child[1]['attributes']['descr']))
                    dn = child[1]['attributes']['dn']
                    targetChildren = cls._getChildren(session, dn)
                    for targetChild in targetChildren:
                        if targetChild[0] == 'statsReportable':
                            scope = str(targetChild[1]['attributes']['scope'])
                            scope = MonitorStats.statsDictionary[scope]
                            statFamily = MonitorStats(target, scope)
                            child_attr = targetChild[1]['attributes']
                            statFamily.set_name(str(child_attr['name']))
                            statFamily.set_description(str(child_attr['name']))
                            dn = targetChild[1]['attributes']['dn']
                            statChildren = cls._getChildren(session, dn)
                            for statChild in statChildren:
                                if statChild[0] == 'statsColl':
                                    child_stats = statChild[1]['attributes']
                                    granularity = str(child_stats['granularity'])
                                    adminState = str(child_stats['adminState'])
                                    retention = str(child_stats['histRet'])
                                    collPolicy = CollectionPolicy(statFamily,
                                                                  granularity,
                                                                  retention,
                                                                  adminState)
                                    collPolicy.set_name(child_stats['name'])
                                    collPolicy.set_description(child_stats['descr'])
                        if targetChild[0] == 'statsHierColl':
                            child_attr = targetChild[1]['attributes']
                            granularity = str(child_attr['granularity'])
                            adminState = str(child_attr['adminState'])
                            retention = str(child_attr['histRet'])
                            collPolicy = CollectionPolicy(target,
                                                          granularity,
                                                          retention,
                                                          adminState)
                            collPolicy.set_name(child_attr['name'])
                            collPolicy.set_description(child_attr['descr'])

    @classmethod
    def _getChildren(cls, session, dn):
        """
        Get the children

        :param session: Session instance object
        :param dn: string containing the distinguished name
        :return: json dictionary containing the children objects
        """
        result = []
        mo_query_url = '/api/mo/' + dn + '.json?query-target=children'
        ret = session.get(mo_query_url)
        mo_data = ret.json()['imdata']
        for node in mo_data:
            for key in node:
                result.append((key, node[key]))
        return result

    def __str__(self):
        """
        Return print string.
        """
        return self.policyType + ':' + self.name

    def flat(self, target='l1PhysIf'):
        """
        This method will return a data structure that is a flattened version
        of the monitor policy. The flattened version is one that walks through
        the heirarchy of the policy and determines the administrative state and
        retention policy for each granularity of each statistics family.
        This is done for the target specified, i.e. 'l1PhysIf'

        For example, if 'foo' is a MonitorPolicy object, then
        flatPol = foo.flat('l1PhysIf') will return a dictionary that looks like
        the following:

        adminState = flatPol['counter_family']['granularity'].adminState
        retention = flatPol['counter_family']['granularity'].retention

        The dictionary will have all of the counter families for all of the
        granularities and the value returned is the administrative state and
        retention value that is the final result of resolving the policy
        hierarchy.

        :param target:  Switch target object.  This will default to 'l1PhysIf'
        :returns: Dictionary of statistic administrative state and retentions
                  indexed by counter family and granularity.
        """

        class Policy(object):
            """
            Policy class
            """

            def __init__(self):
                self.adminState = 'disabled'
                self.retention = 'none'

        result = {}

        # initialize data structure
        for statFamily in MonitorStats.statsFamilyEnum:
            result[statFamily] = {}
            for granularity in CollectionPolicy.granularityEnum:
                result[statFamily][granularity] = Policy()

        # walk through the policy heirarchy and over-ride each
        # policy with the more specific one

        for granularity in self.collection_policy:
            retention = self.collection_policy[granularity].retention
            adminState = self.collection_policy[granularity].adminState
            for statFamily in MonitorStats.statsFamilyEnum:
                result[statFamily][granularity].adminState = adminState
                result[statFamily][granularity].retention = retention

        # now go through monitor targets
        targetPolicy = self.monitor_target[target]
        for granularity in targetPolicy.collection_policy:
            retention = targetPolicy.collection_policy[granularity].retention
            adminState = targetPolicy.collection_policy[granularity].adminState
            for statFamily in MonitorStats.statsFamilyEnum:
                if adminState != 'inherited':
                    result[statFamily][granularity].adminState = adminState
                if retention != 'inherited':
                    result[statFamily][granularity].retention = retention

        target_stats = targetPolicy.monitor_stats
        for statFamily in target_stats:
            collection_pol = target_stats[statFamily].collection_policy
            for granularity in collection_pol:
                retention = collection_pol[granularity].retention
                adminState = collection_pol[granularity].adminState

                if adminState != 'inherited':
                    result[statFamily][granularity].adminState = adminState
                if retention != 'inherited':
                    result[statFamily][granularity].retention = retention

        # if the lesser granularity is disabled, then the larger granularity
        # is as well
        for statFamily in MonitorStats.statsFamilyEnum:
            disable_found = False
            for granularity in CollectionPolicy.granularityEnum:
                if result[statFamily][granularity].adminState == 'disabled':
                    disable_found = True
                if disable_found:
                    result[statFamily][granularity].adminState = 'disabled'
        return result


class MonitorTarget(BaseMonitorClass):
    """
    This class is a child of a MonitorPolicy object. It is used to specify a
    scope for appling a monitoring policy.  An example scope would be the
    Interface class, meaning that the monitoring policies specified here will
    apply to all Interface clas objects (l1PhysIf in the Switch) that use the
    parent MonitoringPolicy as their monitoring policy.

    Children of the MonitorTarget will be CollectionPolicy objects that define
    the collection policy for the specified target plus optional MonitorStats
    objects that allow finer grained control over specific families of
    statistics such as ingress packets, ingrPkts.

    The CollectionPolicy children are contained in a dictionary called
    "collection_policy" that is indexed by the granularity of the
    CollectionPolicy, e.g. '5min', '15min', etc.

    The MonitorStats children are contained in a dictionary called
    "monitor_stats" that is indexed by the name of the statistics family,
    e.g. 'ingrBytes', 'ingrPkts', etc.
    """

    def __init__(self, parent, target):
        """
        The MonitorTarget object is initialized with a parent of type
        MonitorPolicy, and a target string. Initially, this toolkit only
        supports a target of type 'l1PhysIf'.  The 'l1PhyIf' target is a layer
        1 physical interface or "port".  The MonitorTarget will narrow the
        scope of the policy specified by the children of the MonitorTarget to
        be only the target class.

       :param parent:  Parent object that this monitor target is a child.
                       It must be of type MonitorPolicy
       :param target:  String specifying the target class for the Monitor
                       policy.
        """
        targetEnum = ['l1PhysIf']
        if not type(parent) in [MonitorPolicy]:
            raise TypeError(('Parent of MonitorTarget must be one of type'
                             ' MonitorPolicy'))
        if target not in targetEnum:
            raise ValueError('target must be one of:', targetEnum)

        self._parent = parent
        self.scope = target
        self.descr = ''
        self.name = ''
        self._parent.add_target(self)
        self.collection_policy = {}
        self.monitor_stats = {}
        # assume that it has not been written to Switch.
        # This is cleared if the policy is just loaded from Switch
        # or the policy is written to the Switch.
        self.modified = True

    def __str__(self):
        return self.scope


class MonitorStats(BaseMonitorClass):
    """
    This class is a child of a MonitorTarget object.  It is used to specify
    a scope for applying a monitoring policy that is more fine grained than
    the MonitorTarget.  Specifically, the MonitorStats object specifies a
    statistics family such as "ingress packets" or "egress bytes".
    """
    statsDictionary = {'eqptEgrBytes': 'egrBytes',
                       'eqptEgrPkts': 'egrPkts',
                       'eqptEgrTotal': 'egrTotal',
                       'eqptEgrDropPkts': 'egrDropPkts',
                       'eqptIngrBytes': 'ingrBytes',
                       'eqptIngrPkts': 'ingrPkts',
                       'eqptIngrTotal': 'ingrTotal',
                       'eqptIngrDropPkts': 'ingrDropPkts',
                       'eqptIngrUnkBytes': 'ingrUnkBytes',
                       'eqptIngrUnkPkts': 'ingrUnkPkts',
                       'eqptIngrStorm': 'ingrStorm'}

    statsFamilyEnum = ['egrBytes', 'egrPkts', 'egrTotal', 'egrDropPkts',
                       'ingrBytes', 'ingrPkts', 'ingrTotal', 'ingrDropPkts',
                       'ingrUnkBytes', 'ingrUnkPkts', 'ingrStorm']

    def __init__(self, parent, statsFamily):
        """
        The MonitorStats object must always be initialized with a parent object
        of type MonitorTarget. It sets the scope of its children collection
        policies (CollectionPolicy) to a particular statistics family.

        The MonitorStats object contains a dictionary of collection policies
        called collection_policy.  This is a dictionary of children
        CollectionPolicy objects indexed by their granularity, e.g. '5min',
        '15min', etc.

       :param parent: Parent object that this monitor stats object should be
                      applied to. This must be an object of type MonitorTarget.
       :param statsFamily: String specifying the statistics family that the
                           children collection policies should be applied to.
                           Possible values are:['egrBytes', 'egrPkts',
                           'egrTotal', 'egrDropPkts', 'ingrBytes', 'ingrPkts',
                           'ingrTotal', 'ingrDropPkts', 'ingrUnkBytes',
                           'ingrUnkPkts', 'ingrStorm']
        """
        if not type(parent) in [MonitorTarget]:
            raise TypeError(('Parent of MonitorStats must be one of type '
                             'MonitorTarget'))
        if statsFamily not in MonitorStats.statsFamilyEnum:
            raise ValueError('statsFamily must be one of:', MonitorStats.statsFamilyEnum)

        self._parent = parent
        self.scope = statsFamily
        self.descr = ''
        self.name = ''
        self._parent.add_stats(self)
        self.collection_policy = {}
        # assume that it has not been written to Switch.  This is cleared if
        # the policy is just loaded from Switch or the policy is written to
        # the Switch.
        self.modified = True

    def __str__(self):
        return self.scope


class CollectionPolicy(BaseMonitorClass):
    """
    This class is a child of a MonitorPolicy object, MonitorTarget object or
    a MonitorStats object.  It is where the statistics collection policy is
    actually specified.  It applies to all of the statistics that are at the
    scope level of the parent object,
    i.e. all, specific to a target, or specific to a statistics family.  What
    is specified in the CollectionPolicy is the time granularity of the
    collection and how much history to retain.  For example, the granularity
    might be 5 minutes (5min) or 1 hour (1h).  How much history to retain is
    similarly specified.  For example you might specify that it be kept for
    10 days (10d) or 2 years (2year).

    If the CollectionPolicy is a child of a MonitorStats object, it can
    optionally have children that specify the policy for raising threshold
    alarms on the fields in the stats family specified in the MonitorStats
    object.  This has yet to be implemented.

    This object is roughly the same as the statsColl and statsHierColl objects
    in the Switch.
    """
    # this must be in order from small to large
    granularityEnum = ['5min', '15min', '1h', '1d',
                       '1w', '1mo', '1qtr', '1year']
    retentionEnum = ['none', 'inherited', '5min', '15min', '1h', '1d',
                     '1w', '10d', '1mo', '1qtr', '1year', '2year', '3year']

    def __init__(self, parent, granularity, retention, adminState='enabled'):
        """
        The CollectionPolicy must always be initialized with a parent object
        of type MonitorPolicy, MonitorTarget or MonitorStats. The granularity
        must also be specifically specified.  The retention period can be 
        specified, set to "none", or set to "inherited". Note that the "none"
        value is a string, not the Python None.  When the retention period is
        set to "none" there will be no historical stats kept. However, 
        assuming collection is enabled, stats will be kept for
        the current time period.

        If the retention period is set to "inherited", the value will be
        inherited from the less specific policy directly above this one. The
        same applies to the adminState value.  It can be 'disabled',
        'enabled', or 'inherited'.  If 'disabled', the current scope of 
        counters are not gathered.  If enabled, they are gathered.  If 
        'inherited', it will be according to the next higher scope.

        Having the 'inherited' option on the retention and administrative
        status allows these items independently controlled at the current
        stats granularity.  For example, you can specify that ingress unknown
        packets are gathered every 15 minutes by setting adding a collection
        policy that specifies a 15 minutes granularity and an adminState of
        'enabled' under a MonitorStats object that sets the scope to be 
        ingress unknown packets.  This might override a higher level policy
        that disabled collection at a 15 minute interval.   However, you can
        set the retention in that same object to be "inherited" so that this
        specific policy does not change the retention behavior from that of 
        the higher, less specific, policy.

        When the CollectionPolicy is a child at the top level, i.e. of the
        MonitorPolicy, the 'inherited' option is not allowed because there
        is no higher level policy to inherit from.  If this were to happen,
        'inherited' will be treated as 'enabled'.

       :param parent: Parent object that this collection policy should be
                      applied to. This must be an object of type MonitorStats,
                      MonitorTarget, or MonitorPolicy.
       :param granularity:  String specifying the time collection interval or
                            granularity of this policy.  Possible values are:
                            ['5min', '15min', '1h', '1d', '1w', '1mo', '1qtr',
                            '1year'].
       :param retention: String specifying how much history to retain the
                         collected statistics for.  The retention will be for
                         time units of the granularity specified.  Possible
                         values are ['none', 'inherited', '5min', '15min',
                         '1h', '1d', '1w', '10d', '1mo', '1qtr', '1year',
                         '2year', '3year'].
       :param adminState:  Administrative status.  String to specify whether
                           stats should be collected at the specified
                           granularity.  Possible values are ['enabled',
                           'disabled', 'inherited'].  The default if not
                           specified is 'enabled'.
        """
        adminStateEnum = ['enabled', 'disabled', 'inherited']

        if type(parent) not in [MonitorStats, MonitorTarget, MonitorPolicy]:
            raise TypeError(('Parent of collection policy must be one of '
                             'MonitorStats, MonitorTarget, or MonitorPolicy'))
        if granularity not in CollectionPolicy.granularityEnum:
            raise ValueError('granularity must be one of:',
                             CollectionPolicy.granularityEnum)
        if retention not in CollectionPolicy.retentionEnum:
            raise ValueError('retention must be one of:',
                             CollectionPolicy.retentionEnum)
        if adminState not in adminStateEnum:
            raise ValueError('adminState must be one of:',
                             CollectionPolicy.adminStateEnum)

        self._parent = parent
        self.granularity = granularity

        self.retention = retention
        self.adminState = adminState
        self._children = []

        self._parent.add_collection_policy(self)
        # assume that it has not been written to Switch.  This is cleared if
        # the policy is just loaded from Switch or the policy is written to
        # the Switch.
        self.modified = True

    def __str__(self):
        return self.granularity

    def setAdminState(self, adminState):
        """
        Sets the administrative status.

        :param adminState:  Administrative status.  String to specify whether
                            stats should be collected at the specified
                            granularity.  Possible values are ['enabled',
                            'disabled', 'inherited'].  The default if not
                            specified is 'enabled'.
        """
        if self.adminState != adminState:
            self.modified = True

        self.adminState = adminState

    def setRetention(self, retention):
        """
        Sets the retention period.

       :param retention: String specifying how much history to retain the
                         collected statistics for.  The retention will be for
                         time units of the granularity specified.  Possible
                         values are ['none', 'inherited', '5min', '15min',
                         '1h', '1d', '1w', '10d', '1mo', '1qtr', '1year',
                         '2year', '3year'].
        """
        if self.retention != retention:
            self.modified = True

        self.retention = retention


class LogicalModel(BaseNXObject):
    """
    This is the root class for the logical part of the network.
    It's corrolary is the PhysicalModel class.
    It is a container that can hold all of logical model instances such 
    as Tenants.

    From this class, you can populate all of the children classes.
    """

    def __init__(self, session=None, parent=None):
        """
        Initialization method that sets up the Fabric.
        :return:
        """
        if session:
            assert isinstance(session, Session)

        super(LogicalModel, self).__init__(name='', parent=parent)

        self.session = session

    @classmethod
    def get(cls, session=None, parent=None):
        """
        Method to get all of the PhysicalModels.  It will get one and 
        return it in a list.
        
        :param session:
        :param parent:
        :return: list of PhysicalModel
        """
        logical_model = LogicalModel(session=session, parent=parent)
        return [logical_model]

    def populate_children(self, deep=False, include_concrete=False):
        """
        This method will populate the children of the fabric.  If deep is set
        to True, it will populate the entire object tree, both physical and logical.

        If include_concrete is set to True, it will also include the concrete models
        on the network switches.

        :param deep:
        :param include_concrete:
        :return: list of immediate children objects
        """

        if deep:
            for child in self._children:
                child.populate_children(deep, include_concrete)

        return self._children


class LinkNeighbors(BaseNXObject):
    """
    This class represents cdp or lldp neighbors information
    
    """
    
    def __init__(self, disc_proto='cdp', session=None, attributes=None):
        """
        Initialization of cdp and lldp information
        
        :param disc_proto: string contains name of discovery 
               protocol (cdp, lldp)
        :param session: the instance of Session used for switch communication
        :param attributes: A dictionary contains neighbors information
         
        :return:
        """
        super(LinkNeighbors, self).__init__(name="")
        self._session = session
        if attributes is None:
            self.attributes = {}
        else:
            self.attributes = copy.deepcopy(attributes)
        self.disc_proto = disc_proto

    @classmethod
    def _is_feature_enabled(cls, session, f_name=None):
        """
        This method will check if the f_name feature is enabled in the 
        switch. If enabled return True or else return False
        
        :param session: the instance of Session used for switch communication
        :param f_name: String represents a feature name
        
        :return Boolean value
        """
        feature_url = '/api/mo/sys/fm.json?rsp-subtree=full'
        resp = session.get(feature_url)
        for fm in resp.json()['imdata']:
            if fm.get('fmEntity'):
                for feature in fm['fmEntity']['children']:
                    if feature.get('fm'+f_name.title()):
                        return True
        return False
     
    @classmethod
    def get(cls, session, disc_proto='auto', module=None, port=None):
        """
        Gets cdp or lldp neighbors details depending on disc_proto parameter
        
        :param session: the instance of Session used for switch communication
        :param disc_proto: Discovery protocol used for getting neighbors 
               (default: cdp)
        :param module: Module id string.  This specifies the module or
                       slot of the port. (optional)
        :param port: Port number.  This is the port to read. (optional)

        :returns: list of LinkNeighbors object
        
        """
        if not isinstance(session, Session):
            raise TypeError('An instance of Session class is required')

        if port:
            if not isinstance(port, str):
                raise TypeError('When specifying a specific port, the port'
                                ' must be a identified by a string')
            if not isinstance(module, str):
                raise TypeError(('When specifying a specific port, the module'
                                 ' must be identified by a string'))
        
        if disc_proto.lower() in ['auto', 'lldp']:
            # If discovery protocol is auto or lldp, then check if lldp is 
            # enabled and use it. If lldp is not enabled use cdp
            if LinkNeighbors._is_feature_enabled(session, 'lldp'):
                disc_proto = 'lldp'
            else:
                disc_proto = 'cdp'
        else:
            # If some random values is passed in disc_proto, then cdp is used
            disc_proto = 'cdp'
        
        iface_name = ''
        if module and port:
            iface_name = '/if-[eth{0}/{1}]'.format(module, port)
        query_url = ('/api/mo/sys/%s/inst%s.json?rsp-subtree=full' 
                     % (disc_proto, iface_name))
        neighbors_resp = session.get(query_url)
        
        neighbors = neighbors_resp.json()['imdata']
            
        if module and port:
            children = neighbors
        else:
            children = neighbors[0][disc_proto+'Inst']['children']

        resp = []
        adj_epg = disc_proto+'AdjEp'
        proto_if = disc_proto+'If'
        for ch in children:
            for sub_ch in ch[proto_if]['children']:
                if sub_ch.get(adj_epg):
                    attributes = {}
                    attributes['devId'] = str(sub_ch[adj_epg]['attributes']\
                                              ['devId'])
                    attributes['portId'] = str(sub_ch[adj_epg]['attributes']\
                                               ['portId'])
                    attributes['sysName'] = str(sub_ch[adj_epg]['attributes']\
                                                ['sysName'])
                    attributes['ver'] = str(sub_ch[adj_epg]['attributes']\
                                            ['ver'])
                    attributes['cap'] = str(sub_ch[adj_epg]['attributes']\
                                            ['cap'])
                    # Currently hold time is now supported
                    attributes['Hldtme'] = '-'
                    if disc_proto == 'cdp':
                        attributes['platId'] = \
                        str(sub_ch[adj_epg]['attributes']['platId'])
                    else:
                        attributes['platId'] = "-"
                    # attributes['id'] holds local interface
                    attributes['id'] = str(ch[proto_if]['attributes']['id'])
                    attributes['operSt'] = str(ch[proto_if]['attributes']\
                                               ['operSt'])
                    resp.append(LinkNeighbors(disc_proto=disc_proto,
                                          session=session,
                                          attributes=attributes))
                    
        return resp


class HardwareInternal(object):
    """
    This class defines hardware internal details
    
    """
    def __init__(self, parent):
        self._parent = parent
    
    def buff_pkt_details(self, session):
        """
        :param session: Session object
        :return Json output of buffer packet details
        
        """
        command = 'show hardware  internal buffer info pkt-stats detail'
        return session.post_nxapi(command).text
    
    def get(self, session=None):
        """
        :param session: Session object
        :return 
        
        """
        if not session:
            session = self._parent._session
            
        resp = self.buff_pkt_details(session) 
        buffer_info = json.loads(resp)['ins_api']['outputs']['output']\
        ['body']['TABLE_module']['ROW_module']
        module_number = buffer_info['module_number']
        if module_number:
            hardware_int = HardwareInternal(session)            
            hardware_int.buffer = {}
            hardware_int.buffer['total_instant'] = []
            hardware_int.buffer['rem_instant'] = []
            hardware_int.buffer['switch_cell'] = []
            hardware_int.buffer['max_cell'] = []

            pars = buffer_info['TABLE_instance']['ROW_instance']
            for index in range (1,5):
                total_ins = "total_instant_usage_" + str(index)
                rem_ins = "rem_instant_usage_" + str(index)
                max_cel = "max_cell_usage_" + str(index)
                switch_cel = "switch_cell_count_" + str(index)
                hardware_int.buffer['total_instant'].append(pars[total_ins])
                hardware_int.buffer['rem_instant'].append(pars[rem_ins])
                hardware_int.buffer['max_cell'].append(pars[max_cel])
                hardware_int.buffer['switch_cell'].append(pars[switch_cel])
                
        return hardware_int
            
    
class Hardware(BaseNXObject):

    def __init__(self, session=None):
        self.internal = HardwareInternal(self)
        self._session = session
    
    @classmethod
    def get(cls, session,  type='nxapi'):
        
        """
        :param session: Session object
        :param type: String defines type of REST call (nxapi default)
        """
        
        if not isinstance(session, Session):
            raise TypeError('An instance of Session class is required')
        
        if type == 'nxapi':
            return Hardware(session)


class LogTimeStamp(object):
    """
    This class defines timestamp logging
    
    """
    def __init__(self, session=None, parent=None, format='seconds'):
        self._session= session
        self._parent = parent
        self.format= format
        self.object = 'syslogTimeStamp' 
    
    def get(self, session=None):
        """
        :param session: Session object to communicate with Switch
        :return LogTimeStamp object
        """
        query_url = '/api/mo/sys/syslog/timestamp.json'
        
        if not session:
            session = self._session
            
        resp = session.get(query_url).json()['imdata']
        for ret in resp:
            format = ret[self.object]['attributes']['format']
            
            return LogTimeStamp(format=format)

    def _get_attributes(self):
        att = {}
        att['format'] = self.format
        return att
    
    def get_json(self):
        return { self.object: { "attributes": self._get_attributes()}}


class LogMonitor(object):
    
    def __init__(self, session=None, parent=None,
                 admin_st='enabled', severity='notifications'):
        
        self._session= session
        self._parent = parent
        self.admin_st = admin_st
        self.severity = severity
        # monitor logging object name
        self.object = 'syslogTermMonitor'
    
    def get(self, session=None):
        
        if not session:
            session = self._session
        
        query_url = '/api/mo/sys/syslog/monitor.json'
        resp = session.get(query_url).json()['imdata']
        for ret in resp:
            admin_st = ret[self.object]['attributes']['adminState']
            severity = ret[self.object]['attributes']['severity']
            return LogMonitor(admin_st=admin_st, severity=severity)

    def _get_attributes(self):
        att = {}
        att['adminState'] = self.admin_st
        att['severity'] = self.severity
        return att
    
    def get_json(self):
        return { self.object: { "attributes": self._get_attributes()}}

    
class LogConsole(object):
    """
    This class defines logging console
    """
    def __init__(self, session=None, parent=None,
                 admin_st='enabled', severity='critical'):
        self._session= session
        self._parent = parent
        self.admin_st = admin_st
        self.severity = severity
        # Base class object name for console logging
        self.object = 'syslogConsole'
    
    def get(self, session=None):
        
        query_url = '/api/mo/sys/syslog/console.json'
        if not session:
            session = self._session
            
        resp = session.get(query_url).json()['imdata']
        for ret in resp:
            admin_st = ret[self.object]['attributes']['adminState']
            severity = ret[self.object]['attributes']['severity']
            return LogConsole(admin_st=admin_st, severity=severity)
    
    def _get_attributes(self):
        att = {}
        att['adminState'] = self.admin_st
        att['severity'] = self.severity
        return att

    def get_json(self):
        return { self.object: { "attributes": self._get_attributes()}}  


class LogServer(object):
    """
    This class defines server logging
    """
    def __init__(self, session=None, parent=None,
                 host=None, severity='notifications', vrf_name='',
                 fwd_facility='local7'):
        self._session= session
        self._parent = parent
        self.host = host
        self.severity = severity
        self.vrf_name = vrf_name
        self.fwd_facility = fwd_facility
        self.object = 'syslogRemoteDest'

    def get(self, session=None):
        """
        :param session: Session object to communicate with Switch
        :return LogServer object
        """
        query_url = '/api/node/class/syslogSyslog.json?rsp-subtree=full'
        if not session:
            session = self._session
            
        resp = session.get(query_url).json()['imdata']
        for ret in resp:
            children = ret['syslogSyslog']['children']
            for child in children:
                if child.get(self.object):
                    host = child[self.object]['attributes']['host']
                    severity = child[self.object]['attributes']['severity']
                    vrf_name = child[self.object]['attributes']['vrfName']
                    fwd_facility = child[self.object]['attributes']\
                    ['forwardingFacility']
                    return LogServer(host=host, severity=severity,
                                     vrf_name=vrf_name,
                                     fwd_facility=fwd_facility)

    def _get_attributes(self):
        att = {}
        att['host'] = self.host
        att['severity'] = self.severity
        att['vrfName'] = self.vrf_name
        att['forwardingFacility'] = self.fwd_facility
        return att
    
    def get_json(self):
        return { self.object: { "attributes": self._get_attributes()}}


class LogSourceInterface(object):
    """
    This class defines source interface logging
    """
    def __init__(self, session=None, parent=None,
                 admin_st='enabled', if_name='unspecified'):
        self._session= session
        self._parent = parent
        self.admin_st = admin_st
        self.if_name = if_name
        self.object = 'syslogSourceInterface'

    def get(self, session=None):
        """
        :param session: Session object to communicate with Switch
        :return LogSourceInterface object
        """
        query_url = '/api/mo/sys/syslog/source.json'
        if not session:
            session = self._session
            
        resp = session.get(query_url).json()['imdata']
        for ret in resp:
            admin_st = ret[self.object]['attributes']['adminState']
            if_name = ret[self.object]['attributes']['ifName']
            return LogSourceInterface(admin_st=admin_st, if_name=if_name)
    
    def _get_attributes(self):
        
        att = {}
        att['adminState'] = self.admin_st
        att['ifName'] = self.if_name
        return att
    
    def get_json(self):
        return { self.object: { "attributes": self._get_attributes()}}


class LogLevel(object):
    """
    This class defines log level
    """
    
    def __init__(self, session=None, parent=None,
                 facility=None, severity='errors'):
        self._session= session
        self._parent = parent
        self.facility = facility
        self.severity = severity
        self.object = 'syslogLevel'

    def get(self, session=None):
        """
        :param session: Session object to communicate with Switch
        :return LogLevel object
        """
        query_url = '/api/node/class/syslogSyslog.json?rsp-subtree=full'
        if not session:
            session = self._session
            
        resp = session.get(query_url).json()['imdata']
        for ret in resp:
            children = ret['syslogSyslog']['children']
            for child in children:
                if child.get(self.object):
                    facility = child[self.object]['attributes']['facility']
                    severity = child[self.object]['attributes']['severity']
                    return LogLevel(facility=facility, severity=severity)
  
    def _get_attributes(self):
        att = {}
        att['facility'] = self.facility
        att['severity'] = self.severity
        return att
    
    def get_json(self):
        return {self.object : { "attributes" : self._get_attributes()}}    


class Logging(BaseNXObject):
    """
    This is the parent class for all the logging classes
    """
    
    def __init__(self, session=None, parent=None):
        super(Logging, self).__init__(name="logging")
        self._session = session
        self._parent = parent
        self._children = []
        # Base syslog object
        self.object  = 'syslogSyslog'
        
        self.timestamp = LogTimeStamp(session=session, parent=self)
        self.level = LogLevel(session=session, parent=self)
        self.server = LogServer(session=session, parent=self)
        self.monitor = LogMonitor(session=session, parent=self)
        self.src_iface = LogSourceInterface(session=session, parent=self)
        self.console = LogConsole(session=session, parent=self)

    def add_log(self, log_obj=None):
        self._children.append(log_obj)
    
    def get_json(self):
        return super(Logging, self).get_json(self.object)
    
    def get_url(self, fmt='json'):
        return '/api/mo/sys/syslog.' + fmt
  
    @classmethod
    def get(cls, session=None):
        """
        :param session: Session object used to communicate with Switch
        :return Logging object
        """
        
        if not isinstance(session, Session):
            raise TypeError('An instance of Session class is required')
        
        return Logging(session=session)


class BreakoutPort(object):
    """
    This class defines breakout ports
    """
    def __init__(self, id=None, map=None, session=None, parent=None):
        self.id = id
        self.map = map
        self.object = 'imFpP'
        self._session = session
        self._parent = parent
    
    def get_json(self):
        return {self.object : {'attributes' : self._get_attributes()}}
        
    def _get_attributes(self):
        att = {}
        if not self.id:
            raise AttributeError('Port id required')
        
        att['id'] = self.id
        att['breakoutMap'] = self.map
        return att

    def get(self, port=None, session=None):
        
        if not session:
            session = self._session

        query_url = ('/api/mo/sys/breakout/module-%s.json?query-target'
                     '=children' % (self._parent.module_num))
        ret = []
        ports = session.get(query_url).json()['imdata']
        for port in ports:
            id = str(port['imFpP']['attributes']['id'])
            map = str(port['imFpP']['attributes']['breakoutMap'])
            ret.append(BreakoutPort(id, map, session=session))
        return ret


class BreakoutModule(BaseNXObject):
    """
    This class defines breakout modules
    """
    
    def __init__(self, module_num=None, session=None, parent=None):
        
        if not module_num:
            raise TypeError('Module id expected')
        
        super(BreakoutModule, self).__init__(name=module_num)
        self._session = session
        self._parent = parent
        self.module_num = module_num
        self.object = 'imMod'
        self.ports = BreakoutPort(session=session, parent=self)

    def add_port_map(self, id=None, map=None):
        """
        :param id: String reprenenting id (example 1, 45 etc.)
        :param map: String map (Example: 10g-4x)
        """
        if not isinstance(map, str):
            raise TypeError('str instance is expected for map')
        try:
            int(id)
        except ValueError:
            raise ValueError('Invalid port Id')

        self._children.append(BreakoutPort(id, map))

    def _get_attributes(self):
        att = {}
        att['id'] = self.module_num
        return att
    
    def get_json(self):
        return super(BreakoutModule,
                     self).get_json(self.object,
                                    attributes=self._get_attributes())

    def get(self, module_num=None, session=None):
        """
        Get break module info
        :param module_num String representing number
        :param Session object used for communicating with switch
        :return List of BreakoutModule objects
        """
        if not session:
            session = self._session
        
        if module_num:
            query_url = '/api/mo/sys/breakout/module-%s.json' % (module_num)
        else:
            query_url = '/api/mo/sys/breakout.json?query-target=children'
        
        modules = session.get(query_url).json()['imdata']
        ret = []
        for module in modules:
            if module.get('imMod'):
                module_num = str(module['imMod']['attributes']['id'])
                ret.append(BreakoutModule(module_num, session=session))
        return ret
            

class InterfaceBreakout(BaseNXObject):

    def __init__(self, session=None):
        super(InterfaceBreakout, self).__init__(name='')
        self._session = session
        self.object = 'imBreakout'
        
        # id (1) passed here does not make any impact
        self.modules = BreakoutModule('1', session=session, parent=self)
    
    def add_module(self, module):
        if not isinstance(module, BreakoutModule):
            raise TypeError('BreakoutModule instance expected')
        self._children.append(module)
    
    def get_json(self):
        return super(InterfaceBreakout, self).get_json(self.object)
    
    def get_url(self, fmt='json'):
        return '/api/mo/sys/breakout.' + fmt
    
    def get_delete_url(self, module=None, port=None):
        return '/api/mo/sys/breakout/module-%s/fport-%s.json' % (module, port)
    
    @classmethod
    def get(cls, session=None, module=None, port=None):

        if not isinstance(session, Session):
            raise TypeError('An instance of Session class is required')

        return InterfaceBreakout(session)


class SVI(BaseNXObject):
    """
    This class defines SVI
    """
    def __init__(self, vlan=None, admin_st=None, descr=None):

        if not vlan:
            raise TypeError('Proper vlan name expected')
        try:
            # A dummy line which raises error if vlan is otherthan 
            # vlan<ID> format
            int(vlan.replace('vlan', ''))
        except ValueError:
            raise AttributeError('Proper vlan name expected')
        
        super(SVI, self).__init__(name=vlan)
        self.id = vlan #vlan id
        self.descr = descr
        self.admin_st = admin_st
        self.mtu = None
        self.bw = None
        self.object = 'sviIf'
    
    def set_bw(self, bw=None):
        self.bw = bw
    
    def set_mtu(self, mtu=None):
        self.mtu = mtu
    
    def get_mtu(self):
        return self.mtu
    
    def get_bw(self):
        return self.bw

    def get_url(self, fmt='json'):
        return '/api/mo/sys/intf/svi-[%s].%s'  % (self.id, fmt)
    
    def get_delete_url(self, vlan=None):
        return '/api/mo/sys/intf/svi-[%s].json'  % (vlan)
    
    def _get_attributes(self):
        att = {}
        att['id'] = self.id
        if self.admin_st:
            att['adminSt'] = self.admin_st
        if self.descr:
            att['descr'] = self.descr
        if self.mtu:
            att['mtu'] = self.mtu
        if self.bw:
            att['bw'] = self.bw
        return att
    
    def get_json(self):
        return super(SVI, self).get_json(self.object,
                                  attributes=self._get_attributes())
    
    @classmethod
    def get(cls, session=None, vlan=None):
        """
        Get SVI details 
        :param session: Session instance to commnunicate with switch
        :param vlan: String represents svi id i.e. valn10
        """
        if not isinstance(session, Session):
            raise TypeError('An instance of Session class is required')
        if vlan:
            query_url = '/api/mo/sys/intf/svi-[%s].json' % (vlan)
        else:
            query_url = '/api/node/class/sviIf.json'
        
        svis = session.get(query_url).json()['imdata']
        resp = []
        for svi in svis:
            admin_st = str(svi['sviIf']['attributes']['adminSt'])
            id = str(svi['sviIf']['attributes']['id'])
            mtu = str(svi['sviIf']['attributes']['mtu'])
            desc = str(svi['sviIf']['attributes']['descr'])
            bw = str(svi['sviIf']['attributes']['bw'])
            svi_obj = SVI(id, admin_st, desc)
            svi_obj.set_mtu(mtu)
            svi_obj.set_bw(bw)
            resp.append(svi_obj)
        
        return resp


class ConfigInterfaces(BaseNXObject):
    """This class is used to configure multiple interfaces/svi/port channel
    at a time.
    """
    
    def __init__(self, session=None):
        super(ConfigInterfaces, self).__init__(name='')
        self.object = 'interfaceEntity'

    def add_interface(self, interface=None):
        """Form the list of interfaces to be configured"""
        if not isinstance(interface, Interface):
            raise TypeError('Interface instance is expected')
        self._children.append(interface)
    
    def add_svis(self, svi=None):
        """Form list of SVIs"""
        if not isinstance(svi, SVI):
            raise TypeError('SVI instance expected')
        self._children.append(svi)
    
    def add_port_channel(self, pc=None):
        """Form list of PortChannel"""
        if not isinstance(pc, PortChannel):
            raise TypeError('PortChannel instance expected')
        self._children.append(pc)

    def get_url(self, fmt='json'):
        return '/api/node/mo/sys/intf.json'
    
    def get_json(self):
        return super(ConfigInterfaces, self).get_json(self.object,
                                                      attributes={})

  
class VrrpID(object):
    """
    This class defines VRRP ID
    """
    
    def __init__(self, vrrp_id=None, secondary_ip=None, session=None,
                 parent=None):
        if not vrrp_id:
            raise TypeError('vrrp_id is not provided')
        #VRRP ID interface object
        self.object = 'vrrpId'
        self.vrrp_id = vrrp_id
        self.admin_st = None
        self.priority = None
        self._primary_ip = None
        self.interface = None
        #VRRP Secondary object
        self.child_object = 'vrrpSecondary'
        self._secondary_ip = secondary_ip
        
        self._session= session
        self._parent = parent
        
    def set_admin_st(self, admin_st=None):
        self.admin_st = admin_st
        
    def get_admin_st(self):
        """
       :returns: admin state object
        """
        return self.admin_st
    
    def set_priority(self, priority=None):
        self.priority = priority
        
    def get_priority(self):
        """
       :returns: priority object
        """
        return self.priority
    
    def set_primary(self, primary_ip=None):
        self._primary_ip = primary_ip
        
    def get_primary(self):
        """
       :returns: primary ip object
        """
        return self._primary_ip
    
    def set_secondary(self, secondary_ip=None):
        self._secondary_ip = secondary_ip
        
    def get_secondary(self):
        """
       :returns: secondary ip object
        """
        return self._secondary_ip
    
    def set_interface(self, interface):
        self.interface = interface
        
    def get_interface(self):
        return self.interface
    
    def _get_attributes(self):
        att = {}
        if self.vrrp_id:
            att['id'] = self.vrrp_id
        if self.admin_st:
            att['adminSt'] = self.admin_st
        if self.priority:
            att['priCfg'] = self.priority
        if self._primary_ip:
            att['primary'] = self._primary_ip
        return att
    
    def _get_child_attributes(self):
        child = []
        if self._secondary_ip:
            child.append({self.child_object: 
                            {"attributes": 
                                {'secondary': self._secondary_ip}}})
        return child
    
    def get_json(self):
        return {self.object : { "attributes" : self._get_attributes(), 
                                "children" : self._get_child_attributes()}}

     
class Vrrp(BaseNXObject):
    """
    This defines the VRRP Interface 
    """
    
    def __init__(self, interface=None, session=None, parent=None,
                 vrrp_id=None):
        super(Vrrp, self).__init__(name="vrrp_interface")
        if not interface:
            raise TypeError('interface is not provided')
        # Base VRRP interface object
        self.object  = 'vrrpInterface'
        self.interface = interface
        self.admin_st = None
        self.descr = None
        
        self._session = session
        self._parent = parent
        # id ('1') passed here does not make any impact
        self.vrrp_id = VrrpID('1', session=session, parent=self)
        self.vrrp_ids = []
    
    def set_admin_st(self, admin_st=None):    
        self.admin_st = admin_st
        
    def get_admin_st(self):
        """
       :returns: admin state object
        """
        return self.admin_st
    
    def set_descr(self, descr=None):
        self.descr = descr
        
    def get_descr(self):
        """
       :returns: description object
        """
        return self.descr
           
    def add_vrrp_id(self, vrrp_id=None):
        if isinstance(vrrp_id, VrrpID): 
            self._children.append(vrrp_id)
            self.vrrp_ids.append(vrrp_id)
               
    def _get_attributes(self):
        att = {}
        if self.interface.if_name:
            att['id'] = self.interface.if_name
        if self.admin_st:
            att['adminSt'] = self.admin_st
        if self.descr:
            att['descr'] = self.descr
        return att
        
    def get_json(self):
        """
       :returns: json response object
        """
        return super(Vrrp, self).get_json(obj_class=self.object, 
                                          attributes=self._get_attributes())
                                          
    def get_url(self, fmt='json'):
        """
       :returns: url object
        """
        return '/api/node/mo/sys/vrrp/inst.' + fmt
    
    @classmethod
    def get(self, session=None, interface_str=None):
        """
        :param session: Session object to communicate with Switch
        :return Vrrp object
        """
        if not isinstance(session, Session):
            raise TypeError('An instance of Session class is required') 
        
        ret_data = []
        object = 'vrrpInterface'
        
        if interface_str:
            query_url = '/api/node/mo/sys/vrrp/inst/if-['+interface_str+'].json?rsp-subtree=full'
            resp = session.get(query_url).json()['imdata']
        else:
            query_url = '/api/node/mo/sys/vrrp/inst.json?rsp-subtree=full'
            data = session.get(query_url).json()['imdata'][0]
            resp = data['vrrpInst']['children']
        
        for ret in resp:
            interface =ret[object]['attributes']['id'] 
            admin_st = ret[object]['attributes']['adminSt']
            descr = ret[object]['attributes']['descr']
            vrrp = Vrrp(interface=interface)
            if ret[object].get('children'):
                
                for id in ret[object].get('children'):
                    vrrp_id = id['vrrpId']['attributes']['id']
                    admin_st = id['vrrpId']['attributes']['adminSt']
                    priority = id['vrrpId']['attributes']['priCfg']
                    primary_ip = id['vrrpId']['attributes']['primary']
                    vrrp_id = VrrpID(vrrp_id=vrrp_id)
                    vrrp_id.set_admin_st(admin_st)
                    vrrp_id.set_priority(priority)
                    vrrp_id.set_primary(primary_ip)
                    
                    vrrp_id.set_secondary('-')
                    if id['vrrpId'].get('children'):
                        for sec in id['vrrpId']['children']:
                            sec_ip = sec['vrrpSecondary']['attributes']['secondary']
                            vrrp_id.set_secondary(sec_ip)
                            
                    vrrp.add_vrrp_id(vrrp_id)
      
            vrrp.set_admin_st(admin_st)
            vrrp.set_descr(descr)
            ret_data.append(vrrp)        
        return ret_data

     
class ConfigVrrps(BaseNXObject):
    """
    This is the base class to configure multiple VRRP Interface classes
    """
    
    def __init__(self, session=None):
        super(ConfigVrrps, self).__init__(name='')
        self._session = session 
        self.object = 'vrrpInst'
        
        # id ('1') passed here does not make any impact
        self.vrrp_id = VrrpID('1', session=session, parent=self)
        # interface ('1') passed here does not make any impact
        self.vrrp = Vrrp('1', session=session, parent=self)

    def add_vrrp(self, module):
        if not isinstance(module, Vrrp):
            raise TypeError('ConfigVrrps instance expected')
        self._children.append(module)
        
    def get_url(self, fmt='json'):
        """
       :returns: url object
        """
        return '/api/node/mo/sys/vrrp/inst.' + fmt   
    
    def get_json(self):
        """
       :returns: json response object
        """
        return super(ConfigVrrps, self).get_json(self.object) 
        
    @classmethod
    def get(cls, session=None):
        """
        :param session: Session object to communicate with Switch
        :return ConfigVrrps object
        """
        if not isinstance(session, Session):
            raise TypeError('An instance of Session class is required')
        return ConfigVrrps(session)        
                  

class Lacp(BaseNXObject):
    """
    This class defines lacp configuration
    """
    
    def __init__(self, rate=None, interface=None, session=None,
                 parent=None):
        super(Lacp, self).__init__(name='')
        self._session= session
        self._parent = parent
        self.rate = rate
        self.interface = interface
        self.object = 'lacpIf'
        
    @classmethod
    def get(self, session=None, interface=None):
        """
        :param session: Session object to communicate with Switch
        :return Lacp object
        """
        if interface:
            query_url = ('/api/node/mo/sys/lacp/inst/if-['+interface+'].'
                         'json?query-target=self')
        else:
            query_url = ('/api/node/mo/sys/lacp/inst.json?query-'
                         'target=children')
        ret_data = []
        if not isinstance(session, Session):
            raise TypeError('An instance of Session class is required')
          
        resp = session.get(query_url).json()['imdata']
        for ret in resp:
            rate = ret['lacpIf']['attributes']['txRate']
            interface = ret['lacpIf']['attributes']['id']
            lacp = Lacp(rate=rate, interface=interface)
            ret_data.append(lacp)
        return ret_data
            
    def _get_attributes(self):
        att = {}
        att['txRate'] = self.rate
        att['id'] = self.interface.if_name
        return att
    
    def get_url(self):
        return '/api/node/mo/sys/lacp/inst.json?query-target=children'
    
    def get_json(self):
        return super(Lacp, self).get_json(self.object,
                                          attributes=self._get_attributes())       


class IPV6Interface(BaseNXObject):
    """
    This class defines ipv6s of an interface. 
    """
    def __init__(self, if_name, session=None, parent=None):
        """
        :param if_name: String representing interface i.e. eth1/2
        """
        if not isinstance(if_name, str):
            raise TypeError('str instance expected')
        
        self._session = session
        self.interface = if_name
        self.object = 'ipv6If'
        self._addresses = []
        self.if_name = if_name
        self.admin_st = None
        self.link_local_addr = None
        super(IPV6Interface, self).__init__(name=self.if_name)
    def get_if_name(self):
        return self.if_name

    def set_admin_st(self, state):
        self.admin_st = state
    
    def get_admin_st(self):
        return self.admin_st
    
    def get_descr(self):
        return self.descr
 
    def set_descr(self, desc):
        self.descr = desc

    def add_address(self, addr):
        self._addresses.append(addr)
    
    def get_address(self):
        return self._addresses

    def _get_attributes(self):
        att = {}
        if self.admin_st:
            att['adminSt'] = self.admin_st
        if self.descr:
            att['descr'] = self.descr
        att['id'] = self.if_name
        return att
    
    def _get_json(self, class_obj, att=None):
        if not att:
            att = {}
        return {class_obj : {'attributes' : att}}
    
    def set_link_local_addr(self, addr):
        self.link_local_addr = addr

    def get_json(self):
        resp = super(IPV6Interface,
                     self).get_json(self.object,
                                    attributes=self._get_attributes())
        addrs = []
        for addr in self._addresses:
            att = {'addr': addr}
            addrs.append(self._get_json('ipv6Addr', att))
        
        if self.link_local_addr:
            att = {'addr': self.link_local_addr}
            addrs.append(self._get_json('ipv6LLaddr', att))

        resp[self.object]['children'] = addrs
        return resp
    
    def get_url(self, fmt='json'):
        return ('/api/node/mo/sys/ipv6/inst/dom-default/if-[%s].%s'
                % (self.interface.if_name, fmt))

    def get(self, session=None):
        """
        This method is used form get() method of IPV6 class
        :param sessoin: Session instance
        """
        if not session:
            session = self._session
        query_url = ('/api/node/mo/sys/ipv6/inst/dom-default/if-[%s].json'
                     '?query-target=children' % (self.if_name))
        
        resp = session.get(query_url).json()['imdata']
        for addr in resp:
            if addr.get('ipv6Addr'):
                address = str(addr['ipv6Addr']['attributes']['addr'])
                self.add_address(address)
            if addr.get('ipv6LLaddr'):
                self.link_local_addr = str(addr['ipv6LLaddr']['attributes']
                                           ['addr'])
                self.add_address(self.link_local_addr)


class IPV6NextHop(object):
    """This class defines IPv6 nexthop"""
    def __init__(self, addr, interface, vrf, track_id, tag):
        self.addr = addr
        self.i_face = interface
        self.vrf = vrf
        self.track_id = track_id
        self.tag = tag
        self.object = 'ipv6Nexthop'
    
    def _get_attributes(self):
        att = {}
        att['nhAddr'] = self.addr
        if self.i_face:
            att['nhIf'] = self.i_face
        if self.vrf:
            att['nhVrf'] = self.vrf
        if self.track_id:
            att['object'] = self.track_id
        if self.tag:
            att['tag'] = self.tag
        return att
        
    def get_json(self):
        return {self.object : { 'attributes': self._get_attributes()}}


class IPV6Route(BaseNXObject):

    def __init__(self, prefix, name=None, parent=None, session=None):
        
        if not IPV6.is_valid_ipv6_address(prefix.split('/')[0]):
            raise TypeError('Invalid prefix')
        if not name:
            name = ''

        self._session = session
        super(IPV6Route, self).__init__(name=name, parent=parent)
        self.prefix = prefix
        self.object = 'ipv6Route'
        self.next_hops = []

    def get_json(self):
        return super(IPV6Route, self).get_json(self.object,
                                            attributes=self._get_attributes())
    
    def _get_attributes(self):
        att = {}
        att['prefix'] = self.prefix
        return att
    
    def add_next_hop(self, addr, interface=None, vrf=None, track_id=None,
                     tag=None):

        if not IPV6.is_valid_ipv6_address(addr):
            raise TypeError('Invalid prefix')
        
        if not isinstance(interface, (Interface, PortChannel)):
            raise TypeError('Interface or PortChannel instance expected')
        
        if not vrf:
            vrf = 'default'
        next_hop = IPV6NextHop(addr, interface.if_name, vrf, track_id, tag)
        self._children.append(next_hop)
        self.next_hops.append(interface)
    
    def get(self, session=None):
        """"
        Get all the nexthop details from the switch and form a list of
        nexthops and store it in self.next_hops list
        :param session: Session object to communicate with Switch
        :return None
        """
        if not isinstance(session, Session):
            session = self._session
        
        query_url = '/api/node/mo/sys/ipv6/inst/dom-%s/rt-[%s].json?query-target=children' %\
        (self._parent.domain, self.prefix)
        resp = session.get(query_url).json()['imdata']
        for n_hop in resp:
            if n_hop.get('ipv6Nexthop'):
                n_hop_obj = 'ipv6Nexthop'
                addr = n_hop[n_hop_obj]['attributes']['nhAddr']
                i_face = n_hop[n_hop_obj]['attributes']['nhIf']
                vrf = n_hop[n_hop_obj]['attributes']['nhVrf']
                track_id = n_hop[n_hop_obj]['attributes']['object']
                tag = n_hop[n_hop_obj]['attributes']['tag']
                next_hop = IPV6NextHop(addr, i_face, vrf, track_id, tag)
                self.next_hops.append(next_hop)


class IPV6(BaseNXObject):
    """
    This class defines IPv6
    """
    def __init__(self, name=None, session=None, parent=None):
        """
        :param name: String 
        :param session: Session instance used for communicating with switch
        :param parent: parent class of this class
        """
        self._session = session
        self._parent = parent
        if not name:
            name = 'default'
        super(IPV6, self).__init__(name=name)
        self.i_faces = []
        self.cls_object = 'ipv6Dom'
        self.domain = name
        
        self.interfaces = []
        self.routes = []
    
    def get_url(self, fmt='json'):
        return '/api/node/mo/sys/ipv6/inst/dom-%s.%s' % ( self.domain, fmt)
    
    def get_delete_url(self, i_face, fmt='json'):
        return '/api/node/mo/sys/ipv6/inst/dom-%s/if-[%s].%s' % (self.domain,
                                                                 i_face, fmt)
    
    def _get_attributes(self):
        att = {}
        att['name'] = self.domain
        return att
    
    @classmethod
    def is_valid_ipv6_address(cls, address):
        try:
            socket.inet_pton(socket.AF_INET6, address)
        except socket.error:  # not a valid address
            return False
        return True
    
    def add_interface_address(self, interface, addr, link_local=None):
        """
        :param interface: Interface instance
        :param addr: String representing ipv6
        :param link_local: string representing link local address
        """
        if not isinstance(interface, (Interface, PortChannel)):
            raise TypeError('Interface or PortChannel instance expected')
        
        if not IPV6.is_valid_ipv6_address(addr.split('/')[0]):
            raise TypeError('Invalid address')
        
        if link_local and not IPV6.is_valid_ipv6_address(link_local):
            raise TypeError('Invalid address')
        
        if interface.if_name in self.i_faces:
            for ipv6_int in self._children:
                if ipv6_int.if_name == interface.if_name:
                    ipv6_int.add_address(addr)
                if link_local:
                    ipv6_int.set_link_local_addr(link_local)
        else:
            ipv6_int = IPV6Interface(interface.if_name, parent=self)
            if link_local:
                ipv6_int.set_link_local_addr(link_local)
            ipv6_int.add_address(addr)
            self._children.append(ipv6_int)
            self.i_faces.append(interface.if_name)
    
    def add_route(self, route):
        """Add route capability to the configuration"""
        if not isinstance(route, IPV6Route):
            raise TypeError('IPV6Route instance expected')
        self._children.append(route)
        self.routes.append(route)
    
    def get_json(self):
        return super(IPV6, self).get_json(self.cls_object,
                                          attributes=self._get_attributes())

    @classmethod
    def get(cls, session, interface=None, domain=None):
        """
        Get IPv6 details (interface / route)

        :param session: Session instance to commnunicate with switch
        :param interface: String represents interface i.e. ethx/y
        :return IPV6 object after storing interface and route details
        """
        if not isinstance(session, Session):
            raise TypeError('An instance of Session class is required')
        
        if not domain:
            domain = 'default'
        if interface:
            if 'eth' not in interface:
                raise TypeError('Not a valid interface')

            query_url = ('/api/node/mo/sys/ipv6/inst/dom-%s/if-[%s].json' 
                         % (domain, interface))
        else:
            query_url = ('/api/node/mo/sys/ipv6/inst/dom-%s.json?'
                         'query-target=children' % (domain))
        
        resp = session.get(query_url).json()['imdata']
        
        ipv6 = IPV6(domain)
        for ifs in resp:
            if ifs.get('ipv6If'):
                if_name = str(ifs['ipv6If']['attributes']['id'])
                admin_st = str(ifs['ipv6If']['attributes']['adminSt'])
                desc = str(ifs['ipv6If']['attributes']['descr'])
                ret_int = IPV6Interface(if_name, session=session)
                ret_int.set_admin_st(admin_st)
                ret_int.set_descr(desc)
                ret_int.get()
                ipv6.interfaces.append(ret_int)
                
            if ifs.get('ipv6Route'):
                prefix = str(ifs['ipv6Route']['attributes']['prefix'])
                route  = IPV6Route(prefix, parent=ipv6, session=session)
                route.get()
                ipv6.routes.append(route)

        return ipv6


class FeatureAttributes(object):
    """
    This class defines the attributes specific feature
    """
    
    def __init__(self, feature=None, session=None, parent=None):
        self._session= session
        self._parent = parent
        self.admin_st = None
        self.instance = None
        if feature:
            self.name = feature.lower()[2:]
            self.object = 'fm' + feature.title().replace('-','')

    def set_admin_st(self, admin_st):
        self.admin_st = admin_st
    
    def get_admin_st(self):
        return self.admin_st
        
    def set_instance(self, instance):
        self.instance = instance
    
    def get_instance(self):
        return self.instance        
  
    def _get_attributes(self):
        att = {}
        if self.admin_st:
            att['adminSt'] = self.admin_st
        return att
        
    def get_json(self):
        return {self.object : { "attributes" : self._get_attributes()}}
    
    
class Feature(BaseNXObject):
    """
    This defines the feature class
    """
    
    def __init__(self, session=None, parent=None):
        super(Feature, self).__init__(name="feature")
        self._session = session
        self._parent = parent
        
        # Base feature object
        self.object  = 'fmEntity'
    
    def enable(self, feature):
        feature_obj = FeatureAttributes(feature)
        feature_obj.set_admin_st('enabled')
        self._children.append(feature_obj)
        
    def disable(self, feature):
        feature_obj = FeatureAttributes(feature)
        feature_obj.set_admin_st('disabled')
        self._children.append(feature_obj)
        
    def get_json(self):
        return super(Feature, self).get_json(self.object)
    
    def get_url(self, fmt='json'):
        return '/api/mo/sys/fm.' + fmt
    
    def get(self, session=None):
        """
        :param session: Session object to communicate with Switch
        :return List of Feature objects
        """
        if not session:
            session = self._session
    
        query_url = '/api/mo/sys/fm.json?rsp-subtree=full'
        ret_data = []   
        resp = session.get(query_url).json()['imdata']
        for ret in resp:
            children = ret[self.object]['children']
            for child in children:
                for key in child:
                    admin_st = child[key]['attributes']['adminSt']
                    instance = child[key]['attributes']['maxInstance']
                    feature = FeatureAttributes(key)
                    feature.set_admin_st(admin_st)
                    feature.set_instance(instance)
                    ret_data.append(feature)

        return ret_data
