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
# from .nxphysobject import Interface
from .nxphysobject import *
from .nxbaseobject import BaseNXObject, BaseRelation, BaseInterface
from .nxsession import Session
from .nxtoolkitlib import Credentials
import logging
import json


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
        :param subnet_name: String containing the name of this Subnet instance.
        :param parent: An instance of BridgeDomain class representing the\
                       BridgeDomain which contains this Subnet.
        """
        if not isinstance(parent, BridgeDomain):
            raise TypeError('Parent of Subnet class must be BridgeDomain')
        super(Subnet, self).__init__(subnet_name, parent)
        self._addr = None
        self._scope = None

    @classmethod
    def _get_switch_classes(cls):
        """
        Get the APIC classes used by this nxtoolkit class.

        :returns: list of strings containing APIC class names
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
        Sets the attributes when creating objects from the APIC.
        Called from the base object when calling the classmethod get()
        """
        self.set_addr(str(attributes.get('ip')))

    @classmethod
    def get(cls, session, bridgedomain, tenant):
        """
        Gets all of the Subnets from the APIC for a particular tenant and
        bridgedomain.

        :param session: the instance of Session used for APIC communication
        :param bridgedomain: the instance of BridgeDomain used to limit the\
                             Subnet instances retreived from the APIC
        :param tenant: the instance of Tenant used to limit the Subnet\
                       instances retreived from the APIC
        :returns: List of Subnet objects

        """
        return BaseNXObject.get(session, cls, 'fvSubnet',
                                 parent=bridgedomain, tenant=tenant)


class L3Inst(BaseNXObject):
    """ L3Inst or VRF:  roughly equivalent to ACI Context """

    def __init__(self, l3inst_name, parent=None):
        """
        :param l3inst_name: String containing the L3Inst name
        :param parent: An instance of Tenant class representing the Tenant\
                       which contains this L3Inst.

        """
        super(L3Inst, self).__init__(l3inst_name, parent)
        self.name = l3inst_name
        self.adminState = 'admin-up'

    @classmethod
    def _get_switch_classes(cls):
        """
        Get the APIC classes used by this nxtoolkit class.

        :returns: list of strings containing APIC class names
        """
        resp = []
        resp.append('l3Inst')
        return resp

    @classmethod
    def _get_toolkit_to_switch_classmap(cls):
        """
        Gets the APIC class to an nxtoolkit class mapping dictionary

        :returns: dict of APIC class names to nxtoolkit classes
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
    def get_url(str, fmt='json'):
        """
        Get the URL used to push the configuration to the APIC
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
        Sets the attributes when creating objects from the APIC.
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
        Gets all of the L3Insts from the APIC.

        :param session: the instance of Session used for APIC communication
        :param tenant: the instance of Tenant used to limit the L3Insts\
                       retreived from the APIC
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
        :param bd_name:  String containing the name of this L2BD\
                         object.
        :param parent: An instance of Tenant class representing the Tenant\
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
        Get the APIC classes used by this nxtoolkit class.

        :returns: list of strings containing APIC class names
        """
        resp = []
        resp.append('l2BD')
        return resp

    @classmethod
    def _get_toolkit_to_switch_classmap(cls):
        """
        Gets the APIC class to an nxtoolkit class mapping dictionary

        :returns: dict of APIC class names to nxtoolkit classes
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

        :param session: the instance of Session used for APIC communication
        :param tenant: the instance of Tenant used to limit the L2BD\
                       instances retreived from the APIC
        :returns: List of L2BD objects
        """
        return BaseNXObject.get(session, cls, cls._get_switch_classes()[0])

    def _get_url_extension(self):
        return '/bd-[%s]' % self.name

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


class L3Interface(BaseNXObject):
    """
    Creates an L3 interface that can be attached to an L2 interface.
    This interface defines the L3 address i.e. IPv4
    """

    def __init__(self, name):
        """
        :param name:  String containing the name of this L3Interface object.
        """
        super(L3Interface, self).__init__(name)
        self._addr = None
        self._l3if_type = None
        self._mtu = 'inherit'
        self.networks = []

    def is_interface(self):
        """
        Check if this is an interface object.

        :returns: True
        """

        return True

    def get_addr(self):
        """
        Get the L3 address assigned to this interface.
        The address is set via the L3Interface.set_addr() method

        :returns: String containing the L3 address in dotted decimal notation.
        """
        return self._addr

    def set_addr(self, addr):
        """
        Set the L3 address assigned to this interface

        :param addr: String containing the L3 address in dotted decimal\
                     notation.
        """
        self._addr = addr

    def get_mtu(self):
        """
        Get the MTU of this interface

        :returns: MTU of the interface
        """
        return self._mtu

    def set_mtu(self, mtu):
        """
        Set the L3 MTU of this interface

        :param mtu: String containing MTU

        """
        self._mtu = mtu

    def get_l3if_type(self):
        """
        Get the l3if_type of this L3 interface.

        :returns: L3 interface type. Valid values are 'sub-interface',\
                  'l3-port', and 'ext-svi'
        """
        return self._l3if_type

    def set_l3if_type(self, l3if_type):
        """
        Set the l3if_type of this L3 interface.

        :param l3if_type: L3 interface type. Valid values are 'sub-interface',\
                          'l3-port', and 'ext-svi'
        """
        if l3if_type not in ('sub-interface', 'l3-port', 'ext-svi'):
            raise ValueError("l3if_type is not one of 'sub-interface', "
                             "'l3-port', or 'ext-svi'")
        self._l3if_type = l3if_type

    # Context references
    def add_context(self, context):
        """
        Add context to the EPG

        :param context: Instance of Context class to assign to this\
                        L3Interface.
        """
        assert isinstance(context, Context)
        if self.has_context():
            self.remove_context()
        self._add_relation(context)

    def remove_context(self):
        """
        Remove context from the EPG
        """
        self._remove_all_relation(Context)

    def get_context(self):
        """
        Return the assigned context

        :returns: Instance of Context class that this L3Interface is assigned.\
                  If no Context is assigned, None is returned.
        """
        return self._get_any_relation(Context)

    def has_context(self):
        """
        Check if the context has been assigned

        :returns: True or False. True if a Context has been assigned to this\
                  L3Interface.
        """
        return self._has_any_relation(Context)

    def get_json(self):
        """
        Returns json representation of L3Interface

        :returns: json dictionary of L3Interface
        """
        if self.get_addr() is None:
            return None
        text = {'l3extRsPathL3OutAtt': {'attributes': {'encap': '%s-%s' % (self.get_interfaces()[0].encap_type,
                                                                           self.get_interfaces()[0].encap_id),
                                                       'ifInstT': self.get_l3if_type(),
                                                       'addr': self.get_addr(),
                                                       'mtu': self.get_mtu(),
                                                       'tDn': self.get_interfaces()[0]._get_path()},
                                        'children': []}}
        return text


class OSPFInterfacePolicy(BaseNXObject):
    """
    Represents the interface settings of an OSPF interface
    """

    def __init__(self, name, parent=None):
        """
        param name: String containing the name of this OSPF interface policy
        param parent: Instance of the Tenant class representing the tenant\
                      owning this OSPF interface policy
        """

        self.name = name
        self.parent = parent

        # Initialize default values
        self.network_type = 'bcast'
        self.cost = None
        self.priority = None
        self.hello_interval = None
        self.dead_interval = None
        self.retrans_interval = None
        self.transmit_delay = None

        if not isinstance(parent, Tenant):
            raise TypeError('Parent is not set to Tenant')
        super(OSPFInterfacePolicy, self).__init__(name, parent)

    def _generate_attributes(self):
        """Gets the attributes used in generating the JSON for the object
        """
        attributes = dict()
        attributes['name'] = self.name
        if self.descr:
            attributes['descr'] = self.descr
        if self.network_type:
            attributes['nwT'] = self.network_type
        if self.cost:
            attributes['cost'] = self.cost
        if self.priority:
            attributes['priority'] = self.priority
        if self.hello_interval:
            attributes['helloIntvl'] = self.hello_interval
        if self.dead_interval:
            attributes['deadIntvl'] = self.dead_interval
        if self.retrans_interval:
            attributes['rexmitIntvl'] = self.retrans_interval
        if self.transmit_delay:
            attributes['xmitDelay'] = self.transmit_delay
        return attributes

    def get_nw_type(self):
        """
        Get the nw-type of this interface ospf policy
        :returns: string of the network type for this policy
        """
        return self.network_type

    def set_nw_type(self, network_type):
        """
        sets the L3 nw_type with some validation

        :param network_type: string of bcast or p2p

        """
        valid_types = ['bcast', 'p2p']
        if network_type not in valid_types:
            raise ValueError('Invalid Network Type - %s' % network_type)
        else:
            self.network_type = network_type

    def get_json(self):
        """
        Returns json representation of OSPFRouter

        :returns: json dictionary of OSPFIRouter
        """
        attr = self._generate_attributes()
        text = {"ospfIfPol": {"attributes": attr}}
        return text


class OSPFRouter(BaseNXObject):
    """
    Represents the global settings of the OSPF Router
    """

    def __init__(self, name):
        """
        :param name:  String containing the name of this OSPFRouter object.
        """
        super(OSPFRouter, self).__init__(name)
        self._router_id = None
        self._node = None
        self._pod = '1'

    def set_router_id(self, rid):
        """
        Sets the router id of the object
        :param rid: String containing the router id

        """
        self._router_id = rid

    def get_router_id(self):
        """
        :returns string containing the Router ID
        """
        return self._router_id

    def set_node_id(self, node):
        """
        Sets the router id of the object
        :param node: String containing the node id

        """
        self._node = node

    def get_node_id(self):
        """
        :returns string containing the Node ID
        """
        return self._node

    def get_json(self):
        """
        Returns json representation of OSPFRouter

        :returns: json dictionary of OSPFIRouter
        """
        dn_name = "topology/pod-%s/node-%s" % (self._pod, self._node)
        text = {"l3extRsNodeL3OutAtt": {"attributes": {"rtrId": self._router_id,
                                                       "tDn": dn_name}}}
        return text


class OSPFInterface(BaseNXObject):
    """
    Creates an OSPF router interface that can be attached to a L3 interface.
    This interface defines the OSPF area, authentication, etc.
    """

    def __init__(self, name, router=None, area_id=None):
        """
        :param name:  String containing the name of this OSPFInterface object.
        :param area_id: String containing the OSPF area id of this interface.\
                        Default is None.
        """
        super(OSPFInterface, self).__init__(name)
        self.area_id = area_id
        self.router = router
        self.int_policy_name = None
        self.auth_key = None
        self.auth_type = None
        self.auth_keyid = None
        self.networks = []

    def is_interface(self):
        """
        Returns whether this instance is considered an interface.
        :returns: True
        """
        return True

    @staticmethod
    def is_ospf():
        """
        :returns: True if this interface is an OSPF interface.  In the case\
                  of OSPFInterface instances, this is always True.
        """
        return True

    def get_json(self):
        """
        Returns json representation of OSPFInterface
        :returns: json dictionary of OSPFInterface
        """
        children = []
        if self.int_policy_name:
            policy = {'ospfRsIfPol': {'attributes': {'tnOspfIfPolName': self.int_policy_name}}}
            children.append(policy)

        text = {'ospfIfP': {'attributes': {'name': self.name},
                            'children': children}}
        if self.auth_key:
            text['ospfIfP']['attributes']['authKey'] = self.auth_key
            text['ospfIfP']['attributes']['authKeyId'] = self.auth_keyid
            text['ospfIfP']['attributes']['authType'] = self.auth_type

        text = [text, self.get_interfaces()[0].get_json()]
        text = {'l3extLIfP': {'attributes': {'name': self.name},
                              'children': text}, }
        text = {'l3extLNodeP': {'attributes': {'name': self.name},
                                'children': [text, self.router.get_json()]}}
        return text


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
        Get the APIC classes used by this nxtoolkit class.

        :returns: list of strings containing APIC class names
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
        Gets the APIC class to an nxtoolkit class mapping dictionary

        :returns: dict of APIC class names to nxtoolkit classes
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
        Sets the attributes when creating objects from the APIC.
        Called from the base object when calling the classmethod get()
        """
        self.set_type(str(attributes.get('type')))

    @classmethod
    def get(cls, session, bgppeer, tenant):
        """
        Gets all of the BGPPeerAFs from the Switch for a particular BGPPeer

        :param session: the instance of Session used for APIC communication
        :param bgppeer: the instance of BGPPeer using the AF
        :returns: List of BGPPeerAF objects

        """
        return BaseNXObject.get(session, cls, 'bgpPeerAf', parent=bgppeer)


class BGPPeer(BaseNXObject):
    """ BGPPeer :  roughly equivalent to bgpPeer """

    def __init__(self, addr, parent=None):
        """
        :param subnet_name: String containing the name of this BGPPeer instance.
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
        Get the APIC classes used by this nxtoolkit class.

        :returns: list of strings containing APIC class names
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
        Gets the APIC class to an nxtoolkit class mapping dictionary

        :returns: dict of APIC class names to nxtoolkit classes 
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
        Sets the attributes when creating objects from the APIC.
        Called from the base object when calling the classmethod get()
        """
        self.set_addr(str(attributes.get('addr')))
        self.set_remote_as(str(attributes.get('asn')))
        self.set_src_if(str(attributes.get('srcIf')))

    @classmethod
    def get(cls, session, bgpdomain):
        """
        Gets all of the BGPPeers from the APIC for a particular BGPDomain

        :param session: the instance of Session used for APIC communication
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
        Get the APIC classes used by this nxtoolkit class.

        :returns: list of strings containing APIC class names
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
        Gets the APIC class to an nxtoolkit class mapping dictionary

        :returns: dict of APIC class names to nxtoolkit classes
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
        Sets the attributes when creating objects from the APIC.
        Called from the base object when calling the classmethod get()
        """
        self.set_addr(str(attributes.get('addr')))

    @classmethod
    def get(cls, session, bgpdomainaf):
        """
        Gets all of the BGPAdvPrefix from the APIC for a particular BGPDomainAF

        :param session: the instance of Session used for APIC communication
        :param bgpdomainaf: the instance of BGPDomainAF used to limit the\
                             BGPAdvPrefix instances retreived from the Switch
        :returns: List of BGPAdvPrefix objects

        """
        return BaseNXObject.get(session, cls, 'bgpAdvPrefix', parent=bgpdomainaf)


class BGPDomainAF(BaseNXObject):
    """ BGPDomainAF :  roughly equivalent to bgpDomAf """

    def __init__(self, af_type, parent=None):
        """
        :param subnet_name: String containing the name of this BGPPeer instance.
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
        Get the APIC classes used by this nxtoolkit class.

        :returns: list of strings containing APIC class names
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
        Gets the APIC class to an nxtoolkit class mapping dictionary

        :returns: dict of APIC class names to nxtoolkit classes
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
        Sets the attributes when creating objects from the APIC.
        Called from the base object when calling the classmethod get()
        """
        self.set_type(str(attributes.get('type')))

    @classmethod
    def get(cls, session, bgpdomain):
        """
        Gets all of the BGPDomainAF from the Switch for a particular BGPDomain

        :param session: the instance of Session used for APIC communication
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
        :param peer_ip: String containing the IP address of the BGP peer\
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
        Get the APIC classes used by this nxtoolkit class.

        :returns: list of strings containing APIC class names
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
        Gets the APIC class to an nxtoolkit class mapping dictionary

        :returns: dict of APIC class names to nxtoolkit classes
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

        # If no tenant names passed, get all tenant names from APIC
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

            # the following works around a bug encountered in the json returned from the APIC
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
        :param session: the instance of Session used for APIC communication
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
        Check if a bgpdomain exists on the APIC.

        :param session: the instance of Session used for APIC communication
        :param bgpdomain: the instance of BGPDomain to check if exists on the APIC
        :returns: True or False
        """
        sw_bgpdomains = cls.get(session)
        for sw_bgpdomain in sw_bgpdomains:
            if bgpdomain == sw_bgpdomain:
                return True
        return False

    def get_identifier(cls):
        return cls._name

    @staticmethod
    def get_url(str, fmt='json'):
        """
        Get the URL used to push the configuration to the APIC
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
        Get the APIC classes used by this nxtoolkit class.

        :returns: list of strings containing APIC class names
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

        # If no tenant names passed, get all tenant names from APIC
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

            # the following works around a bug encountered in the json returned from the APIC
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
        attributes = super(BGPSession, self)._generate_attributes()
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
        return super(BGPSession, self).get_json(self._get_switch_classes()[0],
                                                attributes=attr)

    @classmethod
    def get(cls, session, parent=None):
        """
        Gets all of the BGP Sessions from the Switch.

        :param parent: Parent object of the BGPSession
        :param session: the instance of Session used for APIC communication
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
        Check if a bgpsession exists on the APIC.

        :param session: the instance of Session used for APIC communication
        :param bgpsession: the instance of BGPSession to check if exists on the APIC
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
        Get the URL used to push the configuration to the APIC
        if no format parameter is specified, the format will be 'json'
        otherwise it will return '/api/mo/sys/bgp/inst.' with the format string
        appended.

        :param fmt: optional format string, default is 'json'
        :returns: URL string
        """
        return '/api/mo/sys/bgp/inst/.' + fmt

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
        To get all of nxtoolkit style Filter Entries APIC class.

        :param session:  the instance of Session used for APIC communication
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


class TunnelInterface(object):
    """This class describes a tunnel interface"""

    def __init__(self, if_type, pod, node, tunnel):
        self.interface_type = str(if_type)
        self.pod = str(pod)
        self.node = str(node)
        self.tunnel = tunnel
        self.if_name = self.interface_type + ' ' + self.pod + '/'
        self.if_name += self.node + '/' + self.tunnel


class FexInterface(object):
    """This class describes a physical interface on a FEX device"""

    def __init__(self, if_type, pod, node, fex, module, port):
        self.interface_type = str(if_type)
        self.pod = str(pod)
        self.node = str(node)
        self.fex = str(fex)
        self.module = str(module)
        self.port = str(port)
        self.if_name = self.interface_type + ' ' + self.pod + '/'
        self.if_name += self.node + '/' + self.fex + '/'
        self.if_name += self.module + '/' + self.port


class InterfaceFactory(object):
    """
    Factory class to generate interface objects
    """

    @classmethod
    def create_from_dn(cls, dn):
        """
        Creates the appropriate interface object based on the dn
        The classes along with an example DN are shown below
        Interface: topology/pod-1/paths-102/pathep-[eth1/12]
        FexInterface: topology/pod-1/paths-103/extpaths-105/pathep-[eth1/12]
        TunnelInterface:
        BladeSwitchInterface:
        """
        if '/extpaths-' in dn:
            # Split the URL into 2 parts
            dn_parts = dn.split('[')

            # Split the first part
            loc = dn_parts[0].split('/')
            assert loc[0] == 'topology'
            # Get the Pod number
            pod = loc[1].split('-')
            assert pod[0] == 'pod'
            pod = pod[1]
            # Get the Node number
            node = loc[2].split('-')
            assert node[0] == 'paths'
            node = node[1]
            # Get the Fex number
            fex = loc[3].split('-')
            assert fex[0] == 'extpaths'
            fex = fex[1]
            # Get the type, module, and port
            mod_port = dn_parts[1].split(']')[0]
            if_type = mod_port[:3]
            (module, port) = mod_port[3:].split('/')
            return FexInterface(if_type, pod, node, fex, module, port)
        elif 'pathep-[tunnel' in dn:
            # Split the URL into 2 parts
            dn_parts = dn.split('[')

            # Split the first part
            loc = dn_parts[0].split('/')
            assert loc[0] == 'topology'
            # Get the Pod number
            pod = loc[1].split('-')
            assert pod[0] == 'pod'
            pod = pod[1]
            # Get the Node number
            node = loc[2].split('-')
            assert node[0] == 'paths'
            node = node[1]
            # Get the tunnel
            assert loc[3] == 'pathep-'
            tunnel = dn_parts[1].split(']')[0]
            assert tunnel.startswith('tunnel')
            tunnel = tunnel[6:]

            return TunnelInterface('tunnel', pod, node, tunnel)
        else:
            return Interface(*Interface.parse_dn(dn))


class PortChannel(BaseInterface):
    """
    This class defines a port channel interface.
    """

    def __init__(self, name):
        super(PortChannel, self).__init__(name)
        self._interfaces = []
        self._nodes = []

    def attach(self, interface):
        """Attach an interface to this PortChannel"""
        if interface not in self._interfaces:
            self._interfaces.append(interface)
        self._update_nodes()

    def detach(self, interface):
        """Detach an interface from this PortChannel"""
        if interface in self._interfaces:
            self._interfaces.remove(interface)
        self._update_nodes()

    def _update_nodes(self):
        """Updates the nodes that are participating in this PortChannel"""
        nodes = []
        for interface in self._interfaces:
            nodes.append(interface.node)
        self._nodes = set(nodes)

    def is_vpc(self):
        """Returns True if the PortChannel is a VPC"""
        return len(self._nodes) > 1

    def is_interface(self):
        """Returns True since a PortChannel is an interface"""
        return True

    def _get_nodes(self):
        """ Returns a single node id or multiple node ids in the
            case that this is a VPC
        """
        return self._nodes

    def _get_path(self):
        """Get the path of this interface used when communicating with
           the APIC object model.
        """
        assert len(self._interfaces)
        pod = self._interfaces[0].pod
        if self.is_vpc():
            (node1, node2) = self._get_nodes()
            path = 'topology/pod-%s/protpaths-%s-%s/pathep-[%s]' % (pod,
                                                                    node1,
                                                                    node2,
                                                                    self.name)
        else:
            node = self._interfaces[0].node
            path = 'topology/pod-%s/paths-%s/pathep-%s' % (pod,
                                                           node,
                                                           self.name)

        return path

    @staticmethod
    def get_url(str, fmt='json'):
        """
        Get the URLs used to push the configuration to the APIC
        if no format parameter is specified, the format will be 'json'
        otherwise it will return '/api/mo/uni.' with the format string
        appended.
        :param fmt: optional format string, default is 'json'
        :returns: URL string
        """
        return ('/api/mo/uni/fabric.' + fmt,
                '/api/mo/uni.' + fmt)

    def get_json(self):
        """
        Returns json representation of the PortChannel

       :returns: json dictionary of the PortChannel
        """
        vpc = self.is_vpc()
        pc_mode = 'link'
        if vpc:
            pc_mode = 'node'
        infra = {'infraInfra': {'children': []}}
        # Add the node and port selectors
        for interface in self._interfaces:
            node_profile, accport_selector = interface.get_port_channel_selector_json(self.name)
            infra['infraInfra']['children'].append(node_profile)
            if self.is_deleted():
                for hports in accport_selector['infraAccPortP']['children']:
                    if 'infraHPortS' in hports:
                        for child in hports['infraHPortS']['children']:
                            if 'infraRsAccBaseGrp' in child:
                                child['infraRsAccBaseGrp']['attributes']['status'] = 'deleted'
            infra['infraInfra']['children'].append(accport_selector)
        # Add the actual port-channel
        accbndlgrp = {'infraAccBndlGrp': {'attributes': {'name': self.name, 'lagT': pc_mode},
                                          'children': []}}
        if self.is_deleted():
            accbndlgrp['infraAccBndlGrp']['attributes']['status'] = 'deleted'
        infrafuncp = {'infraFuncP': {'attributes': {},
                                     'children': [accbndlgrp]}}
        infra['infraInfra']['children'].append(infrafuncp)

        if not vpc:
            return None, infra

        # VPC add Fabric Protocol Policy
        # Pick the lowest node as the unique id for the vpc group
        nodes = []
        for interface in self._interfaces:
            nodes.append(str(interface.node))
        unique_nodes = sorted(set(nodes))
        unique_id = unique_nodes[0]

        fabric_nodes = []
        for node in unique_nodes:
            fabric_node = {'fabricNodePEp': {'attributes': {'id': node}}}
            fabric_nodes.append(fabric_node)
        fabric_group = {'fabricExplicitGEp': {'attributes': {'name': 'vpc' + unique_id, 'id': unique_id},
                                              'children': fabric_nodes}}
        fabric_prot_pol = {'fabricProtPol': {'attributes': {'name': 'vpc' + unique_id},
                                             'children': [fabric_group]}}
        return fabric_prot_pol, infra

    @staticmethod
    def get(session):
        """Gets all of the port channel interfaces from the APIC
        """
        if not isinstance(session, Session):
            raise TypeError('An instance of Session class is required')
        interface_query_url = ('/api/node/class/infraAccBndlGrp.json?'
                               'query-target=self')
        portchannels = []
        ret = session.get(interface_query_url)
        pc_data = ret.json()['imdata']
        for pc in pc_data:
            portchannel_name = str(pc['infraAccBndlGrp']['attributes']['name'])
            portchannel = PortChannel(portchannel_name)
            portchannels.append(portchannel)
        return portchannels


class Endpoint(BaseNXObject):
    """
    Endpoint class
    """

    def __init__(self, name, parent):
        if not isinstance(parent, EPG):
            raise TypeError('Parent must be of EPG class')
        super(Endpoint, self).__init__(name, parent=parent)
        self.mac = None
        self.ip = None
        self.encap = None
        self.if_name = None

    @classmethod
    def _get_switch_classes(cls):
        """
        Get the APIC classes used by this nxtoolkit class.

        :returns: list of strings containing APIC class names
        """
        resp = []
        resp.append('fvCEp')
        resp.append('fvStCEp')
        return resp

    @classmethod
    def _get_toolkit_to_switch_classmap(cls):
        """
        Gets the APIC class to an nxtoolkit class mapping dictionary

        :returns: dict of APIC class names to nxtoolkit classes
        """
        return {}

    @staticmethod
    def _get_parent_class():
        """
        Gets the class of the parent object

        :returns: class of parent object
        """
        return EPG

    @staticmethod
    def _get_parent_dn(dn):
        if '/stcep-' in dn:
            return dn.split('/stcep-')[0]
        else:
            return dn.split('/cep-')[0]

    @staticmethod
    def _get_name_from_dn(dn):
        if '/stcep-' in dn:
            name = dn.split('/stcep-')[1].split('-type-')[0]
        else:
            name = dn.split('/cep-')[1]
        return name

    def get_json(self):
        return None

    def _populate_from_attributes(self, attributes):
        if 'mac' not in attributes:
            return
        self.mac = str(attributes.get('mac'))
        self.ip = str(attributes.get('ip'))
        self.encap = str(attributes.get('encap'))

    @classmethod
    def get_event(cls, session, with_relations=True):
        urls = cls._get_subscription_urls()
        for url in urls:
            if not session.has_events(url):
                continue
            event = session.get_event(url)
            for class_name in cls._get_switch_classes():
                if class_name in event['imdata'][0]:
                    break
            attributes = event['imdata'][0][class_name]['attributes']
            status = str(attributes.get('status'))
            dn = str(attributes.get('dn'))
            parent = cls._get_parent_from_dn(cls._get_parent_dn(dn))
            if status == 'created':
                name = str(attributes.get('mac'))
            else:
                name = cls._get_name_from_dn(dn)
            obj = cls(name, parent=parent)
            obj._populate_from_attributes(attributes)
            obj.timestamp = str(attributes.get('modTs'))
            if obj.mac is None:
                obj.mac = name
            if status == 'deleted':
                obj.mark_as_deleted()
            elif with_relations:
                objs = cls.get(session, name)
                if len(objs):
                    obj = objs[0]
                else:
                    # Endpoint was deleted before we could process the create
                    # return what we what we can from the event
                    pass
            return obj

    @staticmethod
    def _get(session, endpoint_name, interfaces, endpoints,
             apic_endpoint_class, endpoint_path):
        """
        Internal function to get all of the Endpoints

        :param session: Session object to connect to the APIC
        :param endpoint_name: string containing the name of the endpoint
        :param interfaces: list of interfaces
        :param endpoints: list of endpoints
        :param apic_endpoint_class: class of endpoint
        :param endpoint_path: interface of the endpoint
        :return: list of Endpoints
        """
        # Get all of the Endpoints
        if endpoint_name is None:
            endpoint_query_url = ('/api/node/class/%s.json?query-target=self'
                                  '&rsp-subtree=full' % apic_endpoint_class)
        else:
            endpoint_query_url = ('/api/node/class/%s.json?query-target=self'
                                  '&query-target-filter=eq(%s.mac,"%s")'
                                  '&rsp-subtree=full' % (apic_endpoint_class,
                                                         apic_endpoint_class,
                                                         endpoint_name))
        ret = session.get(endpoint_query_url)
        ep_data = ret.json()['imdata']
        for ep in ep_data:
            if ep[apic_endpoint_class]['attributes']['lcC'] == 'static':
                continue
            if 'children' in ep[apic_endpoint_class]:
                children = ep[apic_endpoint_class]['children']
            else:
                children = []
            ep = ep[apic_endpoint_class]['attributes']
            tenant = Tenant(str(ep['dn']).split('/')[1][3:])
            if '/LDevInst-' in str(ep['dn']):
                unknown = '?' * 10
                app_profile = AppProfile(unknown, tenant)
                epg = EPG(unknown, app_profile)
            else:
                app_profile = AppProfile(str(ep['dn']).split('/')[2][3:],
                                         tenant)
                epg = EPG(str(ep['dn']).split('/')[3][4:], app_profile)
            endpoint = Endpoint(str(ep['name']), parent=epg)
            endpoint.mac = str(ep['mac'])
            endpoint.ip = str(ep['ip'])
            endpoint.encap = str(ep['encap'])
            endpoint.timestamp = str(ep['modTs'])
            for child in children:
                if endpoint_path in child:
                    endpoint.if_name = str(child[endpoint_path]['attributes']['tDn'])
                    for interface in interfaces:
                        interface = interface['fabricPathEp']['attributes']
                        interface_dn = str(interface['dn'])
                        if endpoint.if_name == interface_dn:
                            if str(interface['lagT']) == 'not-aggregated':
                                endpoint.if_name = InterfaceFactory.create_from_dn(interface_dn).if_name
                            else:
                                endpoint.if_name = interface['name']
                    endpoint_query_url = '/api/mo/' + endpoint.if_name + '.json'
                    ret = session.get(endpoint_query_url)
            endpoints.append(endpoint)
        return endpoints

    @staticmethod
    def get(session, endpoint_name=None):
        """Gets all of the endpoints connected to the fabric from the APIC
        """
        if not isinstance(session, Session):
            raise TypeError('An instance of Session class is required')

        # Get all of the interfaces
        interface_query_url = ('/api/node/class/fabricPathEp.json?'
                               'query-target=self')
        ret = session.get(interface_query_url)
        interfaces = ret.json()['imdata']

        endpoints = []
        endpoints = Endpoint._get(session, endpoint_name, interfaces,
                                  endpoints, 'fvCEp', 'fvRsCEpToPathEp')
        endpoints = Endpoint._get(session, endpoint_name, interfaces,
                                  endpoints, 'fvStCEp', 'fvRsStCEpToPathEp')

        return endpoints

    @classmethod
    def get_all_by_epg(cls, session, tenant_name, app_name, epg_name, with_interface_attachments=True):
        if with_interface_attachments:
            raise NotImplementedError
        query_url = ('/api/mo/uni/tn-%s/ap-%s/epg-%s.json?'
                     'rsp-subtree=children&'
                     'rsp-subtree-class=fvCEp,fvStCEp' % (tenant_name, app_name, epg_name))
        ret = session.get(query_url)
        data = ret.json()['imdata']
        endpoints = []
        if len(data) == 0:
            return endpoints
        assert len(data) == 1
        assert 'fvAEPg' in data[0]
        if 'children' not in data[0]['fvAEPg']:
            return endpoints
        endpoints_data = data[0]['fvAEPg']['children']
        if len(endpoints_data) == 0:
            return endpoints
        tenant = Tenant(tenant_name)
        app = AppProfile(app_name, tenant)
        epg = EPG(epg_name, app)
        for ep_data in endpoints_data:
            if 'fvStCEp' in ep_data:
                mac = ep_data['fvStCEp']['attributes']['mac']
                ip = ep_data['fvStCEp']['attributes']['ip']
            else:
                mac = ep_data['fvCEp']['attributes']['mac']
                ip = ep_data['fvCEp']['attributes']['ip']
            ep = cls(str(mac), epg)
            ep.mac = mac
            ep.ip = ip
            endpoints.append(ep)
        return endpoints

    @staticmethod
    def get_table(endpoints, title=''):
        """
        Will create table of taboo information for a given tenant
        :param title:
        :param endpoints:
        """

        result = []
        headers = ['Tenant', 'Context', 'Bridge Domain', 'App Profile', 'EPG', 'Name', 'MAC', 'IP', 'Interface',
                   'Encap']
        data = []
        for endpoint in sorted(endpoints, key=lambda x: (x.name)):
            epg = endpoint.get_parent()
            bd = 'Not Set'
            context = 'Not Set'
            if epg.has_bd():
                bd = epg.get_bd().name
                if epg.get_bd().has_context():
                    context = epg.get_bd().get_context().name

            data.append([
                endpoint.get_parent().get_parent().get_parent().name,
                context,
                bd,
                endpoint.get_parent().get_parent().name,
                endpoint.get_parent().name,
                endpoint.name,
                endpoint.mac,
                endpoint.ip,
                endpoint.if_name,
                endpoint.encap
            ])
        data = sorted(data, key=lambda x: (x[1], x[2], x[3], x[4]))
        result.append(Table(data, headers, title=title + 'Endpoints'))
        return result


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
        Get the APIC classes used by this nxtoolkit class.

        :returns: list of strings containing APIC class names
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
        Gets all of the L2Ext Domains from the APIC

        :param session: the instance of Session used for APIC communication
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
        Gets all of the Physical Domainss from the APIC

        :param session: the instance of Session used for APIC communication
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
        Get the APIC classes used by this nxtoolkit class.

        :returns: list of strings containing APIC class names
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
        Gets all of the Physical Domains from the APIC

        :param session: the instance of Session used for APIC communication
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
        Gets all of the L3Ext Domains from the APIC

        :param session: the instance of Session used for APIC communication
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
        fvnsEncapInstP = {fvnsEncapInstP_string: {'attributes': {'name': self.name,
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
    """ Base class for monitoring policies.  These are methods that can be
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
        created and not been written to the APIC
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
    as children that are used to override the default behavior for a particular
    target class such as Interfaces.  There can be further granularity of
    control through children of the MonitorTarget sub-objects.

    Children of the MonitorPolicy will be CollectionPolicy objects that define
    the collection policy plus optional MonitorTarget objects that allow finer
    grained control over specific target APIC objects such as 'l1PhysIf' (layer
    1 physical interface).

    The CollectionPolicy children are contained in a dictionary called
    "collection_policy" that is indexed by the granulariy of the
    CollectionPolicy, e.g. '5min', '15min', etc.

    The MonitorTarget children are contained in a dictionary called
    "monitor_target" that is indexed by the name of the target object,
    e.g. 'l1PhysIf'.

    To make a policy take effect for a particular port, for example, you must
    attach that monitoring policy to the port.

    Note that the name of the MonitorPolicy is used to construct the dn of the
    object in the APIC.  As a result, the name cannot be changed.  If you read
    a policy from the APIC, change the name, and write it back, it will create
    a new policy with the new name and leave the old, original policy, in place
    with its original name.

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
        name (dn) along with the policyType in the APIC.  The dn for "fabric"
        policies will be /uni/fabric/monfabric-[name] and for "access" policies
        it will be /uni/infra/moninfra-[name] in the APIC.

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

        # assume that it has not been written to APIC.  This is cleared if the
        # policy is just loaded from APIC or the policy is written to the APIC.
        self.modified = True

    @classmethod
    def get(cls, session):
        """
        get() will get all of the monitor policies from the APIC and return
        them as a list.  It will get both fabric and access (infra) policies
        including default policies.

       :param session: the instance of Session used for APIC communication
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
        Get the class from the APIC

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

        :param target:  APIC target object.  This will default to 'l1PhysIf'
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
    apply to all Interface clas objects (l1PhysIf in the APIC) that use the
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
        # assume that it has not been written to APIC.
        # This is cleared if the policy is just loaded from APIC
        # or the policy is written to the APIC.
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

       :param parent: Parent object that this monitor stats object should be\
                      applied to. This must be an object of type MonitorTarget.
       :param statsFamily: String specifying the statistics family that the\
                           children collection policies should be applied to.\
                           Possible values are:['egrBytes', 'egrPkts',\
                           'egrTotal', 'egrDropPkts', 'ingrBytes', 'ingrPkts',\
                           'ingrTotal', 'ingrDropPkts', 'ingrUnkBytes',\
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
        # assume that it has not been written to APIC.  This is cleared if
        # the policy is just loaded from APIC or the policy is written to
        # the APIC.
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
    in the APIC.
    """
    # this must be in order from small to large
    granularityEnum = ['5min', '15min', '1h', '1d',
                       '1w', '1mo', '1qtr', '1year']
    retentionEnum = ['none', 'inherited', '5min', '15min', '1h', '1d',
                     '1w', '10d', '1mo', '1qtr', '1year', '2year', '3year']

    def __init__(self, parent, granularity, retention, adminState='enabled'):
        """
        The CollectionPolicy must always be initialized with a parent object of
        type MonitorPolicy, MonitorTarget or MonitorStats. The granularity must
        also be specifically specified.  The retention period can be specified,
        set to "none", or set to "inherited".
        Note that the "none" value is a string, not the Python None.  When the
        retention period is set to "none" there will be no historical stats
        kept. However, assuming collection is enabled, stats will be kept for
        the current time period.

        If the retention period is set to "inherited", the value will be
        inherited from the less specific policy directly above this one. The
        same applies to the adminState value.  It can be 'disabled', 'enabled',
        or 'inherited'.  If 'disabled', the current scope of counters are not
        gathered.  If enabled, they are gathered.  If 'inherited', it will be
        according to the next higher scope.

        Having the 'inherited' option on the retention and administrative
        status allows these items independently controlled at the current
        stats granularity.  For example, you can specify that ingress unknown
        packets are gathered every 15 minutes by setting adding a collection
        policy that specifies a 15 minutes granularity and an adminState of
        'enabled' under a MonitorStats object that sets the scope to be ingress
        unknown packets.  This might override a higher level policy that
        disabled collection at a 15 minute interval.   However, you can set the
        retention in that same object to be "inherited" so that this specific
        policy does not change the retention behavior from that of the higher,
        less specific, policy.

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
        # assume that it has not been written to APIC.  This is cleared if
        # the policy is just loaded from APIC or the policy is written to
        # the APIC.
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
    This is the root class for the logical part of the network.  It's corrolary is the PhysicalModel class.
    It is a container that can hold all of logical model instances such as Tenants.

    From this class, you can populate all of the children classes.
    """

    def __init__(self, session=None, parent=None):
        """
        Initialization method that sets up the Fabric.
        :return:
        """
        if session:
            assert isinstance(session, Session)

        # if parent:
        #     assert isinstance(parent, Fabric)

        super(LogicalModel, self).__init__(name='', parent=parent)

        self.session = session

    @classmethod
    def get(cls, session=None, parent=None):
        """
        Method to get all of the PhysicalModels.  It will get one and return it in a list.
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
        Tenant.get(self.session, self)

        if deep:
            for child in self._children:
                child.populate_children(deep, include_concrete)

        return self._children
