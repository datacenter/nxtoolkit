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
NX Toolkit module for counter and stats objects
"""

import re


class InterfaceStats(object):
    """
    This class defines interface statistics.  It will provide methods to
    retrieve the stats.  The stats are returned as a dictionary with the
    following structure:

    stats= {<counterFamily>:{<counter>:value}}

    stats are gathered and summed up in time intervals or granularities.
    For each granularity there are a set of time periods identified by
    the <period> field.  The current stats are stored in period 0.  These
    stats are zeroed at the beginning of the time interval and are updated
    at a smaller time interval depending on the granularity.  Historical
    statistics have periods that are greater than 0.  The number of historical
    stats to keep is determined by the monitoring policy and may be specific
    to a particular counter family.

    The counter families are as follows: 'egrTotal', 'egrBytes', 'egrPkts',
    'egrDropPkts', 'ingrBytes', 'ingrPkts', 'ingrTotal', 'ingrDropPkts',
    'ingrUnkBytes','ingrUnkPkts', 'ingrStorm'.

    The granularities are: '5min', '15min', '1h', '1d', '1w', '1mo',
    '1qtr', and '1year'.

    For each counter family/granularity/period there are several counter
    values retained.  The best way to see a list of these counters is to
    print the keys of the dictionary.
    """
    def __init__(self, parent, interfaceDn):
        self._parent = parent
        self._interfaceDn = interfaceDn

    @classmethod
    def get_all_ports(cls, session, period=None):
        """
        This method will get all the interface stats for all of the interfaces and return it as a dictionary indexed by the interface id.
        This method is optimized to minimize the traffic to and from the Switch and is intended to typically be used with the period specified
        so that only the necessary stats are pulled.  Note that it will pull the stats for ALL the interfaces.  This may have latency
        implications.

        :param session: Session to use when accessing the Switch
        :param period: Epoch or period to retrieve - all are retrieved if this is not specified

        :returns:  Dictionary of counters. Format is {<interface_id>{<counterFamily>:
                        {<granularity>:{<period>:{<counter>:value}}}}}
        """

        if period:
            if (period < 1):
                raise ValueError('Counter epoch/period value of 0 not yet implemented')
            mo_query_url = '/api/class/l1PhysIf.json?&rsp-subtree-include=stats&rsp-subtree-' \
                           'class=statsHist&rsp-subtree-filter=eq(statsHist.index,"'+str(period-1)+'")'
        else:
            mo_query_url = '/api/class/l1PhysIf.json?&rsp-subtree-include=stats&rsp-subtree-class=statsHist'
        ret = session.get(mo_query_url)
        data = ret.json()['imdata']

        result = {}
        for interface in data:
            if 'children' in interface['l1PhysIf']:
                port_id = cls._parseDn2PortId(interface['l1PhysIf']['attributes']['dn'])
                port_stats = InterfaceStats._process_data(interface)
                result[port_id] = port_stats
        return result

    @classmethod
    def _parseDn2PortId(cls, dn):
        """
        This will parse the dn and return a port_id string.

        Handles DNs that look like the following:
        topology/pod-1/node-103/sys/phys-[eth1/12]
        and returns 1/103/1/12.
        """
        name = dn.split('/')
        pod = name[1].split('-')[1]
        node = name[2].split('-')[1]
        module = name[4].split('[')[1]
        interface_type = module[:3]
        module = module[3:]
        port = name[5].split(']')[0]

        return '{0}/{1}/{2}/{3}'.format(pod, node, module, port)

    def get(self, session=None, period=None):
        """
        Retrieve the count dictionary.  This method will read in all the
        counters and return them as a dictionary.

        :param session: Session to use when accessing the Switch
        
        :returns:  Dictionary of counters. Format is {<counterFamily>: {<counter>:value}}
        """
        result = {}
        if not session:
            session = self._parent._session

        mo_query_url = '/api/mo/' + self._interfaceDn + '.json?rsp-subtree=full&rsp-subtree-include=stats'
        ret = session.get(mo_query_url)
        data = ret.json()['imdata']

        result = InterfaceStats._process_data(data[0])
        # store the result to be accessed by the retrieve method
        self.result = result
        return result
    
    @staticmethod
    def _process_data(data):
        result = {}
        # List of attributes to be skipped
        skip_attr_list = ['childAction', 'clearTs', 'rn', 'status', 'babble']
        if data:
            if 'children' in data['l1PhysIf']:
                children = data['l1PhysIf']['children']
                for grandchildren in children:
                    for count in grandchildren:
                        if count in ['rmonIfIn', 'rmonIfOut', 'rmonEtherStats']:
                            result[count] = {}
                            result[count]['totalPkts'] = 0
                            counterAttr = grandchildren[count]['attributes']
                            for att in counterAttr:
                                if att in ['broadcastPkts', 'multicastPkts',  'ucastPkts']:
                                    result[count]['totalPkts'] += int(counterAttr[att])
                                    result[count][att] = int(counterAttr[att])
                                elif att in ['octetRate', 'packetRate']:
                                    result[count][att] = float(counterAttr[att])
                                elif att not in skip_attr_list: 
                                    result[count][att] = counterAttr[att]

        return result

    def retrieve(self, countFamily, countName):
        """
        This will return the requested count from stats that were loaded with
        the previous get().  It will return 0 for counts that don't exist or
        None for time stamps that don't exist.

        Note that this method will not access the Switch, it will only work on
        data that was previously loaded with a get().

       :param countFamily: The counter family string.  Examples are
                           'egrTotal', 'ingrDropPkts, etc.
       :param countName: Name of the actual counter.  Examples are
                         'unicastPer', 'unicastRate', etc.  Counter
                         names are unique per counter family.

       :returns:  integer, float or None.  If the counter is not present,
                  it will return 0.
        """
           
        if countName in ['octetRate', 'packetRate']:
            result = 0.0
        else:
            result = 0
        if countFamily in self.result:
            if countName in self.result[countFamily]:
                result = self.result[countFamily][countName]
        return result

