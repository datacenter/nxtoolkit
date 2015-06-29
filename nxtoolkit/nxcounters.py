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
"""NX Toolkit module for counter and stats objects
"""

# import json
# import logging
import re


class InterfaceStats(object):
    """
    This class defines interface statistics.  It will provide methods to
    retrieve the stats.  The stats are returned as a dictionary with the
    following structure:

    stats= {<counterFamily>:{<granularity>:{<period>:{<counter>:value}}}}

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
        This method is optimized to minimize the traffic to and from the APIC and is intended to typically be used with the period specified
        so that only the necessary stats are pulled.  Note that it will pull the stats for ALL the interfaces.  This may have latency
        implications.

        :param session: Session to use when accessing the APIC
        :param period: Epoch or period to retrieve - all are retrieved if this is not specified

        :returns:  Dictionary of counters. Format is {<interface_id>{<counterFamily>:
                        {<granularity>:{<period>:{<counter>:value}}}}}
        """
        # request stats
        # for each port
        #   parse port id
        #   process stats
        #   save stats per port id

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

        :param session: Session to use when accessing the APIC
        :param period: Epoch or period to retrieve - all are retrieved if this is not specified

        :returns:  Dictionary of counters. Format is {<counterFamily>:{<granularity>:{<period>:{<counter>:value}}}}
        """
        result = {}
        if not session:
            session = self._parent._session

        if period:
            if (period < 1):
                raise ValueError('Counter epoch value of 0 not yet implemented')

            mo_query_url = '/api/mo/' + self._interfaceDn + \
                           '.json?&rsp-subtree-include=stats&rsp-subtree-class=' \
                           'statsHist&rsp-subtree-filter=eq(statsHist.index,"'+str(period-1)+'")'
        else:
            mo_query_url = '/api/mo/' + self._interfaceDn + '.json?query-target=self&rsp-subtree-include=stats'

        ret = session.get(mo_query_url)
        data = ret.json()['imdata']

        result = InterfaceStats._process_data(data[0])
        # store the result to be accessed by the retrieve method
        self.result = result
        return result

    @staticmethod
    def _process_data(data):
        result = {}
        if data:
            if 'children' in data['l1PhysIf']:
                children = data['l1PhysIf']['children']
                for grandchildren in children:
                    for count in grandchildren:
                        counterAttr = grandchildren[count]['attributes']
                        if re.search('^C', counterAttr['rn']):
                            period = 0
                        else:
                            period = int(counterAttr['index']) + 1

                        if 'EgrTotal' in count:
                            countName = 'egrTotal'
                        elif 'EgrBytes' in count:
                            countName = 'egrBytes'
                        elif 'EgrPkts' in count:
                            countName = 'egrPkts'
                        elif 'EgrDropPkts' in count:
                            countName = 'egrDropPkts'
                        elif 'IngrBytes' in count:
                            countName = 'ingrBytes'
                        elif 'IngrPkts' in count:
                            countName = 'ingrPkts'
                        elif 'IngrTotal' in count:
                            countName = 'ingrTotal'
                        elif 'IngrDropPkts' in count:
                            countName = 'ingrDropPkts'
                        elif 'IngrUnkBytes' in count:
                            countName = 'ingrUnkBytes'
                        elif 'IngrUnkPkts' in count:
                            countName = 'ingrUnkPkts'
                        elif 'IngrStorm' in count:
                            countName = 'ingrStorm'
                        else:
                            countName = count

                        granularity = re.search('(\d+\D+)$', count).group(1)

                        if countName not in result:
                            result[countName] = {}
                        if granularity not in result[countName]:
                            result[countName][granularity] = {}
                        if period not in result[countName][granularity]:
                            result[countName][granularity][period] = {}

                        if countName in ['egrTotal', 'ingrTotal']:
                            for attrName in ['bytesAvg', 'bytesCum', 'bytesMax', 'bytesMin', 'bytesPer',
                                             'pktsAvg', 'pktsCum', 'pktsMax', 'pktsMin', 'pktsPer']:
                                result[countName][granularity][period][attrName] = int(counterAttr[attrName])
                            for attrName in ['bytesRate', 'bytesRateAvg', 'bytesRateMax', 'bytesRateMin',
                                             'pktsRate', 'pktsRateAvg', 'pktsRateMax', 'pktsRateMin']:
                                result[countName][granularity][period][attrName] = float(counterAttr[attrName])

                        elif countName in ['egrBytes', 'ingrBytes']:
                            for attrName in ['floodAvg', 'floodCum', 'floodMax', 'floodMin', 'floodPer',
                                             'multicastAvg', 'multicastCum', 'multicastMax', 'multicastMin', 'multicastPer']:
                                result[countName][granularity][period][attrName] = int(counterAttr[attrName])
                            for attrName in ['floodRate',
                                             'multicastRate', 'multicastRateAvg', 'multicastRateMax', 'multicastRateMin']:
                                result[countName][granularity][period][attrName] = float(counterAttr[attrName])

                        elif countName in ['egrPkts', 'ingrPkts']:
                            for attrName in ['floodAvg', 'floodCum', 'floodMax', 'floodMin', 'floodPer',
                                             'multicastAvg', 'multicastCum', 'multicastMax', 'multicastMin', 'multicastPer',
                                             'unicastAvg', 'unicastCum', 'unicastMax', 'unicastMin', 'unicastPer']:
                                result[countName][granularity][period][attrName] = int(counterAttr[attrName])
                            for attrName in ['floodRate', 'multicastRate', 'unicastRate']:
                                result[countName][granularity][period][attrName] = float(counterAttr[attrName])

                        elif countName in ['egrDropPkts']:
                            for attrName in ['afdWredAvg', 'afdWredCum', 'afdWredMax', 'afdWredMin', 'afdWredPer',
                                             'bufferAvg', 'bufferCum', 'bufferMax', 'bufferMin', 'bufferPer',
                                             'errorAvg', 'errorCum', 'errorMax', 'errorMin', 'errorPer']:
                                result[countName][granularity][period][attrName] = int(counterAttr[attrName])
                            for attrName in ['afdWredRate',
                                             'bufferRate',
                                             'errorRate']:
                                result[countName][granularity][period][attrName] = float(counterAttr[attrName])
                        elif countName in ['ingrDropPkts']:
                            for attrName in ['bufferAvg', 'bufferCum', 'bufferMax', 'bufferMin', 'bufferPer',
                                             'errorAvg', 'errorCum', 'errorMax', 'errorMin', 'errorPer',
                                             'forwardingAvg', 'forwardingCum', 'forwardingMax', 'forwardingMin', 'forwardingPer',
                                             'lbAvg', 'lbCum', 'lbMax', 'lbMin', 'lbPer']:
                                result[countName][granularity][period][attrName] = int(counterAttr[attrName])
                            for attrName in ['bufferRate', 'errorRate', 'forwardingRate', 'lbRate']:
                                result[countName][granularity][period][attrName] = float(counterAttr[attrName])

                        elif countName in ['ingrUnkBytes']:
                            for attrName in ['unclassifiedAvg', 'unclassifiedCum', 'unclassifiedMax', 'unclassifiedMin', 'unclassifiedPer',
                                             'unicastAvg', 'unicastCum', 'unicastMax', 'unicastMin', 'unicastPer']:
                                result[countName][granularity][period][attrName] = int(counterAttr[attrName])
                            for attrName in ['unclassifiedRate', 'unicastRate']:
                                result[countName][granularity][period][attrName] = float(counterAttr[attrName])

                        elif countName in ['ingrUnkPkts']:
                            for attrName in ['unclassifiedAvg', 'unclassifiedCum', 'unclassifiedMax', 'unclassifiedMin', 'unclassifiedPer',
                                             'unicastAvg', 'unicastCum', 'unicastMax', 'unicastMin', 'unicastPer']:
                                result[countName][granularity][period][attrName] = int(counterAttr[attrName])
                            for attrName in ['unclassifiedRate', 'unicastRate']:
                                result[countName][granularity][period][attrName] = float(counterAttr[attrName])
                        elif countName in ['ingrStorm']:
                            for attrName in ['dropBytesAvg', 'dropBytesCum', 'dropBytesMax', 'dropBytesMin', 'dropBytesPer']:
                                result[countName][granularity][period][attrName] = int(counterAttr[attrName])
                            for attrName in ['dropBytesRate', 'dropBytesRateAvg', 'dropBytesRateMax', 'dropBytesRateMin']:
                                result[countName][granularity][period][attrName] = float(counterAttr[attrName])
                        else:
                            print('Found unsupported counter ' + str(countName) + " " + str(granularity) + " " + str(period))
                        result[countName][granularity][period]['intervalEnd'] = counterAttr.get('repIntvEnd')
                        result[countName][granularity][period]['intervalStart'] = counterAttr.get('repIntvStart')

        return result

    def retrieve(self, countFamily, granularity, period, countName):
        """
        This will return the requested count from stats that were loaded with
        the previous get().  It will return 0 for counts that don't exist or
        None for time stamps that don't exist.

        Note that this method will not access the APIC, it will only work on
        data that was previously loaded with a get().

       :param countFamily: The counter family string.  Examples are
                           'egrTotal', 'ingrDropPkts, etc.
       :param granularity: String specifying the counter time granularity.
                           Possible values are: '5min', '15min', '1h', '1d',\
                           '1w', '1mo', '1qtr', and '1year'
       :param period: Integer of time period to get the counter from.
                      Period 0 is the current period. Period 1 is the\
                      previous time granularity.
       :param countName: Name of the actual counter.  Examples are
                         'unicastPer', 'unicastRate', etc.  Counter
                         names are unique per counter family.

       :returns:  integer, float or None.  If the counter is not present,
                  it will return 0.
        """

        # initialize result to a miss
        if countName in ['intervalEnd', 'intervalStart']:
            result = None

        elif countName in ['pktsRate', 'pktsRateAvg', 'pktsRateMax',
                           'pktsRateMin', 'bytesRate', 'bytesRateAvg',
                           'bytesRateMax', 'bytesRateMin', 'floodRate',
                           'unicastRate', 'unclassifiedRate', 'afdWredRate',
                           'bufferRate', 'errorRate', 'forwardingRate',
                           'lbRate', 'multicastRate', 'multicastRateAvg',
                           'multicastRateMax', 'multicastRateMin',
                           'dropBytesRate', 'dropBytesRateAvg',
                           'dropBytesRateMax', 'dropBytesRateMin']:
            result = 0.0
        else:
            result = 0

        # overwrite result if it exists
        if countFamily in self.result:
            if granularity in self.result[countFamily]:
                if period in self.result[countFamily][granularity]:
                    if countName in self.result[countFamily][granularity][period]:

                        # read value
                        result = self.result[countFamily][granularity][period][countName]

        return result
