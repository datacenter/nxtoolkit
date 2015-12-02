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
Simple application that logs on to the Switch and displays stats for all of 
the Interfaces.
"""
from operator import attrgetter
import sys
import nxtoolkit.nxtoolkit as NX


def show_stats_short(args, interfaces):
    """
    show stats short routine

    :param args: command line arguments
    :param interfaces: list of interfaces
    :return: None
    """
    # setup template and display header information
    template = "{0:16} {1:16} {2:16} {3:16} {4:16} {5:16}"
    print(template.format("   INTERFACE  ", "Status", "RX BYTES/Sec", 
                          "TX BYTES/Sec", "RX PKTs/Sec","TX PKTs/Sec"))
    print(template.format("--------------", "------------ ", "------------ ",
                          "---------------", "---------------",
                          "---------------"))
    template = "{0:16} {1:16} {2:16,.2f} {3:16,.2f} {4:16,.2f} {5:16,.2f}"

    for interface in sorted(interfaces, key=attrgetter('if_name')):
        interface.stats.get()
        
        rec = []
        allzero = True
        for (counter_family, count_name) in [('rmonIfIn', 'octetRate'),
                                             ('rmonIfOut', 'octetRate'),
                                             ('rmonIfIn', 'packetRate'),
                                             ('rmonIfOut', 'packetRate')]:
            rec.append(interface.stats.retrieve(counter_family, count_name))
            
            if interface.stats.retrieve(counter_family, count_name) != 0:
                allzero = False
        if (args.nonzero and not allzero) or not args.nonzero:
            print(template.format(interface.name, interface.operSt, *rec))


def show_stats_long(args, interfaces):
    """
    show stats long routine

    :param args: command line arguments
    :param interfaces: list of interfaces
    :return: None
    """
    print('Interface {0}/{1}'.format(interfaces[0].module,interfaces[0].port))
    stats = interfaces[0].stats.get()
    for stats_family in sorted(stats):
        print stats_family
        for counter in sorted(stats[stats_family]):
            print('    {0:>25}: {1}'.format(counter,
                                            stats[stats_family][counter]))


def main():
    """
    Main execution routine

    :return: None
    """
    # Take login credentials from the command line if provided
    # Otherwise, take them from your environment variables file ~/.profile
    description = '''Simple application that logs on to the Switch and 
                displays stats for all of the Interfaces.'''
    creds = NX.Credentials('switch', description)
    creds.add_argument('-i', '--interface',
                       type=str,
                       help='Specify a particular interface module/port e.g. 1/21')
    creds.add_argument('-f', '--full', action="store_true",
                       help='''Show full statistics - only available 
                       if interface is specified''')
    creds.add_argument('-n', '--nonzero', action='store_true',
                       help='''Show only interfaces where the counters are not zero.
                        - only available if interface is NOT specified''')
    args = creds.get()

    # Login to switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)

    # Download all of the interfaces and get their stats
    # and display the stats
    if args.interface:
        interface = args.interface
        if 'eth ' in interface:
            interface = interface[4:]
        #(module, port) = interface.split('/')
        
        #interfaces = NX.Interface.get(session, module, port)
        interfaces = NX.Interface.get(session, 'eth'+interface)
    else:
        interfaces = NX.Interface.get(session)

    if not args.full or not args.interface:
        show_stats_short(args, interfaces)
    else:
        show_stats_long(args, interfaces)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
