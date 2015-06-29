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
Simple application that shows all of the processes running on a switch
"""
import sys
import nxtoolkit.nxtoolkit as NX
#import nxtoolkit.nxphysobject as NX_PHYS
from nxtoolkit.nxtoolkitlib import Credentials


def main():
    """
    Main show Process routine
    :return: None
    """
    description = 'Simple application that logs on to the Switch and displays process information for a switch'
    creds = Credentials('switch', description)
    args = creds.get()

    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print '%% Could not login to Switch'
        sys.exit(0)

    switch = NX.Node.get(session)
    processes = NX.Process.get(session, switch)
    tables = NX.Process.get_table(processes, 'Process list for Switch ::')
    for table in tables:
        print table.get_text(tablefmt='fancy_grid') + '\n'


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
