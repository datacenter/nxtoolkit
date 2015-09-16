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
Simple application that logs on to the Switch and copy the
running config to startup config
"""

import sys
import nxtoolkit.nxtoolkit as NX
import time


def main():
    """
    Main execution routine

    :return: None
    """
    # Take login credentials from the command line if provided
    # Otherwise, take them from your environment variables file ~/.profile
    description = 'copy running config to startup config'
    creds = NX.Credentials('switch', description)
    args = creds.get()

    # Login to Switch
    session = NX.Session(args.url, args.login, args.password)
    resp = session.login()
    if not resp.ok:
        print('%% Could not login to Switch')
        sys.exit(0)

    copy = NX.Copy()
    run_to_start = NX.RunningToStartUp()
    copy.add(run_to_start)

    resp = session.push_to_switch(copy.get_url(), copy.get_json())
    if not resp.ok:
        print resp.text
        print('%% Could not push to the switch')
        exit(0)

    # Get the status of copy
    time.sleep(5)  # Waiting 5 sec. till the copy process is complete
    copy = NX.Copy.get(session)
    print "Copy status: ", copy.run_to_start.status

    # Uncomment below lines to delete the copy task
    '''
    resp = session.delete(run_to_start.get_url())
    if not resp.ok:
        print resp.text
        print('%% Could not delete from the switch')
        exit(0)
    '''


if __name__ == '__main__':
    main()
