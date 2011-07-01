#!/usr/bin/env python

import logging
import os

from sensor import altlog
from sensor import functions
from sensor import runtime
from sensor import locations

r = runtime.Runtime()

if not r.tunnelStatus():
    logging.debug("Runtime tunnel status: disabled")
else:
    logging.debug("Runtime tunnel status: enabled")
    if os.path.exists(locations.OPENVPNPID):
        pid = open(locations.OPENVPNPID).read().rstrip()
        if pid.isdigit():
            pid = int(pid)
            if functions.checkPid(pid):
                logging.debug("Tunnel (%s) status OK" % str(pid))
            else:
                # kill manager
                if os.path.exists(locations.MANAGERPID):
                    mpid = open(locations.MANAGERPID).read().rstrip()
                    if mpid.isdigit():
                        functions.sensorDown()
                        mpid = int(mpid)
                        logging.info("Tunnel down, killing manager %s (1)" % str(mpid))
                        os.kill(mpid, 15)
                else:
                    logging.debug("No manager pid file found")
    else:
        # kill manager
        if os.path.exists(locations.MANAGERPID):
            mpid = open(locations.MANAGERPID).read().rstrip().int()
            if mpid.isdigit():
                functions.sensorDown()
                mpid = int(mpid)
                logging.info("Tunnel down, killing manager %s (2)" % str(mpid))
                os.kill(mpid, 15)
        else:
            logging.debug("No manager pid file found")
