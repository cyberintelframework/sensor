#!/usr/bin/env python

import logging

from sensor import log
from sensor import functions
from sensor import config

c = config.Config()
mainInf = c.getMainIf()
if not mainInf == "":
    # only update if we have tunnels
    if functions.networkStatus(mainInf):
        functions.aptUpdate()
        functions.aptInstall()
    else:
        logging.debug("Sensor not active, not checking APT")
else:
    logging.error("Could not determine mainInf while running sensor-apt-update.py")
