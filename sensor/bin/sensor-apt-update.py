#!/usr/bin/env python

import logging

from sensor import log
from sensor import functions
from sensor import runtime

r = runtime.Runtime()

# only update if we have tunnels
if r.networkStatus():
    functions.aptUpdate()
    functions.aptInstall()
else:
    logging.debug("Sensor not active, not checking APT")
