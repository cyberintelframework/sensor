#!/usr/bin/env python

import logging

from sensor import log
from sensor import functions
from sensor import runtime

r = runtime.Runtime()

# only update if we have tunnels
if r.sensorStatus():
    functions.update()
else:
    logging.debug("sensor not active, not updating")
