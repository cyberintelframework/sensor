#!/usr/bin/env python

from sensor import log
from sensor import functions
from sensor import excepts

# make sure we have an empty network config
functions.sensorDown()

# remove old stuff, maybe sensor crashed or something
functions.cleanUp()

functions.networkUp()

