#!/usr/bin/env python

import logging

from sensor import log
from sensor import functions
from sensor import excepts

try:
    functions.allTunnelsDown()
except excepts.NetworkException:
    logging.warning("not network connection")
    pass

functions.allInfsDown()
