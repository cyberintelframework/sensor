
import pdb
import logging
import logging.handlers
import sys
import signal

from sensor import locations
from sensor import config

changeset = "001"

c = config.Config()

# Defining the debugv logging function
logging.addLevelName(9, "DEBUGV")
logging.DEBUGV = 9
logging.addLevelName(8, "DEBUGVV")
logging.DEBUGVV = 8
logging.addLevelName(7, "TRACE")
logging.TRACE = 7

def who_called_me(n=0):
    import sys
    f = sys._getframe(n)
    c = f.f_code

    filename = c.co_filename
    filename = filename.replace("/var/lib/python-support/python2.5/sensor/", "")

    callargs = c.co_argcount
    varnames = c.co_varnames[:callargs]
    return filename + "->" + str(c.co_name) + str(varnames)

def Logger_debugv(msg, args):
    """ Self made function to handle debugv messages """
    loglevel = c.getLogLevel()
    if loglevel == "debugv":
	logging.log(logging.DEBUGV, msg)
    elif loglevel == "debugvv":
	msg = msg + " % " + str(args)
	logging.log(logging.DEBUGVV, msg)
    elif loglevel == "trace":
	msg = '"' + who_called_me(3) + '" -> "' + msg + '"'
	msg = msg.replace("\'", "")
	msg = msg.replace(",)", ")")
	logging.log(logging.TRACE, msg)

logging.debugv = Logger_debugv

class LogErr:
    "this class is used to redirect stderr to"
    def write(self, data):
        formatted = data.strip()
        if formatted: logging.error( formatted )

def inthandler(signum, frame):
    """ Signal handler for ctrl-c """
    import os
    if os.path.exists(locations.OPENVPNPID):
        os.unlink(locations.OPENVPNPID)
    os.system('clear')
    logging.warning("SURFids menu stopped (received ctrl-c)")
    sys.exit(1)


def setLog():
    loglevel = c.getLogLevel()

    level = logging.INFO
    format='%(asctime)s %(message)s'
    logfile = locations.LOGFILE

    if loglevel in "debug":
        level = logging.DEBUG
        format='%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(message)s'
    elif loglevel in "debugv":
        level = logging.DEBUGV
        format='%(asctime)s %(levelname)s %(message)s'
    elif loglevel in "debugvv":
        level = logging.DEBUGVV
        format='%(asctime)s %(levelname)s %(message)s'
    elif loglevel == "trace":
	level = logging.TRACE
	format='%(levelname)s %(message)s'
    elif loglevel == "warning":
        level = logging.WARNING

    logging.basicConfig(level=level, format=format, filename=logfile)


setLog()

# catch ctrl-c
signal.signal(signal.SIGINT, inthandler)

# redirect stderr/stdout to logfile
logIO = LogErr()
#sys.stdout = logIO
sys.stderr = logIO



