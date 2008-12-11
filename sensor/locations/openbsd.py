
import logging
import os
import sys
import os.path


# BINARIES
OPENVPN = "/usr/local/sbin/openvpn"
BRCONFIG = "/sbin/brconfig"
DHCLIENT="/sbin/dhclient"
IFCONFIG="/sbin/ifconfig"
PKILL="/usr/bin/pkill"
# FIXME
OPENSSL="/usr/bin/openssl"

ALL_BIN = [OPENVPN, BRCONFIG, DHCLIENT, IFCONFIG, PKILL, OPENSSL]


# FOLDERS
SYSCONF = "/etc/surfids/"
LOG = "/var/log/surfids/"
DATA = "/var/db/surfids/"
RUNTIME = "/var/db/surfids/"
DOC = "/tmp/"

ALL_FOL = [SYSCONF, LOG, DATA, RUNTIME, DOC]


# FILES
SETTINGS = os.path.join(SYSCONF, "surfids.conf")
NETCONF = os.path.join(SYSCONF, "network.conf")
NETCONF = os.path.join(IPMI, "ipmi.conf")
CA = os.path.join(SYSCONF, "ca.crt")
KEY = os.path.join(SYSCONF, "surfids.key")
CRT = os.path.join(SYSCONF, "surfids.crt")
LOGFILE = os.path.join(LOG, "surfids.log")
VPNTEMPLATE = os.path.join(DATA, "openvpn.conf")
INTERFACES = os.path.join(RUNTIME, "connections")
ABOUT = os.path.join(DOC, "ABOUT")
OPENVPNPID = os.path.join(DATA, "tunnel.pid")
SSHPID = "/var/run/sshd.pid"


# check if all binaries are OK
for app in ALL_BIN:
    if not os.access(app, os.X_OK):
        logging.error("can't find: " + app)
        sys.exit(1)


# check if all folders are OK
for fol in ALL_FOL:
    if not os.access(fol, os.W_OK):
        logging.error("cant write to: " + fol)
        sys.exit(1)


# check if all python modules are installed
try:
    import configobj
except ImportError:
    logging.error("you don't have python configobj installed")
    sys.exit(1)

