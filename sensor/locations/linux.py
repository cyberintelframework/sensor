
import logging
import os
import sys
import os.path


# BINARIES
OPENVPN = "/usr/sbin/openvpn"
BRCTL = "/usr/sbin/brctl"
DHCLIENT = "/sbin/dhclient"
IFCONFIG = "/sbin/ifconfig"
KILLALL = "/usr/bin/killall"
SSHINIT = "/etc/init.d/ssh"
IPMITOOL = "/usr/bin/ipmitool"
DIALOG = "/usr/bin/dialog"
OPENSSL = "/usr/bin/openssl"
DMESG = "/bin/dmesg"
REBOOT = "/sbin/reboot"
INIT = "/sbin/init"
DPKG = "/usr/bin/dpkg"

ALL_BIN = [OPENVPN, BRCTL, DHCLIENT, IFCONFIG, KILLALL, SSHINIT, DIALOG, OPENSSL, DMESG]


# FOLDERS
SYSCONF = "/etc/surfids/"
BACKUP = "/etc/surfids/backup/"
LOG = "/var/log/surfids/"
DATA = "/var/lib/surfids/"
PID = "/var/lib/surfids/"
DOC = "/usr/share/doc/surfids-sensor/"
PROC = "/proc/"

ALL_FOL = [SYSCONF, LOG, DATA, PID]


# FILES
SETTINGS = os.path.join(SYSCONF, "surfids.conf")
NETCONF = os.path.join(SYSCONF, "network.conf")
BNETCONF = os.path.join(SYSCONF, "backup/network.conf")
IPMI = os.path.join(SYSCONF, "ipmi.conf")
CA = os.path.join(SYSCONF, "ca.crt")
KEY = os.path.join(SYSCONF, "surfids.key")
CRT = os.path.join(SYSCONF, "surfids.crt")
LOGFILE = os.path.join(LOG, "surfids.log")
UPDATELOG = os.path.join(LOG, "update.log")
TEMPLOG = os.path.join(LOG, "temp.log")
DUMP = os.path.join(LOG, "dump.log")
VPNTEMPLATE = os.path.join(SYSCONF, "openvpn.conf")
LOCKFILE = os.path.join(DATA, "openvpn.lock")
ABOUT = os.path.join(DOC, "ABOUT")
SSHPID = "/var/run/sshd.pid"
SSHINIT = "/etc/init.d/ssh"
OPENVPNPID = os.path.join(DATA, "tunnel.pid")
MANAGERPID = os.path.join(DATA, "manager.pid")
DEFAULT = "/etc/default/surfids-sensor"

# CONSTANTS
OPENVPN_INIT_RDY = "Initialization Sequence Completed"

ALL_FILES = [CA, VPNTEMPLATE]

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

# check if all files are OK
for file in ALL_FILES:
    if not os.access(file, os.R_OK):
        logging.error("can't find: " + file)
        sys.exit(1)


# check if all python modules are installed
try:
    import configobj
except ImportError:
    logging.error("you don't have python configobj installed")
    sys.exit(1)

