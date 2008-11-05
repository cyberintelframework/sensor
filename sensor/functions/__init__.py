
import logging
import platform
import urllib2
import os
import time
import configobj

from sensor import config
from sensor import runtime
from sensor import client
from sensor import tools
from sensor import version
from sensor import locations
from sensor import dialog
from sensor import log

# configuration object
c = config.Config()

# runtime object, stores active interfaces
r = runtime.Runtime()

system = platform.system()

# import system specific functions
if system == 'Linux':
    from linux import *
elif system == 'OpenBSD':
    from openbsd import *
else:
    logging.error("unsupported system: " + system)
    import sys
    sys.exit(1)

def getVer(file):
    """ Get the version (changelog) of the given file """
    logging.debugv("functions/__init__.py->getVer(file)", [file])
    if file == "client":
	return client.changeset
    elif file == "config":
	return config.changeset
    elif file == "dialog":
	return dialog.changeset
    elif file == "excepts":
	return excepts.changeset
    elif file == "log":
	return log.changeset
    elif file == "runtime":
	return runtime.changeset
    elif file == "tools":
	return tools.changeset
    elif file == "version":
	return version.changeset


def networkUp():
    """ Makes sure there is network connectivity on the main interface """
    logging.debugv("functions/__init__.py->networkUp()", [])
    logging.info("Configuring main interface")

    # refresh config, maybe somebody changed something
    c.refresh()

    # Only use the first interface that is configured
    try:
	inf = getFirstIf(["dhcp", "static"])
    except excepts.InterfaceException:
	logging.error("Could not find an interface configuration.")
	return

    logging.debug("First interface: %s" % inf)
    infConf = c.getIf(inf)
    infType = infConf['type']
    logging.debug("Interface config type: %s" % infType)

    if infType in ["dhcp", "static"]:
        if infType == "static":
	    nm = infConf['netmask']
	    ip = infConf['address']
	    gw = infConf['gateway']
	    ifUpStatic(inf, ip, nm)
	    if getGw(inf):
		delGw(inf)
            addGw(gw)
	else:
	    ifUpDhcp(inf)

    # set DNS
    (type, prim, sec) = c.getDNS()
    if type == 'static': setDNS(prim, sec)
    r.networkUp()


def sensorUp():
    """ Brings all interfaces up _and_ brings up tunnels """
    logging.debugv("functions/__init__.py->sensorUp()", [])

#    pdb.set_trace()
    if not r.configStatus():
	logging.error("Could not find a configured interface")
	return False

    # Always bring the main network interface up
    networkUp()

    waitInterfaceLink('eth0')

    # refresh config, maybe somebody changed something
    c.refresh()

    # Checking sensor type
    sensortype = c.config['sensortype']

    # Set some general values
    bridgeID = 0
    nm = ""
    bc = ""
    gw = ""

    if sensortype == "normal":
	# Steps to be taken:
	#   Create bridge
	#   Create tap
	#   Add tap + main interface to bridge
	#   Give bridge IP
	#   Remove IP from inf

	# Only use the first interface that is configured
	try:
	    inf = getFirstIf(["dhcp", "static"])
	except excepts.InterfaceException:
            logging.error("Could not find an interface configuration.")
            return

	logging.debug("inf: " + inf)
 
	infConf = c.getIf(inf)
	infType = infConf['type']
	(brdev, ip) = bridgify(inf, infConf, bridgeID)
        r.addInf(inf, brdev, infType, bridgeID)
	ifDelIp(inf)

	if infType == "static":
	    nm = infConf['netmask']
	    gw = infConf['gateway']
	    bc = infConf['broadcast']

	client.checkKey(ip)
	client.register(ip, c.get('sensorid'))

    elif sensortype == "vlan":
	# Only use the first interface that is configured
	try:
	    trunk = getFirstIf(["trunk"])
	    logging.debug("trunk: " + trunk)
	except excepts.InterfaceException:
            logging.error("Could not find a trunk interface configuration.")
            return False

	ifUp(trunk)
        tapdev = addTap(bridgeID)
        brdev = addBridge(bridgeID, [tapdev, trunk])

	(chk, ip) = getLocalIp()

	client.checkKey(ip)
	client.register(ip, c.get('sensorid'))

    mkTunnel(bridgeID)

#    pdb.set_trace()
    if openvpnStatus():
        # only set registered status if there are one ore more tunnels active
        r.sensorUp()
	r.tunnelUp()

    return True


def sensorDown():
    """ Brings tunnels and interfaces down and restore network afterwards """
    logging.debugv("functions/__init__.py->sensorDown()", [])
    # deregister at the server
    (chk, localip) = getLocalIp()
    if chk:
        client.deRegister(localip)
    else:
	logging.warning("Could not find localip, skipping deregistration")

    # Shut everything down
    allTunnelsDown()
    allInfsDown()

    # Get network working again
    networkUp()


def allTunnelsDown():
    """ Bring all active tunnels down """
    logging.debugv("functions/__init__.py->allTunnelsDown()", [])
    logging.info("Bringing all tunnels down")

    if os.path.exists(locations.OPENVPNPID):
        pid = open(locations.OPENVPNPID, 'r').readline().strip()
        if not pid.isdigit(): raise excepts.RunException, "Invalid pidfile (%s)" % pidfile
        logging.debug("Kill openvpn daemon with PID " + pid)
        try:
            os.kill(int(pid), 15)
        except OSError:
            logging.warning("Openvpn daemon with PID %s already died?" % pid)
        os.unlink(locations.OPENVPNPID)

    # set runtime status to tunnels down
    r.sensorDown()


def allInfsDown():
    """ Bring all the interfaces down """
    logging.debugv("functions/__init__.py->allInfsDown()", [])
    logging.info("Bringing all interfaces down")

    # try to bring tunnels down if they are up
    if r.sensorStatus():
        try:
            allTunnelsDown()
        except excepts.NetworkException:
            logging.warning("No network, so can't bring tunnels down")
            r.sensorDown()

    for inf, infProps in r.listInf():
        if infProps['type'] == 'vlan':
            for vlan, vlanProps in infProps['vlans'].items():
                bridge = vlanProps['bridgedev']
                try:
                    ifDown(bridge)
                    delBridge(bridge)
                    delVlan(vlan)
                    r.delVlan(inf, vlan)
                except excepts.InterfaceException:
                    logging.error("can't bring down %s, doesn't exists" % inf)
        try:
            ifDown(inf)
            r.delInf(inf)
        except excepts.InterfaceException:
            logging.error("can't bring down %s, doesn't exists" % inf)

    # and now we will destroy everything that is left

    # down all interfaces
    for inf in ifList():
        ifDown(inf)

    # remove vlans
    for vlan in vlanList():
        delVlan(vlan)

    # remove all bridges
    for bridge in brList():
        ifDown(bridge)
        delBridge(bridge)

    # remove all tap interfaces
    for tap in tapList():
        delTap(tap)
    
    # set dns to bogus
    #setDNS("","")

    # kill any remaining DHCP servers
    cmd=[locations.KILLALL, '-q', locations.DHCLIENT]
    runWrapper(cmd, ignoreError=True)

    # set runtime status to network down
    r.networkDown()


def getFirstIf(types):
    """ Retrieve the first interface with type in given dict of types\n
        Usage example: inf = getFirstIf(["dhcp", "static"])
    """
    logging.debugv("functions/__init__.py->getFirstIf(types)", [types])
    infs = [i for i in ifList() if c.getIf(i)['type'] in types]
    if infs: return infs[0]
    else:
	raise excepts.InterfaceException, "No interface found with type in %s" % str(types)
	return

def getLocalIp():
    """ Get the localy configured IP address """
    logging.debugv("functions/__init__.py->getLocalIp()", [])
    for (dev, status) in r.listNet():
	if status == 3:
	    return True, getIp(dev)
    return False, ""

def update():
    """ Update status info to the server """
    logging.debugv("functions/__init__.py->update()", [])
    logging.info("updating sensor @ ids server")
    rev = version.getRev()
    ssh = int(sshStatus())
    for (inf, infprops) in r.listInf():
        infConf = c.getIf(inf)
        infType = infConf['type']
        if infType in ["dhcp", "static"]:
            ip = getIp(infprops['bridgedev'])
            mac = getMac(inf)
            client.checkKey(ip)
            action(client.update(ip, 0, ssh, rev, mac ))

        elif infType == "vlan":
            for (vlan, vlanprops) in infprops['vlans'].items():
                ip = getIp(vlanprops['bridgedev'])
                mac = getMac(inf)
                vlanid = vlanprops['vlanid']
                client.checkKey(ip)
                action(client.update(ip, vlanid, 0, rev, mac ))


def action(action):
    """ Functions that exececutes action received by server """
    logging.debugv("functions/__init__.py->action(action)", [action])
    if action == "reboot":
        reboot()
    elif action =="sshon":
        sshUp()
    elif action == "sshoff":
        sshDown()
    elif action == "start":
        allDown()
        allUp()
    elif action == "stop":
        allTunnelsDown()


def reboot():
    """ Tell the system to reboot the system """
    logging.debugv("functions/__init__.py->reboot()", [])
    logging.info("rebooting system")
    os.system('reboot')

def cleanUp():
    """ Remove runtime file, used @ startup """
    logging.debugv("functions/__init__.py->cleanUp()", [])
    os.unlink(locations.INTERFACES)

def checkKey():
    """ Checks if sensor key and crt are present """
    logging.debugv("functions/__init__.py->checkKey()", [])
    return os.access(locations.KEY, os.R_OK) and os.access(locations.CRT, os.R_OK)

def delKey():
    """ Removes sensor key and crt file """
    logging.debugv("functions/__init__.py->delKey()", [])
    logging.info("removing key and certificate file")
    os.unlink(locations.KEY)
    os.unlink(locations.CRT)

def initRuntime():
    """ Initializes the runtime status dict """
    logging.debugv("functions/__init__.py->initRuntime()", [])
    try:
	getFirstIf(["dhcp", "static"])
	r.configUp()
    except excepts.InterfaceException:
	logging.warning("Could not find a configured interface")
	r.configDown()

    if openvpnStatus():
	r.sensorUp()
	r.tunnelUp()
    else:
	r.sensorDown()
	r.tunnelDown()
	
    infs = ifList()
    for inf in infs:
	if chkIf(inf):
	    r.net(inf, 1)
            flags = getIfFlags(inf).split()
            if flags[0] == "UP":
                r.net(inf, 2)
                if chkIfIp(inf):
                    r.net(inf, 3)
		    r.networkUp()

def printDict(di, format="%-25s %s"):
    logging.debugv("functions/__init__.py->printDict(di, format)", [di, format])
    for (key, val) in di.items():
        print format % (str(key)+':', val)

def printRuntime(run):
    logging.debugv("functions/__init__.py->printRuntime(run)", [])
    printDict(configobj.ConfigObj(locations.INTERFACES))
