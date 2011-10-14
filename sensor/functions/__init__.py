
import logging
import platform
import urllib2
import os
import time
import configobj

from sensor import config
from sensor import client
from sensor import tools
from sensor import version
from sensor import locations
from sensor import dialog
from sensor import log

# configuration object
c = config.Config()

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
    d = {"client": client.changeset, "config": config.changeset, "dialog": dialog.changeset, "excepts": excepts.changeset, "log": log.changeset, "runtime": runtime.changeset, "tools": tools.changeset, "version": version.changeset}
    return d[file]


def networkUp():
    """ Makes sure there is network connectivity on the main interface """
    logging.debugv("functions/__init__.py->networkUp()", [])
    logging.info("Configuring main interface")

    # refresh config, maybe somebody changed something
    c.refresh()

    # Only use the first interface that is configured
    inf = c.getMainIf()
    if inf == "":
        raise excepts.ConfigException, "Could not find a configured interface"

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
            try:
                ifUpDhcp(inf)
            except excepts.InterfaceException:
                logging.error("Could not setup %s with DHCP" % str(inf))
                raise excepts.InterfaceException, "Could not setup %s with DHCP" % str(inf)

    # set DNS
    (type, prim, sec) = c.getDNS()
    if type == 'static': setDNS(prim, sec)


def sensorUp():
    """ Brings all interfaces up _and_ brings up tunnels """
    logging.debugv("functions/__init__.py->sensorUp()", [])

    try:
        c.validNetConf()
    except excepts.ConfigException, e:
        raise excepts.ConfigException, "Invalid network configuration:\n %s" % str(e)

    # Always bring the main network interface up
    networkUp()

    inf = c.getMainIf()
    if inf == "":
        logging.error("Could not find a configured interface")
        raise excepts.ConfigException, "Could not find a configured interface"

    try:
        addr = getIp(inf)
    except excepts.InterfaceException, msg:
        logging.error(msg)
        return False
    try:
        waitInterfaceLink(inf, addr)
    except excepts.NetworkException, msg:
        logging.error(msg)
        return False

    # refresh config, maybe somebody changed something
    c.refresh()

    # Checking sensor type
    sensortype = c.getSensorType()
    if sensortype == "":
        logging.error("Could not find a sensor type in configuration")
        raise excepts.ConfigException, "Could not find sensor type"

    # Set some general values
    bridgeID = 0
    nm = ""
    bc = ""
    gw = ""

    if c.changed:
        if c.changed == True:
            client.saveConf()

    if sensortype == "normal":
        # Steps to be taken:
        #   Create bridge
        #   Create tap
        #   Add tap + main interface to bridge
        #   Give bridge IP
        #   Remove IP from inf

        # Only use the first interface that is configured
        try:
            inf = c.getMainIf()
        except excepts.InterfaceException:
            logging.error("Could not find an interface configuration.")
            return

        logging.debug("inf: " + inf)
 
        infConf = c.getIf(inf)
        infType = infConf['type']
        ifDelIp(inf)
        (brdev, localIp) = bridgify(inf, infConf, bridgeID)

        if infType == "static":
            nm = infConf['netmask']
            gw = infConf['gateway']
            bc = infConf['broadcast']

        i = 0
        active = 0
        while (i < 20):
            i = i + 1
            chk = scanPort(c.getServer(), 4443)
            logging.debug("Waiting for interface to become active (%s)" % str(i))
            if chk:
                i = 20
                active = 1

        if active == 0:
            logging.error("Could not reach the server on port 4443!")

        client.checkKey(localIp)
        client.register(localIp, c.getSensorID())

    elif sensortype == "vlan":
        try:
            trunk = c.getTrunkIf()
            logging.debug("trunk: " + trunk)
        except excepts.InterfaceException:
            logging.error("Could not find a trunk interface configuration.")
            return False

        ifUp(trunk)
        tapdev = addTap(bridgeID)
        brdev = addBridge(bridgeID, [tapdev, trunk])

        try:
            localIp = getLocalIp()
        except excepts.InterfaceException, msg:
            logging.error(msg)
            localIp = "0.0.0.0"
        except excepts.ConfigException, msg:
            logging.error(msg)
            localIp = "0.0.0.0"

        i = 0
        active = 0
        while (i < 20):
            i = i + 1
            chk = scanPort(c.getServer(), 4443)
            logging.debug("Waiting for interface to become active (%s)" % str(i))
            if chk:
                i = 20
                active = 1

        if active == 0:
            logging.error("Could not reach the server on port 4443!")

        client.checkKey(localIp)
        client.register(localIp, c.getSensorID())

        # Setup loop protection
        setIptables(tap)

    # Check if the sensor certificate is valid, if not, don't start
    if verifyCrt():
        # Check if the sensor key is valid, if not, don't start
        if verifyKey():
            mkTunnel(bridgeID)
        else:
            return False
    else:
        return False

    return True


def sensorDown():
    """ Brings tunnels and interfaces down and restore network afterwards """
    logging.debugv("functions/__init__.py->sensorDown()", [])

    # Get the main interface, return if no interface has been configured
    try:
        inf = c.getMainIf()
    except excepts.InterfaceException:
        logging.error("Could not find an interface configuration.")
        return
    
    # deregister at the server
    try:
        localIp = getLocalIp()
        client.deRegister(localIp)
    except excepts.InterfaceException, msg:
        logging.warning("%s, skipping deregistration" % (str(msg)))
    except excepts.ConfigException, msg:
        logging.warning("%s, skipping deregistration" % (str(msg)))

    # Shut everything down
    allTunnelsDown()
    allInfsDown()

    # Get network working again
    networkUp()


def allTunnelsDown():
    """ Bring all active tunnels down """
    logging.debugv("functions/__init__.py->allTunnelsDown()", [])
    logging.info("Bringing all tunnels down")

    if tunnelStatus():
        logging.debug("WATCHME Kill openvpn daemon with PID " + pid)
        try:
            os.kill(int(pid), 15)
        except OSError:
            logging.warning("WATCHME Openvpn daemon with PID %s already died?" % pid)
        os.unlink(locations.OPENVPNPID)
    else:
        logging.debug("WATCHME Could not find any tunnel PID files")


def allInfsDown():
    """ Bring all the interfaces down """
    logging.debugv("functions/__init__.py->allInfsDown()", [])
    logging.info("Bringing all interfaces down")

    try:
        allTunnelsDown()
    except excepts.NetworkException:
        logging.warning("No network, so can't bring tunnels down")

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
    
    # kill any remaining DHCP servers
    killAllDhcp()


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

def update():
    """ Update status info to the server """
    logging.debugv("functions/__init__.py->update()", [])

    # Get the main interface, return if no interface has been configured
    try:
        inf = c.getMainIf()
    except excepts.InterfaceException:
        logging.error("Could not find an interface configuration.")
        return

    # Get the localIp
    localIp = getLocalIp()

    ssh = int(sshStatus())
    try:
        mac = getMac(inf)
    except excepts.InterfaceException:
        mac = "00:00:00:00:00:00"

    if c.getAutoUpdate() == "Enabled":
        # Do all the APT stuff
        aptUpdate()
        try:
            sensorDown()
        except:
            allTunnelsDown
            allInfsDown()
            networkUp()

        aptInstall()

    ac = client.update(localIp, ssh, mac, getPackageVersion())
    if ac:
        action(ac)  

def action(action):
    """ Functions that exececutes action received by server """
    logging.debugv("functions/__init__.py->action(action)", [action])
    if action == "reboot":
        logging.info("Server request: Reboot")
        reboot()
    elif action =="sshon":
        logging.info("Server request: SSH Enable")
        sshUp()
    elif action == "sshoff":
        logging.info("Server request: SSH Disable")
        sshDown()
    elif action == "start":
        logging.info("Server request: Start/Restart sensor")
        sensorDown()
        sensorUp()
    elif action == "stop":
        logging.info("Server request: Stop sensor")
        sensorDown()
        networkUp()
    elif action == "saveconf":
        logging.info("Server request: Save config")
        client.saveConf()
    elif action == "sensorupgrade":
	# apt-get install surfids-sensor
        logging.info("Server request: Sensor upgrade")
        aptUpdate()
        aptInstall()
    elif action == "aptupgrade":
	# apt-get upgrade
        logging.info("Server request: APT upgrade")
        aptUpdate()
        aptUpgrade()
    elif action == "depupgrade":
	# apt-get install <sensor dependencies>
        logging.info("Server request: Dependency upgrade")
        aptUpdate()
        depUpgrade()
    elif action == "aptcount":
        logging.info("Server request: APT count")
        aptUpdate()
        aptCount()


def reboot():
    """ Tell the system to reboot the system """
    logging.debugv("functions/__init__.py->reboot()", [])
    logging.info("rebooting system")
    os.system(locations.REBOOT)

def writePID():
    """ Write a PID file for the manager """
    logging.debugv("functions/__init__.py->writePID()", [])
    file(locations.MANAGERPID, 'w').write("%s\n" % os.getpid())

def cleanUp():
    """ Cleanup sensor status stuff and dhcp instances """
    logging.debugv("functions/__init__.py->cleanUp()", [])
    if os.access(locations.INTERFACES, os.R_OK):
        os.unlink(locations.INTERFACES)
    if os.access(locations.MANAGERPID, os.R_OK):
        os.unlink(locations.MANAGERPID)
    if os.access(locations.OPENVPNPID, os.R_OK):
        os.unlink(locations.OPENVPNPID)
    if os.access(locations.DUMP, os.R_OK):
        os.unlink(locations.DUMP)

    dhcpExp = r"^dhcp.*$"
    compiled = re.compile(dhcpExp)

    dhcpFiles = [x for x in os.listdir(locations.RUNTIME) if compiled.match(x) != None]
    for pidfile in dhcpFiles:
        killDhcp(pidfile)

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

def ipmiStatus():
    """ Checks for the existance of the ipmitool """
    logging.debugv("functions/__init__.py->ipmiStatus()", [])
    return os.access(locations.IPMITOOL, os.R_OK)

def saveNetConf(config):
    """ Save the given config as the current netconf """
    logging.debugv("saveNetConf(config)", [config])

    if os.access(locations.NETCONF, os.R_OK):
        rev = c.getRev()
        backup = locations.NETCONF + "." + str(rev)
        logging.debug("Creating backup of the netconf file (%s)" % str(backup))
        os.rename(locations.NETCONF, backup)

        try:
            nc = open(locations.NETCONF, "w")
        except:
            logging.error("Could not save netconf")
            return
        nc.write(config)
        nc.close()
        logging.info("Saved network configuration with revision %s" % str(rev))

def printDict(di, format="%-25s %s"):
    logging.debugv("functions/__init__.py->printDict(di, format)", [di, format])
    for (key, val) in di.items():
        print format % (str(key)+':', val)

def printRuntime(run):
    logging.debugv("functions/__init__.py->printRuntime(run)", [])
    printDict(configobj.ConfigObj(locations.INTERFACES))
