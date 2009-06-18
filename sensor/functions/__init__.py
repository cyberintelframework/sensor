
import logging
import platform
import urllib2
import os
import time
import configobj
import pdb

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
            r.networkUp()
        else:
            try:
                ifUpDhcp(inf)
                r.networkUp()
            except excepts.InterfaceException:
                logging.error("Could not setup %s with DHCP" % str(inf))
                raise excepts.InterfaceException, "Could not setup %s with DHCP" % str(inf)

    # set DNS
    (type, prim, sec) = c.getDNS()
    if type == 'static': setDNS(prim, sec)


def sensorUp():
    """ Brings all interfaces up _and_ brings up tunnels """
    logging.debugv("functions/__init__.py->sensorUp()", [])

    if not r.configStatus():
        logging.error("Could not find a configured interface")
        raise excepts.ConfigException, "Could not find a configured interface"

    # Always bring the main network interface up
    networkUp()

    inf = c.getMainIf()
    if inf == "":
        logging.error("Could not find a configured interface")
        raise excepts.ConfigException, "Could not find a configured interface"

    try:
        waitInterfaceLink(inf)
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
        r.addInf(inf, brdev, infType, bridgeID)

        if infType == "static":
            nm = infConf['netmask']
            gw = infConf['gateway']
            bc = infConf['broadcast']

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

        client.checkKey(localIp)
        client.register(localIp, c.getSensorID())

    # Check if the sensor certificate is valid, if not, don't start
    if verifyCrt():
        # Check if the sensor key is valid, if not, don't start
        if verifyKey():
            mkTunnel(bridgeID)
        else:
            return False
    else:
        return False

    if openvpnStatus():
        # only set registered status if there are one ore more tunnels active
        r.sensorUp()
        r.tunnelUp()

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

    if os.path.exists(locations.OPENVPNPID):
        pid = open(locations.OPENVPNPID, 'r').readline().strip()
        if not pid.isdigit(): raise excepts.RunException, "Invalid pidfile (%s)" % pidfile
        logging.debug("WATCHME Kill openvpn daemon with PID " + pid)
        try:
            os.kill(int(pid), 15)
        except OSError:
            logging.warning("WATCHME Openvpn daemon with PID %s already died?" % pid)
        os.unlink(locations.OPENVPNPID)
    else:
        logging.debug("WATCHME Could not find any tunnel PID files")

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
    killAllDhcp()

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

    # Determine which interface needs to be checked
    sensortype = c.getSensorType()
    if sensortype == "":
        raise excepts.ConfigException, "Could not find a sensor type in the configuration"
    elif sensortype == "normal":
        mainIf = c.getMainIf()
        if r.sensorStatus():
            inf = r.getBridgeDev(mainIf)
        else:
            inf = mainIf    
    elif sensortype == "vlan":
        inf = c.getMainIf()

    # Check if the interface has been configured with an IP
    if r.chkNet(inf) == 3:
        localIP = getIp(inf)
        return localIP
    else:
        raise excepts.InterfaceException, "No local IP address could be found"
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
    try:
        localIp = getLocalIp()
    except excepts.ConfigException, msg:
        logging.warning("Could not sync with the server")
        logging.error(msg)
        return
    except excepts.InterfaceException, msg:
       logging.error(msg)
       return

    ssh = int(sshStatus())
    try:
        mac = getMac(inf)
    except excepts.InterfaceException:
        mac = "00:00:00:00:00:00"

    ac = client.update(localIp, ssh, mac)
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

def initRuntime():
    """ Initializes the runtime status dict """
    logging.debugv("functions/__init__.py->initRuntime()", [])
    mainIf = c.getMainIf()
    if mainIf != "":
        r.configUp()
    else:
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
