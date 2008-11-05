"""
openbsd specific system functions
"""
import os
import subprocess
import logging
import socket
import fcntl
import struct

from sensor import locations
from sensor import tools
from sensor import excepts

# network interfaces to ignore
INF_IGNORE=["lo0", "enc0"]

inf_flags = ["UP", "BROADCAST", "DEBUG", "LOOPBACK", "POINTTOPOINT", "NOTRAILERS", "RUNNING", "NOARP", "PROMISC", "ALLMULTI", "MASTER", "SLAVE", "MULTICAST", "PORTSEL", "AUTOMEDIA", "DYNAMIC"]


def system():
    return "Openbsd"

def checkRoot():
    """ check if we are running as root """
    return (os.getuid() == 0)

def vlanList():
    """ return a list of configured vlan interfaces """
    vlandevs = []
    for line in [x for x in os.popen(locations.IFCONFIG + ' -A').readlines() if not x.startswith("\t")]:
        interface = line.split(":")[0]
        if interface.startswith("vlan"):
            vlandevs.append(interface)
    return vlandevs

def getIp(interface):
    """ returns the IP address configured on interface """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0xc0206921,  # SIOCGIFADDR
        struct.pack('256s', interface[:15])
    )[20:24])


def ifUp(interface):
    """ brings interface up (no ip config)"""
    logging.info("bring interface %s up (no ip config)" % interface)
    cmd = "%s %s up" % (locations.IFCONFIG, interface)
    logging.debug(cmd)
    os.system(cmd)


def addVlan(interface, vlanid):
    """ add a vlan config to an interface. return vlan device name """
    logging.info("creating a vlan configuration on %s with vlanid %s" % (interface, vlanid))
    cmd = "%s vlan%s vlan %s vlandev %s" % (locations.IFCONFIG, vlanid, vlanid, interface)
    logging.debug(cmd)
    os.system(cmd)
    return "vlan" + vlanid

def delVlan(vlandev):
    """ remove a virtual vlan interface """
    logging.info("removing virtual vlan device %s" % vlandev)
    cmd = "%s %s destroy" % (locations.IFCONFIG, vlandev)
    logging.debug(cmd)
    os.system(cmd)


def ifList():
    interfaces = []
    for line in [x for x in os.popen(locations.IFCONFIG + ' -A').readlines() if not x.startswith("\t")]:
        interface = line.split(":")[0]
        ignore = INF_IGNORE + vlanList() + brList() + tapList()
        if interface not in ignore:
            interfaces.append(interface)

    return interfaces

def ifDown(interface):
    """ brings given interface down"""
    logging.info("bringin down %s" % interface)
    cmd = "%s %s down" % (locations.IFCONFIG, interface)
    logging.debug(cmd)
    os.system(cmd)

    logging.info("killing dhcp daemon for %s (if running)" % interface)
    cmd = "%s -f \"dhclient %s\"" % (locations.PKILL, interface)
    logging.debug(cmd)
    os.system(cmd)


def ifUpDhcp(interface):
    """ configures a dynamic IP address for given interface """
    logging.info("configuring %s with dynamic address" % interface)
    logging.debug("%s %s" % (locations.DHCLIENT, interface))
    exitcode = os.spawnv(os.P_WAIT, locations.DHCLIENT, [locations.DHCLIENT, interface])
    if exitcode:
        logging.warning("error running dhclient for %s, returned %s" % (interface, exitcode) )
        return False
    else:
        ip = getIp(interface)
        logging.info("%s received %s trough DHCP" % (interface, ip) )
        return ip



def setDNS(prim, sec):
    """ set DNS servers in /etc/resolv.conf """
    logging.info("setting DNS to %s and %s" % (prim, sec) )
    resolv = open('/etc/resolv.conf', 'w')
    resolv.write("%s\n%s\n" % (prim, sec) )
    resolv.close()


def addBridge(id, devices=[]):
    """ create a bridge and add devices to it """
    logging.info("creating bridge with id %s" % id)
    cmd = '%s bridge%s create' % (locations.IFCONFIG, str(id))
    logging.debug(cmd)
    os.system(cmd)
    for device in devices:
        cmd = '%s bridge%s add %s' % (locations.BRCONFIG, str(id), device)
        logging.debug(cmd)
        os.system(cmd)
    return 'bridge'+str(id)

def delBridge(brdev):
    """ removed bridge """
    logging.info("removing bridge device %s" % brdev)
    cmd = '%s %s destroy' % (locations.IFCONFIG, brdev)
    logging.debug(cmd)
    os.system(cmd)


def addTap(id):
    """ create a tap device, ID is a unique id """
    cmd = '%s tun%s create' % (locations.IFCONFIG, str(id))
    logging.debug(cmd)
    os.system(cmd)

    # need to up link0, otherwise brconfig error, don't know why
    cmd = '%s tun%s link0 up' % (locations.IFCONFIG, str(id))
    logging.debug(cmd)
    os.system(cmd)
    return 'tun' + str(id)

def delTap(tap):
    """ removes given tap device """
    cmd = '%s %s destroy' % (locations.IFCONFIG, tap)
    logging.debug(cmd)
    os.system(cmd)

def tapList():
    """ return a list of tap devices """
    interfaces = []
    for line in [x for x in os.popen(locations.IFCONFIG + ' -A').readlines() if not x.startswith("\t")]:
        interface = line.split(":")[0]
        if interface.startswith('tun'): interfaces.append(interface)
    return interfaces


def brList():
    """return a list of bridge interfaces"""
    interfaces = []
    for line in [x for x in os.popen(locations.IFCONFIG + ' -A').readlines() if not x.startswith("\t")]:
        interface = line.split(":")[0]
        if interface.startswith('bridge'): interfaces.append(interface)
    return interfaces

def detach(cmd):
    """ detach a cmd and log output """
    logging.debug(" ".join(cmd))
    pid = os.fork()
    if pid == 0:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        buffer = ""
        while p.poll() == None:
            out = p.stdout.read(1)
            if out:
                if out != "\n":
                    buffer += out
                else:
                    logging.debug(buffer)
                    buffer = ""
        if p.poll() > 0:
            logging.error("%s died with error code %s" % (cmd[0], p.poll()))
        else:
            logging.debug("%s died with error code %s" % (cmd[0], p.poll()))
        import sys
        sys.exit(0)



def mkTunnel(id):
    """ starts tunnel on given tap ID """
    logging.info("creating tunnel with id %s" % id)
    cmd = [locations.OPENVPN, '--config', locations.VPNTEMPLATE, '--dev', 'tun'+str(id)]
    detach(cmd)




def bridgify(inf, infConf, bridgeNumber):
    """ makes and configures a bridge """
    tapdev = addTap(bridgeNumber)
    brdev = addBridge(bridgeNumber, [tapdev, inf])
    ifUp(brdev)

    ip = None
    if infConf['type'] == "dhcp":
        ifUp(inf)
        # with linux you need to give the bridge itself an IP
        # with openbsd you need to give the interface in the brdige an IP
        ip = ifUpDhcp(inf)

    elif infConf['type'] == "static":
        ip = ifUpStatic(inf, infConf['address'], infConf['netmask'])
        # set gateway
        if infConf['gateway']:
            addGw(infConf['gateway'])
    return (inf, ip)

def openvpnStatus():
    """ Returns the status of the OpenVPN daemon """
    #TODO: check if process is really running
    logging.debugv("functions/linux.py->openvpnStatus()", [])
    opid = locations.OPENVPNPID
    if os.access(opid, os.F_OK):
        pid = str(open(opid).read())
        pid = pid.rstrip()
        return os.access(locations.PROC + pid + "/", os.F_OK)


def chkIf(interface):
    """ Checks for the existance of a given interface """
    logging.debugv("functions/linux.py->chkIf(interface)", [interface])
    # set some symbolic constants
    SIOCGIFFLAGS = 0xc0206911
    null256 = '\0'*256
    active_flags = ""

    # create a socket so we have a handle to query
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # call ioctl() to get the flags for the given interface
        result = fcntl.ioctl(s.fileno(), SIOCGIFFLAGS, interface + null256)
        return True
    except IOError:
        logging.warning("Interface %s was not found" % interface)
        return False


def getIfFlags(interface):
    """ Get the interface flags of a given interface """
    logging.debugv("functions/linux.py->getIfFlags(interface)", [interface])
    # set some symbolic constants
    SIOCGIFFLAGS = 0xc0206911
    null256 = '\0'*256
    active_flags = ""

    # create a socket so we have a handle to query
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # call ioctl() to get the flags for the given interface
        result = fcntl.ioctl(s.fileno(), SIOCGIFFLAGS, interface + null256)

        # extract the interface's flags from the return value
        flags, = struct.unpack('H', result[16:18])

        binflags = tools.dec2bin(flags)
        binflags = binflags[::-1]
        i = 0
        for b in binflags:
            if int(b) == 1:
                active_flags += " " + str(inf_flags[i])
            i += 1
        active_flags = active_flags.lstrip()
        return active_flags
    except IOError:
        raise excepts.InterfaceException, "Interface %s was not found" % interface




def chkIfIp(interface):
    """ Checks for the existance of an IP address on a given interface """
    logging.debugv("functions/linux.py->chkIfIp(interface)", [interface])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        res = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0xc0206921,  # SIOCGIFADDR
            struct.pack('256s', interface[:15])
        )[20:24])
        return True
    except IOError:
        logging.warning("Interface %s did not have an IP address" % interface)
        return False


def sshStatus():
    """ Returns the status of the SSH daemon """
    #TODO: check if process is really running
    logging.debugv("functions/linux.py->sshStatus()", [])
    if os.access(locations.SSHPID, os.F_OK):
        pid = str(open(locations.SSHPID).read())
        pid = pid.rstrip()
        return True

def killAllDhcp():
    """ Kills all DHCP servers """
    logging.warning("killAllDhcp() is not implemented yet")
    return True

def waitInterfaceLink(interface):
    from time import sleep as time_sleep

    gw = getGw(interface)
    cmd= ['ping',  '-I', interface,  '-c 1', gw]
    timeout = 60
    done = 0

    while (timeout > 0 and not done):
        try:
            runWrapper(cmd)
            done = 1
        except excepts.RunException, msg:
            time_sleep(1)
            timeout -= 1

    if (timeout == 0):
        msg = "Interface %s did not get a link in 60 seconds" % (interface)
        raise excepts.NetworkException, msg

    logging.debug("network device up after %d seconds" % (60-timeout))


def getGw(interface):
    logging.warning("killAllDhcp() is not implemented yet")
    return "0.0.0.0"


def runWrapper(cmd, ignoreError=False):
    """ A wrapper for external commands. if the command returns not 0, output
        is logged with ERROR level. cmd should be an array, first should be command, the rest args 
    """
    logging.debug(" ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rcode = os.waitpid(p.pid, 0)[1]
    if rcode == 0 or ignoreError == True:
        log = p.stderr.read().strip()
        if log: logging.debug(log)
        return True
    else:
        msg = "%s returned error code %s" % (cmd[0], rcode)
        logging.warning(msg)
        log = p.stderr.read().strip()
        if log: logging.warning(log)
        raise excepts.RunException, msg

