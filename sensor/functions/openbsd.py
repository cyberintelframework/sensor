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

# network interfaces to ignore
INF_IGNORE=["lo0", "enc0"]

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
    logging.debugv("functions/linux.py->openvpnStatus()", [])
    opid = locations.OPENVPNPID
    if os.access(opid, os.F_OK):
    pid = str(open(opid).read())
    pid = pid.rstrip()
    return os.access(locations.PROC + pid + "/", os.F_OK)

