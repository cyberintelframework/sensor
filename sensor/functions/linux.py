"""
linux specific system functions
"""

import logging
import os
import socket
import fcntl
import struct
import subprocess
import pdb
import time

from sensor import locations
from sensor import excepts
from sensor import tools
from sensor import runtime

changeset = "009"

r = runtime.Runtime()

inf_flags = {}
inf_flags[0] = "UP"
inf_flags[1] = "BROADCAST"
inf_flags[2] = "DEBUG"
inf_flags[3] = "LOOPBACK"
inf_flags[4] = "POINTTOPOINT"
inf_flags[5] = "NOTRAILERS"
inf_flags[6] = "RUNNING"
inf_flags[7] = "NOARP"
inf_flags[8] = "PROMISC"
inf_flags[9] = "ALLMULTI"
inf_flags[10] = "MASTER"
inf_flags[11] = "SLAVE"
inf_flags[12] = "MULTICAST"
inf_flags[13] = "PORTSEL"
inf_flags[14] = "AUTOMEDIA"
inf_flags[15] = "DYNAMIC"

def scanPort(IP, port):
   """ Scan A single port\nScanPort(IP, Port)\nReturn a boolean value """
   logging.debugv("functions/linux.py->scanPort(IP, port)", [IP, port])
   scan = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   scan.settimeout(int(4))
   logging.debug("Scanning %s with port %s" % (IP, port))
   if scan.connect_ex((IP, port)) == 0:
      scan.close()
      return True
   else:
      scan.close()
      return False

def system():
    """ Returns the system type """
    logging.debugv("functions/linux.py->system()", [])
    return "Linux"

def checkRoot():
    """ Check if we are running as root """
    logging.debugv("functions/linux.py->checkRoot()", [])
    return (os.getuid() == 0)

def ifList():
    """ Return a list of network interfaces """
    logging.debugv("functions/linux.py->ifList()", [])
    infs = []
    netFile = open('/proc/net/dev', 'r')
    # skip first 2 lines
    for line in netFile.readlines()[2:]:
        # split the string with spaces, and split first with :
        infs.append(line.split()[0].split(":")[0])

    others = vlanList() + ['lo']
    infs = [x for x in infs if x not in others]

    # remove interfaces not starting with eth
    infs = [x for x in infs if x.startswith('eth')]

    return infs

def vlanList():
    """ Return a list of vlan devices """
    logging.debugv("functions/linux.py->vlanList()", [])
    vlanfile = '/proc/net/vlan'

    # if we can't find the file, then kernel module is probably not loaded
    if not os.access(vlanfile, os.R_OK): return []

    return [x for x in os.listdir('/proc/net/vlan') if x != 'config']


def chkIfIp(interface):
    """ Checks for the existance of an IP address on a given interface """
    logging.debugv("functions/linux.py->chkIfIp(interface)", [interface])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        res = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', interface[:15])
        )[20:24])
	return True
    except IOError:
	logging.warning("Interface %s did not have an IP address" % interface)
	return False


def getIp(interface):
    """ Returns the IP address configured on interface """
    logging.debugv("functions/linux.py->getIp(interface)", [interface])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        res = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', interface[:15])
        )[20:24])
	return res
    except IOError:
        raise excepts.InterfaceException, "Interface %s did not have an IP address" % interface

def getIfFlags(interface):
    """ Get the interface flags of a given interface """
    logging.debugv("functions/linux.py->getIfFlags(interface)", [interface])
    # set some symbolic constants
    SIOCGIFFLAGS = 0x8913
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

def chkIf(interface):
    """ Checks for the existance of a given interface """
    logging.debugv("functions/linux.py->chkIf(interface)", [interface])
    # set some symbolic constants
    SIOCGIFFLAGS = 0x8913
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


def getNm(interface):
    """ Returns the netmask configured on interface """
    logging.debugv("functions/linux.py->getNm(interface)", [interface])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x891b,  # SIOCGIFNETMASK
            struct.pack('256s', interface[:15])
        )[20:24])
    except IOError:
        raise excepts.InterfaceException, "interface not found: " + interface

def getMac(interface):
    """ Return hardware address of interface"""
    logging.debugv("functions/linux.py->getMac(interface)", [interface])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #try:
    if True:
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', interface[:15]))
        hwaddr = []
        for char in info[18:24]:
            hdigit = hex(ord(char))[2:]
            if len(hdigit) == 2 : hwaddr.append(hdigit)
            elif len(hdigit) == 1 : hwaddr.append('0' + hdigit)
            else: hwaddr.append('00')
        return ":".join(hwaddr)
    #except IOError:
    #    raise exceptions.InterfaceException, "interface not found: " + interface

def runWrapper(cmd, ignoreError=False):
    """ A wrapper for external commands. if the command returns not 0, output
    is logged with ERROR level. cmd should be an array, first should be command, the rest args """
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


def ifDelIp(interface):
    """ Remove an IP address from a given interface """
    logging.debugv("functions/linux.py->ifDelIp(interface)", [interface])
    logging.info("Removing IP address from %s" % interface)
    cmd = [locations.IFCONFIG, interface, "0.0.0.0", "up"]
    if runWrapper(cmd):
	r.net(interface, 2)
	return True
    else:
	return False
 

def ifUp(interface):
    """ Brings a given interface up """
    logging.debugv("functions/linux.py->ifUp(interface)", [interface])
    logging.info("bring interface %s up " % interface)
    cmd = [locations.IFCONFIG, interface, "up"]
    if runWrapper(cmd):
	r.net(interface, 2)
	return True
    else:
	return False


def ifUpStatic(interface,ip,netmask):
    """ Configures a static IP address for a given interface """
    logging.debugv("functions/linux.py->ifUpStatic(interface, ip, netmask)", [interface, ip, netmask])
    ifUp(interface)
    logging.info("configuring %s with %s/%s" % (interface, ip, netmask))
    cmd = [locations.IFCONFIG, interface, "up", ip, "netmask", netmask]
    if runWrapper(cmd):
	r.net(interface, 3)
	r.networkUp()
    return ip

def ifUpDhcp(interface):
    """ Configures a dynamic IP address for a given interface """
    logging.debugv("functions/linux.py->ifUpDhcp(interface)", [interface])
    ifUp(interface)
    logging.info("configuring %s with dynamic address" % interface)
    cmd = [locations.DHCLIENT, interface, '-pf', locations.PID + 'dhcp-' + interface + '.pid']
    logging.debug(" ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rcode = os.waitpid(p.pid, 0)
    if rcode[1] == 0:
        logging.debug(p.stderr.read())
        try:
            ip = getIp(interface)
            logging.info("received: " + ip)
	    r.net(interface, 3)
	    r.networkUp()
            return ip
        except excepts.InterfaceException:
            logging.warning("Did not receive an IP address on interface %s" % interface)
            logging.warning(p.stderr.read())

    elif rcode[1] == 256:
        logging.warning("Interface %s does not exist" % interface)
        logging.warning(p.stderr.read())
        raise excepts.InterfaceException,"Interface %s does not exist" % interface
    else:
        logging.warning("dhclient returned a unknown exit code")
    raise excepts.NetworkException,"Unable to get IP with DHCP for %s" % interface

def ifDown(interface):
    """ Brings given interface down """
    logging.debugv("functions/linux.py->ifDown(interface)", [interface])
    logging.info("Bringin down %s" % interface)
    try:
        cmd = [locations.IFCONFIG, interface, "0.0.0.0", "down"]
        if runWrapper(cmd):
	    r.net(interface, 1)
    except excepts.RunException, msg:
        raise excepts.InterfaceException, "Interface %s doesn't exists" % interface

    pidfile = locations.PID + 'dhcp-' + interface + '.pid'
    if os.access(pidfile, os.R_OK):
        logging.info("Killing DHCP daemon for %s" % interface)
        pid = open(pidfile, 'r').readline().strip()
        if not pid.isdigit(): raise excepts.RunException, "Invalid pidfile (%s)" % pidfile
        logging.debug("Killed DHCP daemon with PID %s" % pid)
	try:
            os.kill(int(pid), 15)
	except:
	    logging.warn("Killing dhclient: No such process")
        os.unlink(pidfile)

def addGw(ip):
    """ Add gw to routing table """
    logging.debugv("functions/linux.py->addGw(ip)", [ip])
    logging.info("setting default gateway to %s" % (ip) )
    cmd = ["route", "add", "default", "gw", ip]
    runWrapper(cmd)

def delGw(interface):
    """ Remove gateway of device """
    logging.debugv("functions/linux.py->delGw(interface)", [interface])
    logging.info("removing default gateway of device " + interface)
    cmd = ["route", "del", "default", interface]
    runWrapper(cmd)

def getGw(interface):
    """ Return gateway for interface """
    logging.debugv("functions/linux.py->getGw(interface)", [interface])
    f = open('/proc/net/route', 'r')
    for line in f.readlines():
        if line.startswith(interface):
            split = line.split()
            if split[1] == "00000000":
                return tools.hex2ip(split[2])
    return False

def setDNS(prim, sec):
    """ Set DNS servers in /etc/resolv.conf """
    logging.debugv("functions/linux.py->setDNS(prim, sec)", [prim, sec])
    logging.info("Setting DNS to %s and %s" % (prim, sec) )
    resolv = open('/etc/resolv.conf', 'w')
    resolv.write("nameserver %s\nnameserver %s\n" % (prim, sec) )
    resolv.close()

def addVlan(interface, vlanid):
    """ Add a vlan config to an interface. Return vlan device name """
    logging.debugv("functions/linux.py->addVlan(interface, vlanid)", [interface, vlanid])
    logging.info("Creating a vlan configuration on %s with vlanid %s" % (interface, vlanid) )
    cmd = ["vconfig", "add", interface, vlanid]
    runWrapper(cmd)
    return "%s.%s" % (interface, vlanid)

def delVlan(vlandev):
    """ Remove a virtual vlan interface """
    logging.debugv("functions/linux.py->delVlan(vlandev)", [vlandev])
    logging.info("Removing virtual vlan device %s" % vlandev)
    cmd = ["vconfig", "rem", vlandev]
    runWrapper(cmd)
    r.net(vlandev, 0)

def addTap(id):
    """ Create a tap device, ID is a unique id """
    logging.debugv("functions/linux.py->addTap(id)", [id])
    dev = 'tap' + str(id)
    cmd = [locations.OPENVPN, '--mktun', '--dev', dev]
    if runWrapper(cmd):
	r.net(dev, 1)
	if ifUp(dev):
	   return dev
	else:
	    return False
    else:
	return False

def delTap(tap):
    """ Removes given tap device """
    logging.debugv("functions/linux.py->delTap(tap)", [tap])
    cmd = [locations.OPENVPN, '--rmtun', '--dev', tap]
    if runWrapper(cmd):
	r.net(tap, 0)

def tapList():
    """ Return a list of tap devices """
    logging.debugv("functions/linux.py->tapList()", [])
    infs = []
    netFile = open('/proc/net/dev', 'r')
    # skip first 2 lines
    for line in netFile.readlines()[2:]:
        # split the string with spaces, and split first with :
        infs.append(line.split()[0].split(":")[0])
    return [x for x in infs if x.startswith('tap')]


def addBridge(id, devices=[]):
    """ Create a bridge and add devices to it """
    logging.debugv("functions/linux.py->addBridge(id, devices)", [id, devices])
    dev = 'br' + str(id)
    logging.info("Creating bridge %s " % dev)
    cmd = [locations.BRCTL, 'addbr', dev]
    if runWrapper(cmd):
	r.net(dev, 1)
    ifUp(dev)
    for device in devices:
        cmd = [locations.BRCTL, 'addif', dev, device]
        runWrapper(cmd)
    return dev


def mkTunnel(id):
    """ Starts tunnel on given tap ID. OpenVPN will be forked in the background """
    logging.debugv("functions/linux.py->mkTunnel(id)", [id])
    logging.info("Creating tunnel with id %s" % id)
    cmd = [locations.OPENVPN, '--config', locations.VPNTEMPLATE, '--dev', 'tap'+str(id), \
            '--writepid', locations.OPENVPNPID]
    logging.debug(" ".join(cmd))
    pid = os.fork() 
    if pid == 0:
	fd = plock(locations.LOCKFILE)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        buffer = ""
        while p.poll() == None:
            out = p.stdout.read(1)
            if out:
                if out != "\n":
                    buffer += out
                else:
                    logging.debug(buffer[25:])
		    if buffer[25:] == locations.OPENVPN_INIT_RDY:
			punlock(fd, locations.LOCKFILE)
                    buffer = ""
        if p.poll() > 0:
            logging.error("%s died with error code %s, see log for details" % (cmd[0], p.poll()))
        else:
            logging.debug("%s died with error code %s" % (cmd[0], p.poll()))
        import sys
        sys.exit(0)
    else:
	logging.debug("Parent waiting for child...")
	while os.path.exists(locations.LOCKFILE):
	    time.sleep(1)
	logging.debug("Parent continuing...")


def brList():
    """ Return a list of bridge interfaces """
    logging.debugv("functions/linux.py->brList()", [])
    infs = []
    netFile = open('/proc/net/dev', 'r')
    # skip first 2 lines
    for line in netFile.readlines()[2:]:
        # split the string with spaces, and split first with :
        infs.append(line.split()[0].split(":")[0])
    return [x for x in infs if x.startswith('br')]


def delBridge(brdev):
    """ Remove a given bridge interface """
    logging.debugv("functions/linux.py->delBridge(brdev)", [brdev])
    logging.info("removing bridge device %s" % brdev)
    cmd = [locations.BRCTL, 'delbr', brdev]
    runWrapper(cmd)
    r.net(brdev, 0)


def bridgify(inf, infConf, bridgeNumber):
    """ Creates and configures a bridge """
    logging.debugv("functions/linux.py->bridgify(inf, infConf, bridgeNumber)", [inf, infConf, bridgeNumber])
    tapdev = addTap(bridgeNumber)
    brdev = addBridge(bridgeNumber, [tapdev, inf])

    ip = False
    if infConf['type'] == "dhcp":
        ifUp(inf)
        # using linux you need to give the bridge itself an IP
        # using openbsd you need to give the interface in the brdige an IP
        ip = ifUpDhcp(brdev)

    elif infConf['type'] == "static":
        ip = ifUpStatic(brdev, infConf['address'], infConf['netmask'])
        # set gateway
        if infConf['gateway']:
            addGw(infConf['gateway'])

    return (brdev, ip)

def sshStatus():
    """ Returns the status of the SSH daemon """
    logging.debugv("functions/linux.py->sshStatus()", [])
    if os.access(locations.SSHPID, os.F_OK):
	pid = str(open(locations.SSHPID).read())
	pid = pid.rstrip()
	if os.access(locations.PROC + pid + "/", os.F_OK):
            return True
	else:
	    return False
    return False

def openvpnStatus():
    """ Returns the status of the OpenVPN daemon """
    logging.debugv("functions/linux.py->openvpnStatus()", [])
    opid = locations.OPENVPNPID
    if os.access(opid, os.F_OK):
	pid = str(open(opid).read())
	pid = pid.rstrip()
	if os.access(locations.PROC + pid + "/", os.F_OK):
	    return True
	else:
	    return False
    return False

def sshUp():
    """ Starts the SSH daemon """
    logging.debugv("functions/linux.py->sshUp()", [])
    logging.info("starting ssh daemon")
    cmd = [locations.SSHINIT, 'start']
    if runWrapper(cmd):
	r.sshUp()

def sshDown():
    """ Stops the SSH daemon """
    logging.debugv("functions/linux.py->sshDown()", [])
    logging.info("shutting down ssh daemon")
    cmd = [locations.SSHINIT, 'stop']
    if runWrapper(cmd):
	r.sshDown()

def plock(file):
    """ Function to touch a file. Acts as a proxy for locking. """
    logging.debugv("functions/linux.py->plock(file)", [file])
    fd = open(file, "w")
    return fd
    
def punlock(fd, file):
    """ Function to close and delete a file, given a file descriptor and file location.\n
        Acts as a proxy for unlocking.
    """
    logging.debugv("functions/linux.py->punlock(fd, file)", [fd, file])
    fd.close()
    os.unlink(file)

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


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s',
                    filename='flowids.log',
                    )
    mkTunnel(0)
