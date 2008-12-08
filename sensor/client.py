
import logging
import urllib
import urllib2
import os
import platform

from sensor import config
from sensor import runtime
from sensor import locations
from sensor import excepts

# Setting version variables
version = "2.10.00"
changeset = "001"

# configuration object
c = config.Config()

# runtime object, stores active interfaces
r = runtime.Runtime()

def checkNet():
    """ check if we have network, of not raise network exception """
    logging.debugv("client.py->checkNet()", [])
    if not r.networkStatus():
        raise excepts.NetworkException("no network connection")


#def saveConf(method, mainConf, trunkConf):
#def saveConf(method, mainDev, mainConf, trunkDev, trunkConf):
def saveConf():
    """ Send the configuration to the server

        mainConf = 	"dhcp" | "ip|tap_ip|nm|bc|gw"
        vlanDesc = 	<description of vlan. May not contain comma's.>
        vlanConf = 	VLAN_ID , MAINCONF , VLANDESC
        trunkConf = 	VLANCONF ! VLANCONF ! VLANCONF ! ...

        request:        	save_config.php

	    required arguments:
                strip_html_escape_interfacedev=<eth-device>
				strip_html_escape_trunkdev=<eth-device>
				strip_html_escape_keyname=<sensorN>
				strip_html_escape_method=(vlan|normal)
				strip_html_escape_interface=<mainConf>
				strip_html_escape_trunk=<trunkConf>
				int_rev=<revision number>

	    optional arguments:
                ip_dns1=<ip>
				ip_dns2=<ip>
				strip_html_escape_version=<string identifying sensor>
    """
    logging.debugv("client.py->saveConf()", [])

    method = c.netconf['sensortype']

    mainIf = c.getMainIf()
    trunkIf = c.getTrunkIf()

    mainInfConf = c.getIf(mainIf)
    if mainInfConf["type"] == "static":
        mainConf = mainInfConf["address"] + "|" + mainInfConf["tunnel"] + "|" + mainInfConf["netmask"] + "|"
        mainConf += mainInfConf["broadcast"] + "|" + mainInfConf["gateway"]
    elif mainInfConf["type"] == "dhcp":
        mainConf = "dhcp"

    trunkConf = ""
    if method == "vlan":
        for (vlan, vlanConf) in c.getVlans().items():
           desc = vlanConf["description"]
           tunnel = vlanConf["tunnel"]
           vlanid = vlanConf["vlanid"]
           vlanType = vlanConf["type"]
           logging.debug(vlanid + " - " + vlanType)
           if vlanType == "static":
               nm = vlanConf["netmask"]
               gw = vlanConf["gateway"]
               bc = vlanConf["broadcast"]
               vlanIf = "|" + tunnel + "|" + nm + "|" + nm + "|" + bc + "|" + gw
           else:
               vlanIf = "dhcp"
           trunkConf += vlanid + "," + vlanIf + "," + desc + "!"
        trunkConf = trunkConf.rstrip("!")

    sensor = c.getSensorID()
    (dnstype, dns1, dns2) = c.getDNS()
    (os, version, nr) = platform.dist()
    osv = os + "-" + version + "-" + nr
    req = "save_config.php"
    args = urllib.urlencode((
        ('strip_html_escape_method', method),
        ('strip_html_escape_interface', str(mainConf)),
        ('strip_html_escape_interfacedev', str(mainIf)),
        ('strip_html_escape_keyname', sensor),
        ('strip_html_escape_trunk', str(trunkConf)),
        ('strip_html_escape_trunkdev', str(trunkIf)),
    	('strip_html_escape_version', str(osv)),
    	('ip_dns1', str(dns1)),
	    ('ip_dns2', str(dns2)),
    	('int_rev', str(1)))
    )

    logging.debug(str(args))
    try:
        x = makeRequest(req, args)
        for line in x.readlines(): logging.debug(line[:-1])
        c.changed = False
    except excepts.NetworkException:
        c.changed = True


def register(localip, keyname):
    """ Register sensor @ SURFids server

        localip: ip of interface
        method: method used for obtaining IP (dhcp, static, vland or vlans)
        vlanid: id of vlan, 0 of no vlan
        netmask: netmask of interface, only needed when method = static/vlans
        gateway: netmask of interface, only needed when method = static/vlans
        broadcast: broadcast of interface, only needed when method = static/vlans
    """
    logging.debugv("client.py->register(localip, keyname)", [localip, keyname])

    checkNet()

    req = "startclient.php"
    args = urllib.urlencode((
        ('ip_localip', localip),
        ('strip_html_escape_keyname', keyname))
    )
    result = makeRequest(req, args)
    for line in result.readlines(): logging.debug(line[:-1])


def getKey(localip):
    """ download certificate, key and sensor ID """
    logging.debugv("client.py->getKey(localip)", [localip])
    checkNet()

    req = "cert.php"
    args = urllib.urlencode((
        ('ip_localip', localip),)
    )

    result = makeRequest(req, args)
    (cert, key, id) = "".join(result.readlines()).split('EOF')
    return (cert, key, id.strip())


def deRegister(localip):
    """ Deregisters interface from IDS server """
    logging.debugv("client.py->deRegister(localip)", [localip])

    checkNet()

    if not r.networkStatus():
        logging.warning("Sensor not active, not deregistering")
        return

    sensorid = c.getSensorID()
    req = "stopclient.php"
    args = urllib.urlencode((
        ('ip_localip', localip),
        ('strip_html_escape_keyname', sensorid))
    ) 

    x = makeRequest(req, args)
    for line in x.readlines(): logging.debug(line[:-1])


def checkKey(localip):
    """ check if we have cert, key and sensor ID, if not, download """
    logging.debugv("client.py->checkKey(localip)", [localip])
    keyFile = locations.KEY
    certFile = locations.CRT

    if not os.access(keyFile, os.R_OK) or \
            not os.access(certFile, os.R_OK) or \
            c.getSensorID() == "":

        (key, cert, sensorid) = getKey(localip)
        open(keyFile,'w').write(key)
        os.chmod(keyFile, 0600)
        open(certFile,'w').write(cert)
        os.chmod(certFile, 0600)
        c.setSensorID(sensorid)
    else:
        logging.debug("already got certificate, key and sensor id")


def update(localip, ssh, revision, mac):
    """ updates interface @ ids server """
    logging.debugv("client.py->update(localip, ssh, revision, mac)", [localip, ssh, revision, mac])

    checkNet()
    if not r.sensorStatus():
        logging.debug("sensor not active, not updating")
        return

    logging.info("updating @ IDS server")

    sensorid = c.getSensorID()
    req = "status.php"
    args = urllib.urlencode((
        ('strip_html_escape_keyname', sensorid),
        ('ip_localip', localip),
        ('int_ssh', ssh),
        ('int_rev', revision),
        ('mac_mac', mac))
    )

    x = makeRequest(req, args)
    action = None
    for line in [x.strip() for x in x.readlines()]:
        logging.debug(line)
        if line.startswith("ACTION:"):
            action = line.split()[1]
            logging.debug("Received action: " + action)
    return action.lower()


def makeRequest(request, args):
    """ Send a request to the tunnel server.  """

    serverurl = c.getServerurl()
    user = c.getUser()
    passwd = c.getPasswd()
    url = serverurl + request + "?" + args

    logging.info("MRQ: Requesting " + url)

    auth_handler = urllib2.HTTPBasicAuthHandler()
    auth_handler.add_password(realm='Certificates', uri=url, user=user, passwd=passwd)
    opener = urllib2.build_opener(auth_handler)
    urllib2.install_opener(opener)

    try:    
        result = urllib2.urlopen(url)
        logging.debug("MRQ: Success")
        return result
    except urllib2.URLError, (strerror):
        msg = "Could not process HTTP request: " + str(strerror)
        logging.error(msg)
        raise excepts.NetworkException, msg
