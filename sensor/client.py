
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

    if not t.urlCheck(c.getServerurl()):
        logging.warning("Server URL invalid. Could not save configuration!")
        c.changed = True
        return

    method = c.netconf['sensortype']

    mainIf = c.getMainIf()
#    mainIfMac = r.getMainIfMac()
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
               vlanIf = "|" + tunnel + "|" + nm + "|" + bc + "|" + gw
           else:
               vlanIf = "dhcp"
           trunkConf += vlanid + "," + vlanIf + "," + desc + "!"
        trunkConf = trunkConf.rstrip("!")

    sensor = c.getSensorID()
    (dnstype, dns1, dns2) = c.getDNS()
    (os, version, nr) = platform.dist()
    osv = os + "-" + version + "-" + nr
    req = "save_config.php"
    rev = c.getRev()
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
    	('int_rev', str(rev)))
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

    if not r.networkStatus():
        logging.error("No network connection available, not registering")
        return

    req = "startclient.php"
    args = urllib.urlencode((
        ('ip_localip', localip),
        ('strip_html_escape_keyname', keyname))
    )
    try:
        result = makeRequest(req, args)
    except excepts.NetworkException:
        logging.warning("Could not register with server!")
    else:
        for line in result.readlines(): logging.debug(line[:-1])


def getKey(localip):
    """ download certificate, key and sensor ID """
    logging.debugv("client.py->getKey(localip)", [localip])

    req = "cert.php"
    args = urllib.urlencode((
        ('ip_localip', localip),)
    )

    try:
        result = makeRequest(req, args)
    except excepts.NetworkException:
        logging.error("Could not retrieve new certificate!")
        return (False, False, False)
    else:
        (cert, key, id) = "".join(result.readlines()).split('EOF')
        return (cert, key, id.strip())


def deRegister(localip):
    """ Deregisters interface from IDS server """
    logging.debugv("client.py->deRegister(localip)", [localip])

    if not r.networkStatus():
        logging.warning("No network connection available, not deregistering")
        return

    if r.sensorStatus():
        sensorid = c.getSensorID()
        req = "stopclient.php"
        args = urllib.urlencode((
            ('ip_localip', localip),
            ('strip_html_escape_keyname', sensorid))
        ) 

        try:
            x = makeRequest(req, args)
        except excepts.NetworkException:
            logging.warning("Could not deRegister from the server!")
        else:
            for line in x.readlines(): logging.debug(line[:-1])
    else:
        logging.warning("Sensor not active, not deregistering")
        return


def checkKey(localip):
    """ check if we have cert, key and sensor ID, if not, download """
    logging.debugv("client.py->checkKey(localip)", [localip])
    keyFile = locations.KEY
    certFile = locations.CRT

    if not os.access(keyFile, os.R_OK) or \
            not os.access(certFile, os.R_OK) or \
            c.getSensorID() == "":

        (key, cert, sensorid) = getKey(localip)
        if key:
            open(keyFile,'w').write(key)
            os.chmod(keyFile, 0600)
        if cert:
            open(certFile,'w').write(cert)
            os.chmod(certFile, 0600)
        if sensorid:
            c.setSensorID(sensorid)
        # After we got a sensor ID we need to save the configuration
        # We could not do this before due to missing a sensor ID
        saveConf()
    else:
        logging.debug("already got certificate, key and sensor id")


def getConfig():
    """ Get the latest configuration from the server """
    logging.debugv("client.py->getConfig()", [])

    if r.networkStatus():
        sensorid = c.getSensorID()
        req = "get_config.php"
        args = urllib.urlencode((
            ('strip_html_escape_keyname', str(sensorid)),
        ))
        try:
            x = makeRequest(req, args)
        except excepts.NetworkException:
            logging.warning("Could not retrieve configuration from the server!")
            return False
        else:
            config = ""
            for line in [x for x in x.readlines()]:
                logging.debug(line)
                config += line
            return config
    else:
        logging.warning("No network connection available. Can't get new configuration.")
        return False

def update(localip, ssh, mac, pversion):
    """ updates interface @ ids server """
    logging.debugv("client.py->update(localip, ssh, mac, pversion)", [localip, ssh, mac, pversion])

    if not r.networkStatus():
        logging.debug("Sensor not active, not syncing")
        return

    logging.info("Updating @ IDS server")

    sensorid = c.getSensorID()
    req = "status.php"
    args = urllib.urlencode((
        ('strip_html_escape_keyname', sensorid),
        ('ip_localip', localip),
        ('int_ssh', ssh),
        ('mac_mac', mac),
        ('strip_html_escape_pversion', pversion))
    )

    try:
        x = makeRequest(req, args)
    except excepts.NetworkException:
        logging.warning("Could not sync with server!")
        action = None
    else:
        action = None
        for line in [x.strip() for x in x.readlines()]:
            logging.debug(line)
            if line.startswith("ACTION:"):
                action = line.split()[1]
                logging.debug("Received action: " + action)
    if action:
        return action.lower()
    else:
        return False


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
