
import logging
import urllib
import urllib2
import os

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


def saveConf(method, mainConf, trunkConf):
    """ Send the configuration to the server

        mainConf =        "dhcp" | "ip|tap_ip|nm|bc|gw"
        vlanDesc =        [a-zA-Z0-9 ]+
        method =        "vlan" | "simple"
        vlanConf =        VLAN_ID , MAINCONF , VLANDESC
        trunkConf =        VLANCONF ! VLANCONF ! VLANCONF ! ...
        request =        "save_config.php?method=METHOD&interface=MAINCONF&trunk=TRUNKCONF

    """
    logging.debugv("client.py->saveConf(method, mainConf, trunkConf)", [method, mainConf, trunkConf])

    sensor = c.get('sensorid')
    req = "save_config.php"
    args = urllib.urlencode((
        ('strip_html_escape_method', method),
        ('strip_html_escape_interface', str(mainConf)),
        ('strip_html_escape_keyname', sensor),
        ('strip_html_escape_trunk', str(trunkConf)))
    )

    logging.debug(str(args))
    x = makeRequest(req, args)
    for line in x.readlines(): logging.debug(line[:-1])


def register(localip, keyname):
    """ register interface @ ids server.

        localip: ip of interface
        method: method used for obtaining IP (dhcp, static, vland or vlans)
        vlanid: id of vlan, 0 of no vlan
        netmask: netmask of interface, only needed when method = static/vlans
        gateway: netmask of interface, only needed when method = static/vlans
        broadcast: broadcast of interface, only needed when method = static/vlans
    """
    logging.debugv("client.py->register(localip, keyname)", [localip, keyname])

    checkNet()

    req ="startclient.php"
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

    sensorid = c.get('sensorid')
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
            c.get('sensorid') == "":

        (key, cert, sensorid) = getKey(localip)
        open(keyFile,'w').write(key)
        os.chmod(keyFile, 0600)
        open(certFile,'w').write(cert)
        os.chmod(certFile, 0600)
        c.set('sensorid', sensorid)
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

    sensorid = c.get('sensorid')
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

    serverurl = c.get('serverurl')
    user = c.get('user')
    passwd = c.get('passwd')
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
