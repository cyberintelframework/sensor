from configobj import ConfigObj
import logging
import pdb
import md5

from sensor import locations

# Setting version variables
version = "2.10.00"
changeset = "001"

class Config:

    # making this a borg object (singleton)
    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state
        self.config = ConfigObj(locations.SETTINGS)
        self.netconf = ConfigObj(locations.NETCONF)
        self.ipmi = ConfigObj(locations.IPMI)
        self.changed = False
        try:
            logging.debugv("config.py->__init__(self)", [])
        except AttributeError:
            foo = "Do nothing"

    def refresh(self):
        """ reloads config file from filesystem """
        logging.debugv("config.py->refresh(self)", [])
        logging.debug("refreshing configuration")
        self.config = False
        self.config = ConfigObj(locations.SETTINGS)
        self.netconf = False
        self.netconf = ConfigObj(locations.NETCONF)
        self.ipmi = False
        self.ipmi = ConfigObj(locations.IPMI)

    ############################
    # IPMI functions
    ############################

    def getIpmiAddress(self):
        """ Get the address for the IPMI interface """
        logging.debugv("config.py->getIpmiAddress(self)", [])
        try:
            ipmiAddress = self.ipmi['address']
            return ipmiAddress
        except KeyError:
            self.ipmi['address'] = ""
            self.ipmi.write()
            return self.ipmi['address']

    def getIpmiNetmask(self):
        """ Get the netmask for the IPMI interface """
        logging.debugv("config.py->getIpmiNetmask(self)", [])
        try:
            ipmiNetmask = self.ipmi['netmask']
            return ipmiNetmask
        except KeyError:
            self.ipmi['netmask'] = ""
            self.ipmi.write()
            return self.ipmi['netmask']

    def getIpmiGatewayIP(self):
        """ Get the gateway IP address for the IPMI interface """
        logging.debugv("config.py->getIpmiGatewayIP(self)", [])
        try:
            ipmiGwIp = self.ipmi['gwip']
            return ipmiGwIp
        except KeyError:
            self.ipmi['gwip'] = ""
            self.ipmi.write()
            return self.ipmi['gwip']

    def getIpmiGatewayMAC(self):
        """ Get the gateway MAC address for the IPMI interface """
        logging.debugv("config.py->getIpmiGatewayMAC(self)", [])
        try:
            ipmiGwMac = self.ipmi['gwmac']
            return ipmiGwMac
        except KeyError:
            self.ipmi['gwmac'] = ""
            self.ipmi.write()
            return self.ipmi['gwmac']

    def getIpmiVlanID(self):
        """ Get the VLAN ID for the IPMI interface """
        logging.debugv("config.py->getIpmiVlanID(self)", [])
        try:
            ipmiVlanID = self.ipmi['vlanid']
            return ipmiVlanID
        except KeyError:
            self.ipmi['vlanid'] = ""
            self.ipmi.write()
            return self.ipmi['vlanid']

    ############################
    # Interfaces functions
    ############################

    def getMainIf(self):
        """ Get the interface configured as main interface """
        logging.debugv("config.py->getMainIf(self)", [])
        try:
            mainIf = self.netconf['mainIf']
            return mainIf
        except KeyError:
            self.netconf['mainIf'] = ""
            self.netconf.write()
            return self.netconf['mainIf']

    def setMainIf(self, interface):
        """ Set the interface as main interface """
        logging.debugv("config.py->setMainIf(self, interface)", [interface])
        self.netconf['mainIf'] = interface
        self.netconf.write()

    def getInfs(self):
        """ try to get the interfaces, create if not exists """
        logging.debugv("config.py->getInfs(self)", [])
        try:
            return self.netconf['interfaces']
        except KeyError:
            self.netconf['interfaces'] = {}
            self.netconf.write()
            return self.netconf['interfaces']


    def getIf(self, interface):
        """ get interface info, return empty info if not existing """
        logging.debugv("config.py->getIf(self, interface)", [interface])
        try:
            return self.getInfs()[interface]
        except KeyError:
            self.getInfs()
            self.netconf['interfaces'][interface] = {
                    'type': 'disabled',
                    'address': '',
                    'netmask': '',
                    'broadcast': '',
                    'gateway': '',
                    'tunnel': '',
                    }
            self.netconf.write()
            return self.netconf['interfaces'][interface]


    def resetOtherInfs(self, interface, types):
        """ Reset the types of all the interfaces (with the given types) except the given interface """
        logging.debugv("config.py->resetOtherInfs(self, interface, types)", [interface, types])
        for (inf, infConf) in self.getInfs().items():
            if inf != interface:
                if self.getInfs()[inf]['type'] in types:
                    self.getInfs()[inf]['type'] = 'disabled'
        self.netconf.write()

    def setIfProp(self, interface, key, value):
        """ set interface property """
        logging.debugv("config.py->setIfProp(self, interface, key, value)", [interface, key, value])
        inf = self.getIf(interface)
        inf[key] = value
        self.netconf['interfaces'][interface] = inf
        self.netconf.write()

    def chkInfType(self, interface):
        """" Check the interface type of a given interfaces """
        logging.debugv("config.py->chkInfType(self, interface)", [interface])
        try:
            type = self.netconf['interfaces'][interface]['type']
            return type
        except KeyError:
            return "Unknown"

    ############################
    # Vlans functions
    ############################

    def getTrunkIf(self):
        """ Get the interface configured as trunk interface """
        logging.debugv("config.py->getTrunkIf(self)", [])
        try:
            mainIf = self.netconf['trunkIf']
            return mainIf
        except KeyError:
            self.netconf['trunkIf'] = ""
            self.netconf.write()
            return self.netconf['trunkIf']

    def flushVlans(self):
        """ Flush the vlans config, but do not write it to the config yet """
        logging.debugv("config.py->flushVlans(self)", [])
        logging.debug("Flushin internal vlans config")
        self.netconf['vlans'] = {}

    def getVlans(self):
        """ Retrieve the vlans config """
        logging.debugv("config.py->getVlans(self)", [])
        try:
            return self.netconf['vlans']
        except KeyError:
            self.netconf['vlans'] = {}
            self.netconf.write()
            return self.netconf['vlans']

    def getVlan(self, number):
        """ Get a single vlan config """
        logging.debugv("config.py->getVlan(self, number)", [number])
        try:
            return self.getVlans()[str(number)]
        except KeyError:
            self.netconf['vlans'][str(number)] = {
                   'vlanid': '',
                   'type': 'disabled',
                   'description': '',
                   'address': '',
                   'netmask': '',
                   'gateway': '',
                   'broadcast': '',
                   'tunnel': '',
                   }
            self.netconf.write()
            return self.netconf['vlans'][str(number)]

    def getTotalVlans(self):
        """ Retrieve the amount of VLANs to be configured """
        logging.debugv("config.py->getTotalVlans(self)", [])
        return len(self.getVlans())

    def setVlanProp(self, number, key, value):
        """ set a vlan property """
        logging.debugv("config.py->setVlanProp(self, number, key, value)", [number, key, value])
        vlan = self.getVlan(number)
        vlan[key] = value
        self.netconf['vlans'][number] = vlan
        self.netconf.write()

    def chkVlanID(self, number):
        """ Check the VLAN number and see if it is in use already or not """
        logging.debugv("config.py->chkVlanID(self, number)", [number])
        for (vlanConf) in self.getVlans().values():
            if vlanConf['vlanid'] == number:
                return True
        return False

    def chkTrunk(self, interface):
        """ Check if a given interface is selected as trunk device """
        logging.debugv("config.py->chkTrunk(self, interface)", [interface])
        try:
            if self.netconf['interfaces'][interface]['type'] == "trunk":
                return "Selected"
            else:
                return ""
        except KeyError:
            return ""

    def setTrunk(self, trunk):
        """ Set the trunk interface for sensor type VLAN """
        logging.debugv("config.py->setTrunk(self, trunk)", [trunk])
        self.getIf(trunk)
        self.netconf['interfaces'][trunk]['type'] = "trunk"
        self.netconf['trunkIf'] = trunk
        for inf in self.netconf['interfaces']: 
            if inf != trunk:
                if self.netconf['interfaces'][inf]['type'] == "trunk":
                    self.netconf['interfaces'][inf]['type'] = "disabled"
        self.netconf.write()

    def resetTrunk(self):
        """ Reset all the trunk interfaces to disabled """
        logging.debugv("config.py->resetTrunk(self)", [])
        for inf in self.getInfs():
            if self.netconf['interfaces'][inf]['type'] == "trunk":
                self.netconf['interfaces'][inf]['type'] = "disabled"
        self.netconf.write()

    ############################
    # Misc functions
    ############################

    def getRev(self):
        """ Retrieve the current netconf revision number """
        logging.debugv("config.py->getRev(self)", [])

        try:
            rev = self.netconf['revision']
            return rev
        except KeyError:
            self.netconf['revision'] = 1
            self.netconf.write()
            return self.netconf['revision']

    def addRev(self):
        """ Increases the network configuration revision by one 
            and saves it
        """
        logging.debugv("config.py->addRev(self)", [])

        try:
            rev = int(self.netconf['revision'])
            rev = rev + 1
            self.netconf['revision'] = rev
            self.netconf.write()
        except KeyError:
            self.netconf['revision'] = 1
            self.netconf.write()

    def validAdmin(self, passwd):
        """ Checks the given pass against admin pass """
        logging.debugv("config.py->validAdmin(self, passwd)", [])

        if passwd == "": return False
        else:
            m = md5.new()
            m.update(passwd)
            passwd = m.hexdigest()

            try:
                if passwd == self.config['adminpass']:
                    logging.info("Successful admin login")
                    return True
                else:
                    logging.warning("Failed admin login")
                    return False
            except KeyError:
                logging.error("No admin password was set")
                return False

    def getSensorType(self):
        """ Get the type of sensor (normal|vlan) """
        logging.debugv("config.py->getSensorType(self)", [])

        try:
            return self.netconf['sensortype']
        except KeyError:
            self.netconf['sensortype'] = ""
            self.netconf.write()
            return self.netconf['sensortype']

    def getDNS(self):
        """ get DNS configuration. (staticconfig, prim, sec) """
        logging.debugv("config.py->getDNS(self)", [])
        try:
            (prim, sec) = self.netconf['dns']
            return (self.netconf['dnstype'], prim, sec)
        except KeyError:
            self.netconf['dnstype'] = "dhcp"
            self.netconf['dns'] = ("","")
            self.netconf.write()
            (prim, sec) = self.netconf['dns']
            return (self.netconf['dnstype'], prim, sec)

    def setDNS(self, type="dhcp", prim="", sec=""):
        """ set DNS configuration. Set static to True if you want to specify a
            manual DNS configuration
        """
        logging.debugv("config.py->setDNS(self, type, prim, sec)", [type, prim, sec])
        self.netconf['dnstype'] = type 
        self.netconf['dns'] = (prim, sec)
        self.netconf.write()

    def getServer(self):
        """ Get the server """
        logging.debugv("config.py->getServer(self)", [])
        try:
            return self.config['server']
        except KeyError:
            return '0.0.0.0'

    def getSensorID(self):
        """ Get the sensor ID """
        logging.debugv("config.py->getSensorID(self)", [])
        try:
            return self.config['sensorid']
        except KeyError:
            return 'Unkown'

    def setSensorID(self, sensorid):
        """ Set the sensor ID """
        logging.debugv("config.py->setSensorID(self, sensorid)", [sensorid])
        self.config['sensorid'] = sensorid
        self.config.write()

    def getLogLevel(self):
        """ Get the level of logging """
        #logging.debugv("config.py->getLogLevel(self)", [])
        try:
            return self.config['loglevel']
        except KeyError:
            return 'info'

    def setLogLevel(self, loglevel):
        """ Set the level of logging """
        logging.debugv("config.py->setLogLevel(self, loglevel)", [loglevel])
        self.config['loglevel'] = loglevel
        self.config.write()

    def getPasswd(self):
        """ Get the password """
        logging.debugv("config.py->getPasswd(self)", [])
        try:
            return self.config['passwd']
        except KeyError:
            return ''

    def setPasswd(self, passwd):
        """ Set the password """
        logging.debugv("config.py->setPasswd(self, passwd)", [passwd])
        self.config['passwd'] = passwd
        self.config.write()

    def getUser(self):
        """ Get the user """
        logging.debugv("config.py->getUser(self)", [])
        try:
            return self.config['user']
        except KeyError:
            return ''

    def setUser(self, user):
        """ Set the user """
        logging.debugv("config.py->setPasswd(self, user)", [user])
        self.config['user'] = user
        self.config.write()

    def getServerurl(self):
        """ Get the server URL """
        logging.debugv("config.py->getServerurl(self)", [])
        try:
            return self.config['serverurl']
        except KeyError:
            return ''

    def setServerurl(self, url):
        """ Set the server URL """
        logging.debugv("config.py->setServerurl(self, url)", [url])
        self.config['serverurl'] = url
        self.config.write()

    def getEmail(self):
        """ Get the email address """
        logging.debugv("config.py->getEmail(self)", [])
        try:
            return self.config['email']
        except KeyError:
            return ''

    def setEmail(self, email):
        """ Set the email address """
        logging.debugv("config.py->setEmail(self, email)", [email])
        self.config['email'] = email
        self.config.write()

    def getAutoStart(self):
        """ Get the autostart value """
        logging.debugv("config.py->getAutoStart(self)", [])
        try:
            autoStart = self.config['autostart']
            return autoStart
        except KeyError:
            self.config['autostart'] = "Disabled"
            self.config.write()
            return self.config['autostart']

    def setAutoStart(self, toggle):
        """ Set the autostart value """
        logging.debugv("config.py->setAutoStart(self, toggle)", [toggle])
        self.config['autostart'] = toggle
        self.config.write()

#    def get(self, key):
#        logging.debugv("config.py->get(self, key)", [key])
#        try:
#            return self.netconf[key]
#        except KeyError:
#            return ""

#    def set(self, key, value):
#        logging.debugv("config.py->set(self, key, value)", [key, value])
#        self.netconf[key] = value
#        self.netconf.write()

