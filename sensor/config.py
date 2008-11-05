from configobj import ConfigObj
import logging
import pdb

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

    ############################
    # Interfaces functions
    ############################

    def getInfs(self):
        """ try to get the interfaces, create if not exists """
	logging.debugv("config.py->getInfs(self)", [])
        try:
            return self.config['interfaces']
        except KeyError:
            self.config['interfaces'] = {}
            self.config.write()
            return self.config['interfaces']


    def getIf(self, interface):
        """ get interface info, return empty info if not existing """
	logging.debugv("config.py->getIf(self, interface)", [interface])
        try:
            return self.getInfs()[interface]
        except KeyError:
            self.getInfs()
            self.config['interfaces'][interface] = {
                    'type': 'disabled',
                    'address': '',
                    'netmask': '',
                    'broadcast': '',
                    'gateway': '',
		    'tunnel': '',
                    }
            self.config.write()
            return self.config['interfaces'][interface]


    def resetOtherInfs(self, interface, types):
	""" Reset the types of all the interfaces (with the given types) except the given interface """
	logging.debugv("config.py->resetOtherInfs(self, interface, types)", [interface, types])
        for (inf, infConf) in self.getInfs().items():
	    if inf != interface:
		if self.getInfs()[inf]['type'] in types:
        	    self.getInfs()[inf]['type'] = 'disabled'
	self.config.write()

    def setIfProp(self, interface, key, value):
        """ set interface property """
	logging.debugv("config.py->setIfProp(self, interface, key, value)", [interface, key, value])
        inf = self.getIf(interface)
        inf[key] = value
        self.config['interfaces'][interface] = inf
        self.config.write()

    def chkInfType(self, interface):
	"""" Check the interface type of a given interfaces """
	logging.debugv("config.py->chkInfType(self, interface)", [interface])
	try:
	    type = self.config['interfaces'][interface]['type']
	    return type
	except KeyError:
	    return "Unknown"

    ############################
    # Vlans functions
    ############################

    def flushVlans(self):
	""" Flush the vlans config, but do not write it to the config yet """
	logging.debugv("config.py->flushVlans(self)", [])
	logging.debug("Flushin internal vlans config")
	self.config['vlans'] = {}

    def getVlans(self):
        """ Retrieve the vlans config """
	logging.debugv("config.py->getVlans(self)", [])
        try:
            return self.config['vlans']
        except KeyError:
            self.config['vlans'] = {}
            self.config.write()
            return self.config['vlans']

    def getVlan(self, number):
        """ Get a single vlan config """
	logging.debugv("config.py->getVlan(self, number)", [number])
        try:
            return self.getVlans()[str(number)]
        except KeyError:
            self.config['vlans'][str(number)] = {
                   'vlanid': '',
                   'type': 'disabled',
                   'description': '',
                   'address': '',
                   'netmask': '',
                   'gateway': '',
                   'broadcast': '',
		   'tunnel': '',
                   }
            self.config.write()
            return self.config['vlans'][str(number)]

    def getTotalVlans(self):
	""" Retrieve the amount of VLANs to be configured """
	logging.debugv("config.py->getTotalVlans(self)", [])
	return len(self.getVlans())

    def setVlanProp(self, number, key, value):
        """ set a vlan property """
	logging.debugv("config.py->setVlanProp(self, number, key, value)", [number, key, value])
        vlan = self.getVlan(number)
        vlan[key] = value
        self.config['vlans'][number] = vlan
        self.config.write()

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
	    if self.config['interfaces'][interface]['type'] == "trunk":
	        return "Selected"
	    else:
	        return ""
	except KeyError:
	    return ""

    def setTrunk(self, trunk):
	""" Set the trunk interface for sensor type VLAN """
	logging.debugv("config.py->setTrunk(self, trunk)", [trunk])
	self.getIf(trunk)
	self.config['interfaces'][trunk]['type'] = "trunk"
	for inf in self.config['interfaces']: 
	    if inf != trunk:
		if self.config['interfaces'][inf]['type'] == "trunk":
	            self.config['interfaces'][inf]['type'] = "disabled"
	self.config.write()

    def resetTrunk(self):
	""" Reset all the trunk interfaces to disabled """
	logging.debugv("config.py->resetTrunk(self)", [])
	for inf in self.getInfs():
	    if self.config['interfaces'][inf]['type'] == "trunk":
		self.config['interfaces'][inf]['type'] = "disabled"
	self.config.write()

    ############################
    # Misc functions
    ############################

    def getDNS(self):
        """ get DNS configuration. (staticconfig, prim, sec) """
	logging.debugv("config.py->getDNS(self)", [])
        try:
            (prim, sec) = self.config['dns']
            return (self.config['dnstype'], prim, sec)
        except KeyError:
            self.config['dnstype'] = "dhcp"
            self.config['dns'] = ("","")
            self.config.write()
            (prim, sec) = self.config['dns']
            return (self.config['dnstype'], prim, sec)

    def setDNS(self, type="dhcp", prim="", sec=""):
        """ set DNS configuration. Set static to True if you want to specify a
            manual DNS configuration
        """
	logging.debugv("config.py->setDNS(self, type, prim, sec)", [type, prim, sec])
        self.config['dnstype'] = type 
        self.config['dns'] = (prim, sec)
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
        self.set('loglevel', loglevel)

    def get(self, key):
	logging.debugv("config.py->get(self, key)", [key])
        try:
            return self.config[key]
        except KeyError:
            return ""

    def set(self, key, value):
	logging.debugv("config.py->set(self, key, value)", [key, value])
        self.config[key] = value
        self.config.write()

