
import logging
import configobj

from sensor import locations
from sensor import excepts

changeset = "001"

class Runtime:
    """
    This class is used to store all runtime information.
     * Interfaces that are started/created by surfids
     * tunnel status
    """

    # making this a borg object (singleton)
    __shared_state = {}

    def __init__(self):
        logging.debugv("runtime.py->__init__(self)", [])
        self.__dict__ = self.__shared_state
        self.config = configobj.ConfigObj(locations.INTERFACES)
        if not self.config.has_key('infs'): self.config['infs'] = {}
        if not self.config.has_key('status'): self.config['status'] = {}
        if not self.config.has_key('net'): self.config['net'] = {}
        self.config.write()


    def addInf(self, inf, brinf, type='dhcp', bridgeid="0"):
        """ add a interface to runtime db . brinf is the interface that is used for routing"""
        logging.debugv("runtime.py->addInf(self, inf, brinf, type, bridgeid)", [inf, brinf, type, bridgeid])
        self.config['infs'][inf] = {
            'bridgedev': brinf,
            'bridgeid': bridgeid,
            'type': type,
        }
        self.config.write()

    def chkInf(self, interface):
        """ checks if interface is in runtime db """
        logging.debugv("runtime.py->chkInf(self, interface)", [interface])
        if not self.config['infs'].has_key(interface):
            raise excepts.InterfaceException, "interface not found: %s" % interface

    def getInf(self, interface):
        """ get interface info from runtime db """
        logging.debugv("runtime.py->getInf(self, interface)", [interface])
        self.chkInf(interface)
        return self.config['infs'][interface]

    def delInf(self, interface):
        """ remove a interface from runtime db """
        logging.debugv("runtime.py->delInf(self, interface)", [interface])
        self.chkInf(interface)
        self.config['infs'].pop(interface)
        self.config.write()

    def listInf(self):
        """ returns a list of interfaces with config from runtime db"""
        logging.debugv("runtime.py->listInf(self)", [])
        return self.config['infs'].items()

    def listInfStatus(self):
        """ returns a list of interfaces with status from runtime db"""
        logging.debugv("runtime.py->listInfStatus(self)", [])
        return self.config['net'].items()

    def setInf(self, interface, key, value):
        logging.debugv("runtime.py->setInf(self, interface, key, value)", [interface, key, value])
        self.chkInf(interface)
        self.config['infs'][interface][key] = value
        self.config.write()

    def listVlan(self, inf):
        """ returns a list of interfaces from runtime db"""
        logging.debugv("runtime.py->listVlan(self, inf)", [inf])
        self.chkInf(inf)
        return self.config['infs'][inf]['vlans'].items()

    def addVlan(self, interface, vlandev, brinf, vlanid, type="dhcp", bridgeid="0"):
        """ Add a vlan virtual interface to runtime db """
        logging.debugv("runtime.py->addVlan(self, interface, vlandev, brinf, vlanid, type, bridgeid)", [interface, vlandev, brinf, vlanid, type, bridgeid])
        self.chkInf(interface)
        self.config['infs'][interface]['vlans'][vlandev] = {
            'vlanid': vlanid,
            'type': type,
            'bridgedev': brinf,
            'bridgeid': bridgeid,
           }
        self.config.write()

    def checkVlan(self, interface, vlandev):
        """ checks if vlan is in runtime db """
        logging.debugv("runtime.py->checkVlan(self, interface, vlandev)", [interface, vlandev])
        self.chkInf(interface)
        if not self.config['infs'][interface]['vlans'].has_key(vlandev):
            raise InterfaceException, "vlan not found: %s,%s" % (interface, vlandev)

    def getVlan(self, interface, vlan):
        """ get vlan interface info from runtime db """
        logging.debugv("runtime.py->getVlan(self, interface, vlan)", [interface, vlan])
        self.checkVlan(interface, vlan)
        return self.config['infs'][interface]['vlans'][vlan]
        
    def delVlan(self, interface, vlandev):
        """ remove vlan interface from runtime db """
        logging.debugv("runtime.py->delVlan(self, interface, vlandev)", [interface, vlandev])
        self.checkVlan(interface, vlandev)
        self.config['infs'][interface]['vlans'].pop(vlandev)
        self.config.write()

    def setVlan(self, interface, vlandev, key, value):
        """ set the property of a vlan """
        logging.debugv("runtime.py->setVlan(self, interface, vlandev, key, value)", [interface, vlandev, key, value])
        self.checkVlan(interface, vlandev)
        self.config['infs'][interface]['vlans'][vlandev][key] = value
        self.config.write()

    def tunnelStatus(self):
        """ Returns the status of the OpenVPN tunnel """
        logging.debugv("runtime.py->tunnelStatus(self)", [])
        if self.config['status'].get('tunnel') == "enabled":
            return True
        return False

    def tunnelUp(self):
        """ Sets the status of the OpenVPN tunnel to enabled """
        logging.debugv("runtime.py->tunnelUp(self)", [])
        logging.info("Setting runtime tunnel status to enabled")
        self.config['status']['tunnel'] = "enabled"
        self.config.write()

    def tunnelDown(self):
        """ Sets the status of the OpenVPN tunnel to enabled """
        logging.debugv("runtime.py->tunnelDown(self)", [])
        logging.info("Setting runtime tunnel status to disabled")
        self.config['status']['tunnel'] = "disabled"
        self.config.write()

    def sensorStatus(self):
        """ return the status of the surfids tunnel configuration """
        logging.debugv("runtime.py->sensorStatus(self)", [])
        if not self.networkStatus(): return False
        if self.config['status'].get('sensor') == "enabled":
            return True
        return False

    def sensorUp(self):
        """ run this after all surfids tunnels are started """
        logging.debugv("runtime.py->sensorUp(self)", [])
        logging.info("setting runtime tunnel status to up")
        if not self.networkStatus():
            raise excepts.NetworkException("network not up")
        self.config['status']['sensor'] = "enabled"
        self.config.write()

    def sensorDown(self):
        """ run this after all surfids tunnels are shutdown """
        logging.debugv("runtime.py->sensorDown(self)", [])
        logging.info("setting runtime tunnel status to down")
        self.config['status']['sensor'] = "disabled"
        self.config.write()

    def configStatus(self):
        """ Return the status of the network configuration """
        logging.debugv("runtime.py->configStatus(self)", [])
        if self.config['status'].get('config') == "enabled":
            return True
        return False

    def configUp(self):
        """ Set the status of the configuration to enabled """
        logging.debugv("runtime.py->configUp(self)", [])
        logging.info("Setting runtime config status to enabled")
        self.config['status']['config'] = "enabled"
        self.config.write()

    def configDown(self):
        """ Set the status of the configuration to disabled """
        logging.debugv("runtime.py->configDown(self)", [])
        logging.info("Setting runtime config status to disabled")
        self.config['status']['config'] = "disabled"
        self.config.write()

    def networkStatus(self):
        """ returns the status of the surfids network configuration """
        logging.debugv("runtime.py->networkStatus(self)", [])
        if self.config['status'].get('network') == "enabled":
            return True
        return False

    def networkUp(self):
        """ run this after the surfids network config was set """
        logging.debugv("runtime.py->networkUp(self)", [])
        logging.info("setting runtime network status to up")
        self.config['status']['network'] = "enabled"
        self.config.write()

    def networkDown(self):
        """ run this after the surfids network config was unset """
        logging.debugv("runtime.py->networkDown(self)", [])
        logging.info("setting runtime network status to down")
        self.config['status']['network'] = "disabled"
        self.config.write()

    def reset(self):
        """ reset all status stuff and interfaces """
        logging.debugv("runtime.py->reset(self)", [])
        logging.info("Resetting runtime status")
        for inf in self.listInf():
            self.delInf(inf)
        self.sensorDown()
        self.networkDown()
        self.tunnelDown()
        self.config.write()

    def net(self, inf, status):
        """ Set the runtime status of a network interface.\n
        \t0 = Interface does not exist\n
        \t1 = Interface exists\n
        \t2 = Interface exists and is up\n
        \t3 = Interface exists, is up and has IP """

        logging.debugv("runtime.py->net(self, inf, status)", [inf, status])

        logging.info("Runtime %s set to %s" % (inf, status))
        self.config['net'][inf] = status
        self.config.write()

    def chkNet(self, inf):
        """ Returns the status of a given interface """
        logging.debugv("runtime.py->chkNet(self, inf)", [inf])

        try:
            status = self.config['net'][inf]
            return int(status)
        except KeyError:
            return int(9)

    def listNet(self):
        """ Returns a list with the network status """
        logging.debugv("runtime.py->listNet(self)", [])
        return self.config['net'].items()

    def sshUp(self):
        """ Set the runtime status of the SSH daemon to enabled. """
        logging.debugv("runtime.py->sshUp(self)", [])
        logging.info("Setting runtime SSH status to enabled")
        self.config['status']['ssh'] = "enabled"
        self.config.write()

    def sshDown(self):
        """ Set the runtime status of the SSH daemon to disabled. """
        logging.debugv("runtime.py->sshDown(self)", [])
        logging.info("Setting runtime SSH status to disabled")
        self.config['status']['ssh'] = "disabled"
        self.config.write()
