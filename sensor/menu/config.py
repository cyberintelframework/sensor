 
import logging
import pdb
import string

from sensor import dialog
from sensor import functions as f
from sensor import config
from sensor import tools as t
from sensor import log
from sensor import runtime
from sensor import client
from sensor import excepts

import manage

class Config:
    def __init__(self, d):
        # d = dialog object
        self.d = d

        # c = config object
        self.c = config.Config()

        # r = runtime object
        self.r = runtime.Runtime()

        # flag for config change. used for "activate new config" popup
        self.changed = False

        logging.debugv("menu/config.py->__init__(self, d)", [])


    def run(self):
        """ submenu of main to for network configuration """
        logging.debugv("menu/config.py->run(self)", [])
        choice = self.d.menu("What do you want to network?",
            choices=[
                ("Network", "Configure network..."),
                ("DNS", "Nameservers settings..."),
                ('serverurl', self.c.getServerurl()),
                ('user', self.c.getUser()),
                ('passwd', len(self.c.getPasswd())*'*'),
                ('email', self.c.getEmail()),
                ('loglevel', self.c.getLogLevel() ),
                ], cancel="back")

        # cancel 
        if choice[0] == 1:
            if self.changed:
                client.saveConf()
                self.activateChoice()
            return
        elif choice[1] == "Network": self.setNetwork()
        elif choice[1] == "DNS": self.dns()
        elif choice[1] == "serverurl": self.setServerurl()
        elif choice[1] == "user": self.setUser()
        elif choice[1] == "passwd": self.setPasswd()
        elif choice[1] == "loglevel": self.setLogLevel()
        self.run()

    def activateChoice(self):
        """ Choose to stop or restart sensor after changing the config """
        logging.debugv("menu/config.py->activateChoice(self)", [])
        choices = [
                ("Stop", "Stop the sensor"),
                ("Restart", "Restart the sensor"),
                ]
        choice = self.d.menu("Select the next action", choices=choices, cancel="back")
        if choice[1] == "Stop":
            manage.Manage(self.d).sensorDown()
        elif choice[1] == "Restart":
            manage.Manage(self.d).sensorUp()
        else:
            self.activateChoice()

    def setNetwork(self):
        """ Submenu for choosing a sensor type """
        logging.debugv("menu/config.py->setNetwork(self)", [])
        choices = [
                ("Normal", "Normal sensor"),
                ("Vlan", "VLAN sensor"),
                ]
        choice = self.d.menu("Select the type of sensor", choices=choices, cancel="back")
        if choice[0] == 1: return
        elif choice[1] == "Normal":
            self.c.netconf['sensortype'] = "normal"
            self.c.resetTrunk()
            self.c.netconf.write()
            self.list()
        elif choice[1] == "Vlan":
            self.c.netconf['sensortype'] = "vlan"
            self.c.netconf.write()
            self.configVlan()
        self.setNetwork()

    def configVlan(self):
        """ Submenu for configuring the VLAN setup """
        logging.debugv("menu/config.py->configVlan(self)", [])
        choices = [
                ("Trunk", "Select the trunk device"),
                ("Main", "Select the main device"),
                ]
        choice = self.d.menu("Configure VLAN sensor", choices=choices, cancel="back")
        if choice[0] == 1: return
        elif choice[1] == "Trunk": self.listTrunk()
        elif choice[1] == "Main": self.list()
        self.configVlan()


    def listTrunk(self):
        """ Submenu for configuring the trunk device """
        logging.debugv("menu/config.py->listTrunk(self)", [])
        self.c.refresh()
        infs = f.ifList()
        choices = [(x,self.c.chkTrunk(x)) for x in infs]
        output = self.d.menu("Select the trunk interface", choices=choices)
        if not output[0]:
            interface = output[1]
            logging.info("Setting trunk interface to %s" % interface)
            self.c.changed = True
            self.c.setTrunk(interface)
            self.editVlanNum()


    def list(self):
        """ submenu of network, listing interfaces """
        logging.debugv("menu/config.py->list(self)", [])
        # before listing, reset the trunks to disabled
        infs = f.ifList()
        choices = [(x,self.c.chkInfType(x)) for x in infs]
        choice = self.d.menu("Select the interface", choices=choices, cancel="back")
        if choice[0] == 1: return
        else:
            self.edit(choice[1])
        self.list()


    def dns(self):
        """ submenu of network, dns settings menu """
        logging.debugv("menu/config.py->dns(self)", [])
        (type, prim, sec) = self.c.getDNS()
        choices = [ ("type", type) ]
        if type == "static":
            choices += [
                    ("primary", prim),
                    ("secondary", sec),
                ]
        logging.debug(choices)
        choice = self.d.menu("DNS settings", choices=choices, cancel="back")
        if choice[0] == 1:
            # We need to check if DNS settings are correct
            (type, prim, sec) = self.c.getDNS()
            if type == "static":
                if prim == "" or (prim == "" and sec == ""):
                    # No Nameserver set
                    self.d.msgbox("Specify a nameserver or set type to DHCP")
                else:
                    return
            else:                    
                return
        elif choice[1] == "type": self.dnsType()
        elif choice[1] == "primary": self.dnsPrim()
        elif choice[1] == "secondary": self.dnsSec()
        self.dns()

    def dnsType(self):
        """ set dns type (dhcp or static config """
        logging.debugv("menu/config.py->dnsType(self)", [])
        (type, prim, sec) = self.c.getDNS()
        output = self.d.radiolist("What type of DNS config do you want?", choices=[
            ("dhcp", "get DNS settings trough dhcp", int(type=="dhcp")),
            ("static", "Manual configuration", int(type=="static")),
        ])
        if output[0]: return
        type = output[1]
        self.changed = True
        self.c.setDNS(type, prim, sec)

    def dnsPrim(self):
        """ set primary DNS server """
        logging.debugv("menu/config.py->dnsPrim(self)", [])
        (type, prim, sec) = self.c.getDNS()
        while True:
            input = self.d.inputbox("primary DNS:", 10, 50, prim)
            if input[0]: return
            if t.ipv4check(input[1]):
                prim = input[1]
                break
        self.changed = True
        self.c.setDNS(type, prim, sec)

    def dnsSec(self):
        """ set secondary DNS server """
        logging.debugv("menu/config.py->dnsSec(self)", [])
        (type, prim, sec) = self.c.getDNS()
        while True:
            input = self.d.inputbox("secondary DNS:", 10, 50, prim)
            if input[0]: return
            if t.ipv4check(input[1]):
                sec = input[1]
                break
        self.changed = True
        self.c.setDNS(type, prim, sec)


    def edit(self, interface):
        """ submenu of network, for editing a interface """
        logging.debugv("menu/config.py->edit(self, interface)", [interface])
        # Set this interface as the main IF
        self.c.setMainIf(interface)
        self.c.changed = True
        inf = self.c.getIf(interface)

        choices = [
                    ("Type", inf["type"]),
                ]

        if inf["type"] == "static":
            # Static sensors always need Local IP address
            choices += [
                        ("Local IP address", inf["address"]),
                    ]

            # Only add Endpoint option for simple sensors
            if self.c.netconf['sensortype'] == "simple":
                choices += [
                                ("Endpoint IP address", inf["tunnel"]),
                        ]

            # Add the rest of the options
            choices += [
                        ("Netmask", inf["netmask"]),
                        ("Gateway", inf["gateway"]),
                        ("Broadcast", inf["broadcast"]),
                    ]

        choice = self.d.menu("Interface %s configuration" % interface, choices=choices, cancel="back")

        if choice[0] == 1: return
        elif choice[1] == "Type": self.editType(interface)
        elif choice[1] == "Tunnel": self.editTunnel(interface)
        elif choice[1] == "Local IP address": self.editAddress(interface)
        elif choice[1] == "Netmask": self.editNetmask(interface)
        elif choice[1] == "Broadcast": self.editBroadcast(interface)
        elif choice[1] == "Gateway": self.editGateway(interface)
        elif choice[1] == "Endpoint IP address": self.editTunnelIP(interface)
        self.edit(interface)

    def editType(self, interface):
        """ Edit the network type for a given interface """
        logging.debugv("menu/config.py->editType(self, interface)", [interface])
        type = self.c.getIf(interface)['type']
        output = self.d.radiolist("type for " + interface, choices=[
            ("disabled", "Device is disabled", int(type=='disabled')),
            ("dhcp", "Dynamic (DHCP)", int(type=='dhcp')),
            ("static", "Static", int(type=='static')),
        ])
        if not output[0]: 
            type = output[1]
            logging.info("setting type for %s to %s" % (interface, type) )
            self.changed = True
            self.c.setIfProp(interface, "type", type)
            self.c.resetOtherInfs(interface, ["dhcp", "static"])
            

    def editTunnelIP(self, interface):
        """ Edit the statically set IP address for the tunnel server side """
        logging.debugv("menu/config.py->editTunnelIP(self, interface)", [interface])
        address = self.c.getIf(interface)['tunnel']
        while True:
            output = self.d.inputbox("Endpoint address on the tunnel server", 10, 50, address)
            if output[0]: return
            if t.ipv4check(output[1]):
                address = output[1]
                logging.info("Setting address for tunnel endpoint to %s" % (address) )
                self.changed = True
                self.c.setIfProp(interface, "tunnel", address)
                return
            else:
                self.d.msgbox("Please enter a valid IP address")

#    def editTunnel(self, interface):
#        """ Enable or disable the tunnel for a given interface """
#        tunnel = self.c.getIf(interface)['tunnel']
#        output = self.d.yesno("Do you want to enable the tunnel for this interface?")
#        tunnel = ["enabled", "disabled"][int(output)]
#        logging.info("setting tunnel for %s to: %s" % (interface, tunnel) )
#        self.changed = True
#        self.c.setIfProp(interface, "tunnel", tunnel )

    def editAddress(self, interface):
        """ Edit the statically set IP address """
        logging.debugv("menu/config.py->editAddress(self, interface)", [interface])
        address = self.c.getIf(interface)['address']
        tunnel = self.c.getIf(interface)['tunnel']
        while True:
            output = self.d.inputbox("address for " + interface, 10, 50, address)
            if output[0]: return
            if t.ipv4check(output[1]):
                if output[1] == tunnel:
                    self.d.msgbox("Local IP address and Endpoint IP address cannot be the same.\n Choose a different address.")
                else:
                    address = output[1]
                    logging.info("setting address for %s to %s" % (interface, address) )
                    self.changed = True
                    self.c.setIfProp(interface, "address", address)
                    return
            else:
                self.d.msgbox("Please enter a valid IP address")

    def editNetmask(self, interface):
        """ Edit the statically set netmask """
        logging.debugv("menu/config.py->editNetmask(self, interface)", [interface])
        netmask = self.c.getIf(interface)['netmask']
        while True:
            output = self.d.inputbox("netmask for " + interface, 10, 50, netmask)
            if output[0]: return
            if t.ipv4check(output[1]):
                netmask = output[1]
                logging.info("setting netmask for %s to %s" % (interface, netmask) )
                self.changed = True
                self.c.setIfProp(interface, "netmask", netmask)
                return
            else:
                self.d.msgbox("please enter a valid netmask address")


    def editBroadcast(self, interface):
        """ Edit the statically set broadcast """
        logging.debugv("menu/config.py->editBroadcast(self, interface)", [interface])
        broadcast = self.c.getIf(interface)['broadcast']
        if broadcast == "":
            address = self.c.getIf(interface)['address']
            netmask = self.c.getIf(interface)['netmask']
            broadcast = t.broadcast(address, netmask)
        while True:
            output = self.d.inputbox("Broadcast for " + interface, 10, 50, broadcast)
            if output[0]: return
            if t.ipv4check(output[1]):
                broadcast = output[1]
                logging.info("Setting broadcast for %s to %s" % (interface, broadcast) )
                self.changed = True
                self.c.setIfProp(interface, "broadcast", broadcast)
                return
            else:
                self.d.msgbox("Please enter a valid broadcast address")


    def editGateway(self, interface):
        """ Edit the statically set gateway address """
        logging.debugv("menu/config.py->editGateway(self, interface)", [interface])
        gateway = self.c.getIf(interface)['gateway']
        while True:
            output = self.d.inputbox("gateway for " + interface, 10, 50, gateway)
            if output[0]: return
            if t.ipv4check(output[1]):
                gateway = output[1]
                logging.info("setting gateway for %s to %s" % (interface, gateway) )
                self.changed = True
                self.c.setIfProp(interface, "gateway", gateway)
                return
            else:
                self.d.msgbox("please enter a valid gateway address")



    def editVlanNum(self):
        """ Edit the amount of VLANs that need to be configured """
        logging.debugv("menu/config.py->editVlanNum(self)", [])
        vlannum = self.c.getTotalVlans()
        output = self.d.inputbox("Number of vlans", 10, 50, str(vlannum))
        if output[0] == 1:
            self.listTrunk()
        else:
            if output[1].isdigit() and str(output[1]) != '0':
                vlannum = output[1]
                logging.debug("Setting number of vlans to %s" % vlannum)
                self.editVlans(vlannum)
            else:
                self.d.msgbox("Invalid number of VLANs. Enter a number between 1 and 9")
                self.editVlanNum()

    def editVlans(self, vlannum):
        """ list of configured vlans """
        logging.debugv("menu/config.py->editVlans(self, vlannum)", [vlannum])
        curVlanNum = self.c.getTotalVlans()
        logging.debug("curVlanNum %s vs vlannum %s" % (str(curVlanNum), str(vlannum)))
        if int(curVlanNum) > int(vlannum):
            # Current number of VLAN's is not the same as given number -> flush vlan config
            self.c.flushVlans()

        choices = []
        for i in range(int(vlannum)):
            vlan = self.c.getVlan(str(i))
            if vlan['description'] != "":
                tag = vlan['vlanid'] + " - " + vlan['description']
            else:
                tag = vlan['vlanid']
            choices += [(str(i), tag)]

        logging.debug("choices: %s" % str(choices))
        choice = self.d.menu("Choose a VLAN to edit...", choices=choices, cancel="back")
        if choice[0] == 1:
            self.listTrunk()
        else:
            self.editVlan(choice[1])
            self.editVlans(vlannum)


    def editVlan(self, vlan):
        """ edit vlan settings """
        logging.debugv("menu/config.py->editVlan(self, vlan)", [vlan])
        vlanConf = self.c.getVlan(vlan)

        choices = [
                    ("Description", vlanConf["description"]),
                    ("VlanID", vlanConf["vlanid"]),
                    ("Type", vlanConf["type"]),
                ]

        if vlanConf["type"] == "static":
            choices += [
                        ("Endpoint IP address", vlanConf["tunnel"]),
                        ("Netmask", vlanConf["netmask"]),
                        ("Gateway", vlanConf["gateway"]),
                        ("Broadcast", vlanConf["broadcast"]),
                    ]

        choice = self.d.menu("vlan %s config" % vlan, choices=choices, cancel="back")

        if choice[0] == 1: return
        elif choice[1] == "Description": self.editVlanDescription(vlan)
        elif choice[1] == "VlanID": self.editVlanID(vlan)
        elif choice[1] == "Type": self.editVlanType(vlan)
        elif choice[1] == "Endpoint IP address": self.editVlanAddress(vlan)
        elif choice[1] == "Netmask": self.editVlanNetmask(vlan)
        elif choice[1] == "Gateway": self.editVlanGateway(vlan)
        elif choice[1] == "Broadcast": self.editVlanBroadcast(vlan)
        self.editVlan(vlan)


    def editVlanDescription(self, vlan):
        """ Edit description of vlan interface """
        logging.debugv("menu/config.py->editVlanDescription(self, vlan)", [vlan])
        description = self.c.getVlan(vlan)['description']
        output = self.d.inputbox("Description for " + vlan, 10, 50, description)
        if not output[0]:
            description = output[1]
            logging.info("Setting description for VLAN %s to %s" % (vlan, description) )
            self.changed = True
            self.c.setVlanProp(vlan, "description", description)


    def editVlanID(self, vlan):
        """ Edit vlan ID of vlan interface """
        logging.debugv("menu/config.py->editVlanID(self, vlan)", [vlan])
        vlanid = self.c.getVlan(vlan)['vlanid']
        output = self.d.inputbox("VLAN for vlan%s" % vlan, 10, 50, vlanid)
        if not output[0]:
            if output[1].isdigit():
                vlanid = output[1]
                if self.c.chkVlanID(vlanid):
                    self.d.msgbox("VLAN ID already in use")
                    self.editVlanID(vlan)
                else:
                    logging.info("Setting VLAN ID for %s to %s" % (vlan, vlanid) )
                    self.changed = True
                    self.c.setVlanProp(vlan, "vlanid", vlanid)
            else:
                self.d.msgbox("Enter a NUMBER")
                self.editVlanVlanID(vlan)


    def editVlanType(self, vlan):
        """ Edit type (dhcp/static) of vlan interface """
        logging.debugv("menu/config.py->editVlanType(self, vlan)", [vlan])
        type = self.c.getVlan(vlan)['type']
        output = self.d.radiolist("type for " + vlan, choices=[
            ("disabled", "Disabled", int(type=="disabled")),
            ("dhcp", "Dynamic (DHCP)", int(type=="dhcp")),
            ("static", "Static", int(type=="static")),
        ])
        if not output[0]: 
            type = output[1]
            logging.info("Setting type for VLAN %s to %s" % (vlan, type) )
            self.changed = True
            self.c.setVlanProp(vlan, "type", type)


    def editVlanAddress(self, vlan):
        """ Edit address of vlan interface """
        logging.debugv("menu/config.py->editVlanAddress(self, vlan)", [vlan])
        address = self.c.getVlan(vlan)['tunnel']
        while True:
            output = self.d.inputbox("Address for new VLAN device", 10, 50, address)
            logging.debug(output)
            if output[0]: return
            if t.ipv4check(output[1]):
                address = output[1]
                logging.info("Setting address for VLAN %s to %s" % (vlan, address) )
                self.changed = True
                self.c.setVlanProp(vlan, "tunnel", address)
                return
            else:
                self.d.msgbox("You entered an invalid IP address")


    def editVlanNetmask(self, vlan):
        """ Edit netmask of vlan interface """
        logging.debugv("menu/config.py->editVlanNetmask(self, vlan)", [vlan])
        netmask = self.c.getVlan(vlan)['netmask']
        while True:
            output = self.d.inputbox("Netmask for new VLAN device", 10, 50, netmask)
            if output[0]: return
            if t.ipv4check(output[1]):
                netmask = output[1]
                logging.info("Setting netmask for VLAN %s to %s" % (vlan, netmask) )
                self.changed = True
                self.c.setVlanProp(vlan, "netmask", netmask)
                return
            else:
                self.d.msgbox("You entered an invalid netmask address")


    def editVlanBroadcast(self, vlan):
        """ Edit broadcast of vlan interface """
        logging.debugv("menu/config.py->editVlanBroadcast(self, vlan)", [vlan])
        broadcast = self.c.getVlan(vlan)['broadcast']
        if broadcast == "":
            address = self.c.getVlan(vlan)['tunnel']
            netmask = self.c.getVlan(vlan)['netmask']
            broadcast = t.broadcast(address, netmask)
        while True:
            output = self.d.inputbox("Broadcast address for new VLAN device", 10, 50, broadcast)
            if output[0]: return
            if t.ipv4check(output[1]):
                broadcast = output[1]
                logging.info("Setting broadcast for VLAN %s to %s" % (vlan, broadcast) )
                self.changed = True
                self.c.setVlanProp(vlan, "broadcast", broadcast)
                return
            else:
                self.d.msgbox("You entered an invalid broadcast address")



    def editVlanGateway(self, vlan):
        """ Edit gateway of vlan interface """
        logging.debugv("menu/config.py->editVlanGateway(self, vlan)", [vlan])
        gateway = self.c.getVlan(vlan)['gateway']
        while True:
            output = self.d.inputbox("Gateway for new VLAN device on %s" % vlan, 10, 50, gateway)
            if output[0]: return
            if t.ipv4check(output[1]):
                gateway = output[1]
                logging.info("setting gateway for VLAN %s to %s" % (vlan, gateway) )
                self.changed = True
                self.c.setVlanProp(vlan, "gateway", gateway)
                return
            else:
                self.d.msgbox("You entered an invalid gateway address")

 
    def setServerurl(self):
        """ Set or edit the server URL used for updates """
        logging.debugv("menu/config.py->setServerurl(self)", [])
        url = self.c.getServerurl()
        input = self.d.inputbox("Full URL of IDS server:", init=url)
        if input[0] == 1: return
        url = input[1]
        logging.info("setting serverurl to: " + url)
        self.changed = True
        self.c.setServerurl(url)

    def setUser(self):
        """ Set the https user to get updates with """
        logging.debugv("menu/config.py->setUser(self)", [])
        user = self.c.getUser()
        input = self.d.inputbox("Username for IDS server:", init=user)
        if input[0] == 1: return
        user = input[1]
        logging.info("setting user to: " + user)
        self.changed = True
        self.c.setUser( user)

    def setPasswd(self):
        """ Set the password for the https user """
        logging.debugv("menu/config.py->setPasswd(self)", [])
#        passwd = self.c.get("passwd")
        passwd = self.c.getPasswd()
        input = self.d.inputbox("Passwd IDS server:", init=passwd)
        if input[0] == 1: return
        passwd = input[1]
        logging.info("setting passwd to: " + passwd)
        self.changed = True
        self.c.setPasswd(passwd)

    def setLogLevel(self):
        """ Set the logging level of the SURFids log file """
        logging.debugv("menu/config.py->setLogLevel(self)", [])
        level = self.c.getLogLevel()
        output = self.d.radiolist("choose a loglevel: ", choices=[
            ("warning", "Show only Warnings", int(level=='warning')),
            ("info", "Normal logging", int(level=='info')),
            ("debug", "Debug logging", int(level=='debug')),
            ("debugv", "Debug verbose logging", int(level=='debugv')),
            ("debugvv", "Debug more verbose logging", int(level=='debugvv')),
            ("trace", "Trace log in dot format", int(level=='trace')),
        ])
        if not output[0]: 
            level = output[1]
            logging.info("setting loglevel to %s" % (level) )
            self.c.setLogLevel(level)


