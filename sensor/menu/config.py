 
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

        # c = config object        self.c = config.Config()
        self.c = config.Config()

        # r = runtime object
        self.r = runtime.Runtime()

        # flag for config change. used for "activate new config" popup
        self.changed = False

        logging.debugv("menu/config.py->__init__(self, d)", [])


    def run(self):
        """ submenu of main to for network configuration """
        logging.debugv("menu/config.py->run(self)", [])
        choices=[
                ("Network", "Configure network...")
            ]

        if f.ipmiStatus():
            choices += [
                ("IPMI", "Configure IPMI...")
                ]

        choices += [
                ("DNS", "Nameservers settings..."),
                ('serverurl', self.c.getServerurl()),
                ('user', self.c.getUser()),
                ('passwd', len(self.c.getPasswd())*'*'),
                ('email', self.c.getEmail()),
                ('loglevel', self.c.getLogLevel() ),
            ]

        choice = self.d.menu("What do you want to network?", choices=choices, cancel="back", menu_height=10)

        # cancel 
        if choice[0] == 1:
            if self.changed:
                client.saveConf()
                self.activateChoice()
            return
        elif choice[1] == "Network": self.setNetwork()
        elif choice[1] == "IPMI": self.setIpmi()
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

    def setIpmi(self):
        """ Submenu for configuring IPMI settings """
        logging.debugv("menu/config.py->setIpmi(self)", [])

        address = self.c.getIpmiAddress()
        netmask = self.c.getIpmiNetmask()
        gwip = self.c.getIpmiGatewayIP()
        gwmac = self.c.getIpmiGatewayMAC()
        vlanid = self.c.getIpmiVlanID()

        choices = [
                    ("IP Address", "[%s]" % str(address)),
                    ("Netmask", "[%s]" % str(netmask)),
                    ("Gateway IP", "[%s]" % str(gwip)),
                    ("Gateway MAC", "[%s]" % str(gwmac)),
                    ("VLAN ID", "[%s] (optional)" % str(vlanid)),
                    ("Users", "IPMI User management..."),
                ]
        choice = self.d.menu("Configure the IPMI interface", choices=choices, cancel="back", width=60)
        if choice[0] == 1: return
        elif choice[1] == "IP Address": self.editIpmiAddress()
        elif choice[1] == "Netmask": self.editIpmiNetmask()
        elif choice[1] == "Gateway IP": self.editIpmiGatewayIP()
        elif choice[1] == "Gateway MAC": self.editIpmiGatewayMAC()
        elif choice[1] == "VLAN ID": self.editIpmiVlanID()
        elif choice[1] == "Users": self.editIpmiUsers()
        self.setIpmi()

    def editIpmiAddress(self):
        """ Edit the statically set IPMI IP address """
        logging.debugv("menu/config.py->editIpmiAddress(self)", [])
        address = self.c.getIpmiAddress()
        while True:
            output = self.d.inputbox("IPMI Address", 10, 50, address)
            if output[0]: return
            if t.ipv4check(output[1]):
                address = output[1]
                try:
                    f.ipmiSetNet(["ipaddr", address])
                    logging.debug("Setting IPMI address to %s" % (address) )
                    self.c.ipmi["address"] = address
                    self.c.ipmi.write()
                except excepts.RunException:
                    self.d.msgbox("Could not set the IP address for the IPMI interface", 8, 55)
                return
            else:
                self.d.msgbox("Please enter a valid IP address")

    def editIpmiNetmask(self):
        """ Edit the statically set IPMI netmask """
        logging.debugv("menu/config.py->editIpmiNetmask(self)", [])
        netmask = self.c.getIpmiNetmask()
        while True:
            output = self.d.inputbox("IPMI Netmask", 10, 50, netmask)
            if output[0]: return
            if t.ipv4check(output[1]):
                netmask = output[1]
                try:
                    f.ipmiSetNet(["netmask", netmask])
                    logging.debug("Setting IPMI netmask to %s" % (netmask) )
                    self.c.ipmi["netmask"] = netmask
                    self.c.ipmi.write()
                except excepts.RunException:
                    self.d.msgbox("Could not set the subnet mask for the IPMI interface", 8, 55)
                return
            else:
                self.d.msgbox("Please enter a valid netmask address")

    def editIpmiGatewayIP(self):
        """ Edit the statically set IPMI gateway IP address """
        logging.debugv("menu/config.py->editIpmiGatewayIP(self)", [])
        gw = self.c.getIpmiGatewayIP()
        while True:
            output = self.d.inputbox("IPMI gateway IP address", 10, 50, gw)
            if output[0]: return
            if t.ipv4check(output[1]):
                gw = output[1]
                try:
                    f.ipmiSetNet(["defgw", "ipaddr", gw])
                    logging.debug("Setting IPMI gateway address to %s" % (gw))
                    self.c.ipmi["gwip"] = gw
                    self.c.ipmi.write()
                except excepts.RunException:
                    self.d.msgbox("Could not set the gateway IP address for the IPMI interface", 8, 60)
                return
            else:
                self.d.msgbox("Please enter a valid IP address")

    def editIpmiGatewayMAC(self):
        """ Edit the statically set IPMI gateway MAC address """
        logging.debugv("menu/config.py->editIpmiGatewayMAC(self)", [])
        gwmac = self.c.getIpmiGatewayMAC()
        while True:
            output = self.d.inputbox("IPMI gateway MAC address", 10, 50, gwmac)
            if output[0]: return
            if t.macCheck(output[1]):
                gwmac = output[1]
                try:
                    f.ipmiSetNet(["defgw", "macaddr", gwmac])
                    logging.debug("Setting IPMI gateway MAC address to %s" % (gwmac))
                    self.c.ipmi["gwmac"] = gwmac
                    self.c.ipmi.write()
                except excepts.RunException:
                    self.d.msgbox("Could not set the gateway MAC address for the IPMI interface", 8, 60)
                return
            else:
                self.d.msgbox("Please enter a valid MAC address")

    def editIpmiVlanID(self):
        """ Edit the statically set IPMI VLAN ID """
        logging.debugv("menu/config.py->editIpmiVlanID(self)", [])
        vlanid = self.c.getIpmiVlanID()
        while True:
            output = self.d.inputbox("IPMI VLAN ID", 10, 50, vlanid)
            if output[0]: return
            if output[1]:
                vlanid = output[1]
                try:
                    if vlanid == 0:
                        f.ipmiSetNet(["vlan", "id", "off"])
                    else:
                        f.ipmiSetNet(["vlan", "id", vlanid])
                    logging.debug("Setting IPMI VLAN ID to %s" % (vlanid))
                    self.c.ipmi["vlanid"] = vlanid
                    self.c.ipmi.write()
                except excepts.RunException:
                    self.d.msgbox("Could not set the VLAN ID for the IPMI interface", 8, 60)
                return

    def editIpmiUsers(self):
        """ Edit the statically set IPMI VLAN ID """
        logging.debugv("menu/config.py->editIpmiUsers(self)", [])

        choices = f.ipmiUserList()
        choices += [("Add", "Add a new user")]
        choice = self.d.menu("Edit IPMI users", choices=choices, cancel="back")
        if choice[0]: return
        elif choice[1] == "Add":
            self.addIpmiUser()
#            self.editIpmiUsers()
        else:
            self.editIpmiUser(choice[1])
#            self.editIpmiUsers()
        return

    def editIpmiUser(self, id):
        """ Edit a single IPMI user """
        logging.debugv("menu/config.py->editIpmiUser(self)", [])

        user = f.getIpmiUser(id)
        (level, privtext) = f.getIpmiUserPriv(id)

        choices = [
                    ("Username", "Edit the username [%s]" % str(user)),
                    ("Password", "Edit the password"),
                    ("Privilege", "Edit the privilege level [%s]" % str(privtext)),
                    ("Delete", "Delete this user")
                ]
        choice = self.d.menu("Edit IPMI user: %s" % str(user), choices=choices, cancel="back")
        if choice[0]: return
        elif choice[1] == "Username": self.editIpmiUserName(id)
        elif choice[1] == "Password": self.editIpmiUserPass(id)
        elif choice[1] == "Privilege": self.editIpmiUserPriv(id)
        elif choice[1] == "Delete": self.delIpmiUser(id)
        self.editIpmiUser(id)

    def editIpmiUserPriv(self, id):
        """ Edit the privilege level of an IPMI user """
        logging.debugv("menu/config.py->editIpmiUserPriv(self, id)", [id])

        (level, privtext) = f.getIpmiUserPriv(id)

        choices = [
                    ("0", "NO ACCESS", int(level==0)),
                    ("1", "CALLBACK", int(level==1)),
                    ("2", "USER", int(level==2)),
                    ("3", "OPERATOR", int(level==3)),
                    ("4", "ADMINISTRATOR", int(level==4))
                ]
        choice = self.d.radiolist("Edit IPMI user privilege", choices=choices, cancel="back")
        if choice[0]: return
        elif choice[1]:
            f.ipmiUserPriv(id, choice[1])
            self.editIpmiUser(id)

    def editIpmiUserPass(self, id):
        """ Edit the password for a given user """
        logging.debugv("menu/config.py->editIpmiUserPass(self, id)", [id])

        output = self.d.inputbox("Enter password for this user:", 10, 50)
        if output[0]: return
        elif output[1] != "":
            check = self.d.inputbox("Re-enter password for this user:", 10, 50)
            if output[0]: return
            elif check[1] != output[1]:
                self.d.msgbox("Passwords didn't match, not saving password.")
                self.editIpmiUser(id)
            elif check[1] == output[1]:
                f.ipmiUserPassEdit(id, check[1])
                self.editIpmiUser(id)
        elif output[1] == "":
            self.d.editIpmiUserPass(id)
        else: return
                

    def editIpmiUserName(self, id):
        """ Edit the username for an IPMI user """
        logging.debugv("menu/config.py->editIpmiUserName(self, id)", [id])

        username = f.getIpmiUser(id)

        output = self.d.inputbox("Edit username:", 10, 50, username)
        if output[0]: return
        elif output[1] != "":
            f.ipmiUserNameEdit(id, output[1])
            return
        else:
            self.editIpmiUser(id)

    def delIpmiUser(self, id):
        """ Ask for confirmation for deleting a given IPMI user """
        logging.debugv("menu/config.py->delIpmiUser(self, id)", [id])

        output = self.d.yesno("Are you sure you want to delete this user?")
        if int(output) == 0:
            f.ipmiUserDel(id)
            self.editIpmiUsers()
        else: self.editIpmiUsers()

    def addIpmiUser(self):
        """ Add a new IPMI user """
        logging.debugv("menu/config.py->addIpmiUser(self)", [])

        output = self.d.inputbox("New username:", 10, 50, "")
        if output[0]: return
        elif output[1] != "":
            f.ipmiUserAdd(output[1])
            return
        else:
            self.addIpmiUser()

    def setNetwork(self):
        """ Submenu for choosing a sensor type """
        logging.debugv("menu/config.py->setNetwork(self)", [])
        type = self.c.getSensorType()
        choices = [
                    ("Normal", "Normal sensor", int(type=="normal")),
                    ("Vlan", "VLAN sensor", int(type=="vlan")),
                ]

        choice = self.d.radiolist("Select the type of sensor", choices=choices, cancel="back")
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
        choices = [(x,self.c.chkInfType(x), int(self.c.chkInfType(x)!="disabled")) for x in infs]
        choice = self.d.radiolist("Select the main interface (use space to select)", choices=choices, cancel="back")
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
            if self.c.netconf['sensortype'] == "normal":
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


