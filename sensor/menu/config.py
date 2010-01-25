 
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
                ("Network", "Configure network..."),
            ]

        if f.ipmiStatus():
            choices += [
                ("IPMI", "Configure IPMI...")
                ]

        choices += [
                ("DNS", "Nameservers settings..."),
                ("Admin", "Administrator menu..."),
                ('AutoStart', self.c.getAutoStart()),
                ('Loglevel', self.c.getLogLevel() ),
            ]

        title = "\\ZbStart > Configure\\n\\ZBSelect the item you want to configure"
        choice = self.d.menu(title, choices=choices, cancel="Back", menu_height=10, colors=1, width=60)

        # cancel 
        if choice[0] == 1: return
        elif choice[1] == "Network": self.configNetwork()
        elif choice[1] == "IPMI": self.setIpmi()
        elif choice[1] == "DNS": self.dns()
        elif choice[1] == "Admin": self.chkAdmin()
        elif choice[1] == "Loglevel": self.setLogLevel()
        elif choice[1] == "AutoStart":
            if self.c.getAutoStart() == "Enabled":
                self.disableAutoStart()
            else:
                self.enableAutoStart()
        self.run()

###############################################
###############################################

    def configNetwork(self):
        """ GUI rebuild of network configuration screen """
        logging.debugv("menu/config.py->configNetwork(self)", [])

        # ITEM - Sensor Type
        sensorType = self.c.getSensorType()
        choices = t.formatMenuItem("Sensor type", sensorType)

        # Some autoconfig stuff here
        # Set the main interface if there's only 1 interface
        totalInfs = f.ifList()
        if len(totalInfs) == 1:
            logging.debug("Auto configuration: Setting mainIf to %s" % str(totalInfs[0]))
            self.c.setMainIf(totalInfs[0])

        # ITEM - Main Interface
        mainIf = self.c.getMainIf()
        choices += t.formatMenuItem("Main interface", mainIf)

        # ITEM - Trunk Interface
        if sensorType == "vlan":
            trunkIf = self.c.getTrunkIf()
            if trunkIf == mainIf and trunkIf != "":
                choices += t.formatMenuItem("Trunk interface", trunkIf, False)
            else:
                choices += t.formatMenuItem("Trunk interface", trunkIf)
            # ITEM - Number of vlans
            totalVlans = self.c.getTotalVlans()
            choices += t.formatMenuItem("Number of VLANs", str(totalVlans))

        # ITEM - Main interface - IP config
        if mainIf != "":
            infType = self.c.getIf(mainIf)["type"]
            choices += t.formatMenuItem("IP config - %s" % str(mainIf), infType, self.c.validInfConf("normal", mainIf, 0))

        # ITEMs - VLANS
        if sensorType == "vlan":
            for (vlan, vlanConf) in self.c.getVlans().items():
                vlanID = vlanConf["vlanid"]
                if vlanID == "":
                    vlanID = "Unknown-%s" % str(vlan)
                    vlanType = ""
                    vlanDesc = ""
                else:
                    vlanType = vlanConf["type"]
                    vlanDesc = vlanConf["description"]
                choices += t.formatMenuItem("Config vlan %s" % str(vlanID), vlanType, self.c.validInfConf("vlan", vlan, 0))

        title = "\\ZbStart > Configure > Network\\n\\ZBSelect the item you want to (re-)configure"
        choice = self.d.menu(title, choices=choices, cancel="Back", ok_label="Edit", colors=1, height=20, menu_height=12)
        if choice[0] == 1: 
            try:
                self.c.validNetConf()
            except excepts.ConfigException, err:
                self.invalidNetConfAction(err)
                return
            else:
                if self.changed:
                    self.c.addRev()
                    f.backupNetConf(self.c.getRev())
                    self.activateChoice()
                return
        elif choice[1] == "Sensor type": self.setSensorType()
        elif choice[1] == "Main interface": self.setMainIf()
        elif choice[1] == "IP config - %s" % str(mainIf):
            try:
                infType = self.c.getIf(mainIf)["type"]
            except KeyError:
                self.setIfType(mainIf)
            if not infType == "static":
                self.setIfType(mainIf)
            self.setIfConfig(mainIf)
        elif choice[1] == "Trunk interface": self.setTrunkIf()
        elif choice[1] == "Number of VLANs": self.setTotalVlans()
        else:
            # handle vlans here
            temp = choice[1].split()
            if temp[2].startswith("Unknown"):
                unknown = temp[2]
                # Retrieving vlanIndex from menu item
                # Basically:
                #  find string -
                #  move index + 1
                #  give me substring from current index to end of string
                vlanIndex = unknown[unknown.index("-")+1:len(unknown)]
                self.setVlanConfig(vlanIndex)
            else:
                vlanID = temp[len(temp) - 1]
                vlanIndex = self.c.getVlanIndexByID(vlanID)
                self.setVlanConfig(vlanIndex)

        self.configNetwork()


    def setSensorType(self):
        """ Submenu for choosing a sensor type """
        logging.debugv("menu/config.py->setSensorType(self)", [])
        type = self.c.getSensorType()
        choices = [
                    ("Normal", "Normal sensor", int(type=="normal")),
                    ("Vlan", "VLAN sensor", int(type=="vlan")),
                ]

        title = "\\ZbStart > Configure > Network > Sensor type\\n\\ZBSelect the type of sensor"
        choice = self.d.radiolist(title, choices=choices, cancel="Cancel", ok_label="Ok", height=20, colors=1)
        if choice[0] == 1: return
        elif choice[1] == "Normal":
            self.c.netconf['sensortype'] = "normal"
            self.c.resetTrunk()
            self.c.netconf.write()
            self.changed = True
            return                  # returns to configNetwork()
        elif choice[1] == "Vlan":
            self.c.netconf['sensortype'] = "vlan"
            self.c.netconf.write()
            self.changed = True
            return                  # returns to configNetwork()
        return                      # returns to configNetwork()


    def setMainIf(self):
        """ Submenu for choosing the main interface """
        logging.debugv("menu/config.py->setMainIf(self)", [])

        title = "\\Zb... > Configure > Network > Setup main interface\\n\\ZB"
        title += "Select the main interface"

        infs = f.ifList()
        choices = [(x, self.c.chkInfType(x), int(self.c.getMainIf() == x)) for x in infs]
        choice = self.d.radiolist(title, choices=choices, cancel="Back", ok_label="Ok", height=20, colors=1)
        if choice[0] == 1: return           # returns to configNetwork()
        else:
            self.c.setMainIf(choice[1])
            self.changed = True
        return                              # returns to configNetwork()


    def setTrunkIf(self):
        """ Submenu for choosing the trunk interface """
        logging.debugv("menu/config.py->setTrunkIf(self)", [])

        title = "\\Zb... > Configure > Network > Setup trunk interface\\n\\ZB"
        title += "Select the trunk interface"

        infs = self.c.getInfs()
        choices = [(x, self.c.chkInfType(x), int(self.c.getTrunkIf() == x)) for x in infs]
        choice = self.d.radiolist(title, choices=choices, cancel="Back", ok_label="Ok", height=20, colors=1)
        if choice[0] == 1: return           # returns to configNetwork()
        else:
            if choice[1] == self.c.getMainIf():
                self.d.msgbox("The trunk interface cannot be the same as the main interface!")
            else:
                logging.info("Setting trunk interface to %s" % interface)
                self.c.setTrunk(choice[1])
                self.changed = True
        return                              # returns to configNetwork()


    def setIfConfig(self, inf):
        """ Submenu for configuring a specific interface """
        logging.debugv("menu/config.py->setIfConfig(self, inf)", [inf])

        infConf = self.c.getIf(inf)

        choices = t.formatMenuItem("Type", infConf["type"])
        if infConf["type"] == "static":
            choices += t.formatMenuItem("Local IP address", infConf["address"])
            if self.c.getSensorType() == "normal":
                choices += t.formatMenuItem("Endpoint IP address", infConf["tunnel"])
            choices += t.formatMenuItem("Netmask", infConf["netmask"])
            choices += t.formatMenuItem("Gateway", infConf["gateway"])
            choices += t.formatMenuItem("Broadcast", infConf["broadcast"])

        title = "\\Zb... > Configure > Network > IP config %s\\n\\ZBSelect the item you want to (re-)configure" % str(inf)
        choice = self.d.menu(title, choices=choices, cancel="Back", ok_label="Edit", height=20, colors=1)
        if choice[0] == 1: return
        elif choice[1] == "Type":
            self.setIfType(inf)
            self.setIfConfig(inf)           # Make sure setIfConfig() is loaded after setIfType()
        elif choice[1] == "Local IP address":
            self.popupIfConfig("address", inf)
            self.setIfConfig(inf)           # Make sure setIfConfig() is loaded after popupIfConfig()
        elif choice[1] == "Endpoint IP address":
            self.popupIfConfig("tunnel", inf)
            self.setIfConfig(inf)           # Make sure setIfConfig() is loaded after popupIfConfig()
        elif choice[1] == "Netmask":
            self.popupIfConfig("netmask", inf)
            self.setIfConfig(inf)           # Make sure setIfConfig() is loaded after popupIfConfig()
        elif choice[1] == "Gateway":
            self.popupIfConfig("gateway", inf)
            self.setIfConfig(inf)           # Make sure setIfConfig() is loaded after popupIfConfig()
        elif choice[1] == "Broadcast":
            self.popupIfConfig("broadcast", inf)
            self.setIfConfig(inf)           # Make sure setIfConfig() is loaded after popupIfConfig()

        return                  # returns to configNetwork()


    def setVlanConfig(self, vlanIndex):
        """ Submenu for configuring a specific vlan """
        logging.debugv("menu/config.py->setVlanConfig(self, vlanIndex)", [vlanIndex])

        vlanConf = self.c.getVlan(vlanIndex)

        choices = t.formatMenuItem("VLAN ID", vlanConf["vlanid"])
        if vlanConf["vlanid"] != "":
            choices += t.formatMenuItem("Type", vlanConf["type"])
            choices += t.formatMenuItem("Description", vlanConf["description"])
            if vlanConf["type"] == "static":
                choices += t.formatMenuItem("Endpoint IP address", vlanConf["tunnel"])
                choices += t.formatMenuItem("Netmask", vlanConf["netmask"])
                choices += t.formatMenuItem("Gateway", vlanConf["gateway"])
                choices += t.formatMenuItem("Broadcast", vlanConf["broadcast"])

        vlanID = vlanConf["vlanid"]
        if vlanID == "":
            vlanID = "Unknown-%s" % str(vlanIndex)

        title = "\\Zb... > Network > VLAN config %s\\n\\ZBSelect the item you want to (re-)configure" % str(vlanID)
        choice = self.d.menu(title, choices=choices, cancel="Back", ok_label="Edit", height=20, colors=1)
        if choice[0] == 1: return
        elif choice[1] == "VLAN ID":
            self.setVlanID(vlanIndex)
            self.setVlanConfig(vlanIndex)           # Make sure setVlanConfig() is loaded after setIfType()
        elif choice[1] == "Type":
            self.setVlanType(vlanIndex, vlanID)
            self.setVlanConfig(vlanIndex)           # Make sure setVlanConfig() is loaded after setVlanType()
        elif choice[1] == "Description":
            self.setVlanDesc(vlanIndex, vlanID)
            self.setVlanConfig(vlanIndex)           # Make sure setVlanConfig() is loaded after setVlanDesc()
        elif choice[1] == "Local IP address":
            self.popupVlanConfig("address", vlanIndex, vlanID)
            self.setVlanConfig(vlanIndex)           # Make sure setVlanConfig() is loaded after popupVlanConfig()
        elif choice[1] == "Endpoint IP address":
            self.popupVlanConfig("tunnel", vlanIndex, vlanID)
            self.setVlanConfig(vlanIndex)           # Make sure setVlanConfig() is loaded after popupVlanConfig()
        elif choice[1] == "Netmask":
            self.popupVlanConfig("netmask", vlanIndex, vlanID)
            self.setVlanConfig(vlanIndex)           # Make sure setVlanConfig() is loaded after popupVlanConfig()
        elif choice[1] == "Gateway":
            self.popupVlanConfig("gateway", vlanIndex, vlanID)
            self.setVlanConfig(vlanIndex)           # Make sure setVlanConfig() is loaded after popupVlanConfig()
        elif choice[1] == "Broadcast":
            self.popupVlanConfig("broadcast", vlanIndex, vlanID)
            self.setVlanConfig(vlanIndex)           # Make sure setVlanConfig() is loaded after popupVlanConfig()

        return                  # returns to configNetwork()


    def setVlanType(self, vlanIndex, vlanID):
        """ Submenu for setting the type of an VLAN interface """
        logging.debugv("menu/config.py->setVlanType(self, vlanIndex, vlanID)", [vlanIndex, vlanID])
        title = "\\Zb... > Network > VLAN %s > Type\\n\\ZB" % str(vlanID)
        subtitle = "Set the type of configuration for this VLAN interface"
        title += subtitle
        vlanConf = self.c.getVlan(vlanIndex)
        vlanType = vlanConf["type"]

        choices = [
                    ("DHCP", "Automatic configuration by DHCP", int(vlanType=="dhcp")),
                    ("Static", "Static configuration", int(vlanType=="static")),
                    ("Disabled", "Disable this interface", int(vlanType=="disabled")),
                ]
        choice = self.d.radiolist(title, choices=choices, ok_label="Ok", height=20, colors=1)
        if choice[0] == 1: return
        elif choice[1] == "DHCP":
            self.c.setVlanProp(vlanIndex, "type", "dhcp")
            self.c.netconf.write()
            self.changed = True
            return                  # returns to setVlanConfig()
        elif choice[1] == "Static":
            self.c.setVlanProp(vlanIndex, "type", "static")
            self.c.netconf.write()
            self.changed = True
            return                  # returns to setVlanConfig()
        elif choice[1] == "Disabled":
            self.c.setVlanProp(vlanIndex, "type", "disabled")
            self.c.netconf.write()
            self.changed = True
            return                  # returns to setVlanConfig()
        return                      # returns to setVlanConfig()


    def setVlanID(self, vlanIndex):
        """ Submenu for setting the ID of a VLAN interface """
        logging.debugv("menu/config.py->setVlanID(self, vlanIndex)", [vlanIndex])

        vlanConf = self.c.getVlan(vlanIndex)
        vlanID = vlanConf["vlanid"]

        if vlanID == "":
            title = "\\Zb... > Network > VLAN Unknown-%s > VLAN ID\\n\\ZB" % str(vlanIndex)
        else:
            title = "\\Zb... > Network > VLAN %s > VLAN ID\\n\\ZB" % str(vlanID)
        subtitle = "Set the VLAN ID for this VLAN interface"
        title += subtitle

        while True:
            output = self.d.inputbox(title, 10, 50, vlanID, colors=1, ok_label="Ok")
            if output[0]: return
            else:
                if output[1].isdigit() and str(output[1]) != '0':
                    vlanID = output[1]
                    if not self.c.chkVlanID(vlanID, vlanIndex):
                        self.c.changed = True
                        self.c.setVlanProp(vlanIndex, "vlanid", output[1])
                        self.changed = True
                        return                  # returns to setVlanConfig()
                    else:
                        self.d.msgbox("VLAN ID already in use!")
                else:
                    self.d.msgbox("Please enter a valid integer between 0 and 4095!")
        


    def setIfType(self, inf):
        """ Submenu for setting the type of an interface """
        logging.debugv("menu/config.py->setIfType(self, inf)", [inf])
        title = "\\Zb... > Network > IP config %s > Type\\n\\ZB" % str(inf)
        subtitle = "Set the type of configuration for this interface"
        infConf = self.c.getIf(inf)
        infType = infConf["type"]

        choices = [
                    ("DHCP", "Automatic configuration by DHCP", int(infType=="dhcp")),
                    ("Static", "Static configuration", int(infType=="static")),
                    ("Disabled", "Disable this interface", int(infType=="disabled")),
                ]
        choice = self.d.radiolist(title, choices=choices, ok_label="Ok", height=20, colors=1)
        if choice[0] == 1: return
        elif choice[1] == "DHCP":
            self.c.setIfProp(inf, "type", "dhcp")
            self.c.netconf.write()
            self.changed = True

            # Do some auto configuration
            # If this interface = mainIf, set DNS to dhcp as well
            if self.c.getMainIf() == inf:
                self.c.setDNS()

            return                  # returns to setIfConfig()
        elif choice[1] == "Static":
            self.c.setIfProp(inf, "type", "static")
            self.c.netconf.write()
            self.changed = True
            return                  # returns to setIfConfig()
        elif choice[1] == "Disabled":
            self.c.setIfProp(inf, "type", "disabled")
            self.c.netconf.write()
            self.changed = True
            return                  # returns to setIfConfig()
        return                      # returns to setIfConfig()


    def popupIfConfig(self, type, inf):
        """ Dialog window to input IP addresses for an interface configuration """
        logging.debugv("menu/config.py->popupIfConfig(self, type, inf)", [type, inf])

        infConf = self.c.getIf(inf)
        savedInput = infConf[type]

        if type == "address":
            title = "\\Zb... > Network > IP config %s > Local IP\\n\\ZB" % str(inf)
            subtitle = "Enter the IP address of the local interface"
        elif type == "tunnel":
            title = "\\Zb... > Network > IP config %s > Endpoint IP\\n\\ZB" % str(inf)
            subtitle = "Enter the IP address of the endpoint interface"
        elif type == "netmask":
            title = "\\Zb... > Network > IP config %s > Subnet mask\\n\\ZB" % str(inf)
            subtitle = "Enter the subnet mask address of the local interface"
        elif type == "gateway":
            title = "\\Zb... > Network > IP config %s > Gateway\\n\\ZB" % str(inf)
            subtitle = "Enter the gateway address of the local interface"
        elif type == "broadcast":
            title = "\\Zb... > Network > IP config %s > Broadcast\\n\\ZB" % str(inf)
            subtitle = "Enter the broadcast address of the local interface"
        title += subtitle

        while True:
            output = self.d.inputbox(title, 10, 50, savedInput, colors=1, ok_label="Ok")
            if output[0]: return
            if t.ipv4check(output[1]):
                address = output[1]
                logging.info("Setting %s for %s to %s" % (type, inf, output[1]))
                self.changed = True
                self.c.setIfProp(inf, type, output[1])
                self.changed = True
                return                  # returns to setIfConfig()
            else:
                self.d.msgbox("Please enter a valid address")


    def popupVlanConfig(self, type, vlanIndex, vlanID):
        """ Dialog window to input IP addresses for a VLAN configuration """
        logging.debugv("menu/config.py->popupIfConfig(self, type, vlanIndex, vlanID)", [type, vlanIndex, vlanID])

        vlanConf = self.c.getVlan(vlanIndex)
        savedInput = vlanConf[type]

        if type == "tunnel":
            title = "\\Zb... > Network > VLAN %s > Local IP\\n\\ZB" % str(vlanID)
            subtitle = "Enter the IP address of the VLAN interface"
        elif type == "netmask":
            title = "\\Zb... > Network > VLAN %s > Subnet mask\\n\\ZB" % str(vlanID)
            subtitle = "Enter the subnet mask address of the local interface"
        elif type == "gateway":
            title = "\\Zb... > Network > VLAN %s > Gateway\\n\\ZB" % str(vlanID)
            subtitle = "Enter the gateway address of the local interface"
        elif type == "broadcast":
            title = "\\Zb... > Network > VLAN %s > Broadcast\\n\\ZB" % str(vlanID)
            subtitle = "Enter the broadcast address of the local interface"
        title += subtitle

        while True:
            output = self.d.inputbox(title, 10, 50, savedInput, colors=1, ok_label="Ok")
            if output[0]: return
            if t.ipv4check(output[1]):
                address = output[1]
                logging.info("Setting %s for %s to %s" % (type, vlanID, output[1]))
                self.changed = True
                self.c.setVlanProp(vlanIndex, type, output[1])
                self.changed = True
                return                  # returns to setVlanConfig()
            else:
                self.d.msgbox("Please enter a valid address")

    def setVlanDesc(self, vlanIndex, vlanID):
        """ Dialog window to input the description (label) of the VLAN """
        logging.debugv("menu/config.py->setVlanDesc(self, vlanIndex, vlanID)", [vlanIndex, vlanID])

        title = "\\Zb... > Network > VLAN %s > Description\\n\\ZB" % str(vlanID)
        subtitle = "Enter the description of the VLAN interface"
        title += subtitle

        desc = self.c.getVlan(vlanIndex)["description"]

        output = self.d.inputbox(title, 10, 50, desc, colors=1)
        if output[0]: return            # returns to setVlanConfig()
        else:
            logging.debug("Setting description for VLAN %s to %s" % (str(vlanID), str(desc)))
            self.c.setVlanProp(vlanIndex, "description", output[1])
            self.changed = True
            return                      # returns to setVlanConfig()


    def setTotalVlans(self):
        """ Edit the amount of VLANs that need to be configured """
        logging.debugv("menu/config.py->setTotalVlans(self)", [])

        title = "\\ZbConfig > Network > VLANs\\n\\ZB"
        subtitle = "Enter the number of vlans you want to use"
        vlannum = self.c.getTotalVlans()
        while True:
            output = self.d.inputbox(title, 10, 50, str(vlannum), colors=1)
            if output[0] == 1: return
            else:
                if output[1].isdigit() and str(output[1]) != '0':
                    if vlannum != output[1]:
                        logging.debug("Setting number of vlans to %s" % str(output[1]))
                        # Make sure vlans are created
                        for i in range(0, int(output[1])):
                            # first entry in dict is 0
                            self.c.getVlan(i)
                            self.changed = True

                    return              # returns to configNetwork()
                else:
                    self.d.msgbox("Invalid number of VLANs. Enter a valid integer between 1 and 4095", width=60)
        return                          # returns to configNetwork()



#################################################
#################################################

    def invalidNetConfAction(self, err):
        """ Ask the user what to do about the invalid NetConf """
        logging.debugv("menu/config.py->invalidNetConfAction(self, err)", [err])
        choices = [
                ("Config", "Go back to the configuration menu"),
                ("Ignore", "Ignore this warning"),
            ]

        title = "Network configuration is invalid:\n\t%s\n\n" % str(err)
        title += "Sensor won't start until network config is fixed.\n"
        title += "What do you want to do?"
        choice = self.d.menu(title, choices=choices, menu_height=10, nocancel=1, width=60)

        if choice[0] == 1: self.invalidNetConfAction()
        elif choice[1] == "Config": self.configNetwork()
        elif choice[1] == "Ignore": return


    def invalidDNSConfAction(self):
        """ Ask the user what to do about the invalid NetConf """
        logging.debugv("menu/config.py->invalidDNSConfAction(self)", [])
        choices = [
                ("Config", "Go back to the DNS menu"),
                ("Ignore", "Ignore this warning"),
            ]

        choice = self.d.menu("Invalid DNS config!\nSensor won't start until DNS config is fixed.\nWhat do you want to do?", choices=choices, menu_height=10, nocancel=1)

        if choice[0] == 1: self.invalidDNSConfAction()
        elif choice[1] == "Config": self.dns()
        elif choice[1] == "Ignore": return


    def enableAutoStart(self):
        """ Enabling default tunnel startup """
        logging.debugv("menu/config.py->enableAutoStart(self)", [])
        self.c.setAutoStart("Enabled")

    def disableAutoStart(self):
        """ Disabling default tunnel startup """
        logging.debugv("menu/config.py->disableAutoStart(self)", [])
        self.c.setAutoStart("Disabled")

    def chkAdmin(self):
        """ Ask for password to enter the admin menu """
        logging.debugv("menu/config.py->chkAdmin(self)", [])

        choice = self.d.passwordbox("Enter admin password", 10, 50, "", insecure=1)
        if choice[0]: return
        elif self.c.validAdmin(choice[1]): self.adminMenu()
        return

    def adminMenu(self):
        """ Administrator menu """
        logging.debugv("menu/config.py->adminMenu(self)", [])

        choices=[
                ('serverurl', self.c.getServerurl()),
                ('user', self.c.getUser()),
                ('passwd', len(self.c.getPasswd())*'*'),
            ]
        choice = self.d.menu("What do you want to configure?", choices=choices, cancel="back")

        if choice[0] == 1: return
        elif choice[1] == "serverurl": self.setServerurl()
        elif choice[1] == "user": self.setUser()
        elif choice[1] == "passwd": self.setPasswd()
        self.adminMenu()


    def activateChoice(self):
        """ Choose to stop or restart sensor after changing the config """
        logging.debugv("menu/config.py->activateChoice(self)", [])
        choices = [
                ("Stop", "Stop the sensor"),
                ("Restart", "Restart the sensor"),
                ]
        choice = self.d.menu("The configuration of the sensor has changed. What would you like to do?", choices=choices, cancel="back")
        if choice[1] == "Stop":
            manage.Manage(self.d).sensorDown()
            client.saveConf()
        elif choice[1] == "Restart":
            self.d.msgbox("Stopping sensor...")
            f.sensorDown()
            client.saveConf()
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
            self.editIpmiUserPass(id)
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


    def dns(self):
        """ Submenu of network, DNS settings menu """
        logging.debugv("menu/config.py->dns(self)", [])
        (type, prim, sec) = self.c.getDNS()
        choices = [ ("Type", type) ]
        if type == "static":
            choices += [
                    ("Primary DNS server", prim),
                    ("Secondary DNS server", sec),
                ]
        title = "\\ZbStart > Configure > DNS\\n\\ZBSelect the item you want to configure"
        choice = self.d.menu(title, choices=choices, cancel="Back", ok_label="Edit", colors=1)
        if choice[0] == 1:
            try:
                self.c.validDNSConf()
            except excepts.ConfigException, err:
                self.invalidDNSConfAction()
                return
            else:
                if self.changed:
                    self.c.addRev()
                    f.backupNetConf(self.c.getRev())
                    self.activateChoice()
                return
        elif choice[1] == "Type": self.dnsType()
        elif choice[1] == "Primary DNS server": self.dnsPrim()
        elif choice[1] == "Secondary DNS server": self.dnsSec()
        self.dns()

    def dnsType(self):
        """ Set dns type (dhcp or static config """
        logging.debugv("menu/config.py->dnsType(self)", [])
        (type, prim, sec) = self.c.getDNS()
        title = "\\ZbStart > Configure > DNS > DNS type\\n\\ZBWhat type of DNS config do you want?"
        output = self.d.radiolist(title, colors=1, choices=[
            ("dhcp", "Receive DNS settings through dhcp", int(type=="dhcp")),
            ("static", "Manual configuration", int(type=="static")),
        ])
        if output[0]: return
        newtype = output[1]
        if newtype != type:
            self.changed = True
            self.c.setDNS(newtype, prim, sec)

    def dnsPrim(self):
        """ Set primary DNS server """
        logging.debugv("menu/config.py->dnsPrim(self)", [])
        (type, prim, sec) = self.c.getDNS()
        while True:
            input = self.d.inputbox("Primary DNS server:", 10, 50, prim)
            if input[0]: return
            if t.ipv4check(input[1]):
                prim = input[1]
                break
        self.changed = True
        self.c.setDNS(type, prim, sec)

    def dnsSec(self):
        """ Set secondary DNS server """
        logging.debugv("menu/config.py->dnsSec(self)", [])
        (type, prim, sec) = self.c.getDNS()
        while True:
            input = self.d.inputbox("Secondary DNS server:", 10, 50, sec)
            if input[0]: return
            if input[1] == "":
                sec = ""
                break
            elif t.ipv4check(input[1]):
                sec = input[1]
                break
        self.changed = True
        self.c.setDNS(type, prim, sec)


    def setServerurl(self):
        """ Set or edit the server URL used for updates """
        logging.debugv("menu/config.py->setServerurl(self)", [])
        url = self.c.getServerurl()
        input = self.d.inputbox("Full URL of IDS server:", init=url, width=100)
        if input[0] == 1: return
        if t.urlCheck(input[1]):
            url = input[1]
            logging.info("Setting serverurl to: %s" + str(url))
            self.changed = True
            self.c.setServerurl(url)
        else:
            self.d.msgbox("You entered an invalid URL. Make sure it ends with a forward slash.")
            self.setServerurl()

    def setUser(self):
        """ Set the https user to get updates with """
        logging.debugv("menu/config.py->setUser(self)", [])
        user = self.c.getUser()
        input = self.d.inputbox("Username for IDS server:", init=user)
        if input[0] == 1: return
        user = input[1]
        logging.info("Setting user to: " + user)
        self.changed = True
        self.c.setUser( user)

    def setPasswd(self):
        """ Set the password for the https user """
        logging.debugv("menu/config.py->setPasswd(self)", [])
#        passwd = self.c.get("passwd")
        passwd = self.c.getPasswd()
        input = self.d.passwordbox("Passwd IDS server:", init=passwd, insecure=1)
        if input[0] == 1: return
        passwd = input[1]
        logging.info("Setting passwd to: " + passwd)
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


