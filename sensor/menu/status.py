 
import logging
import os
import pdb
import configobj

from sensor import functions as f
from sensor import config
from sensor import version
from sensor import tools as t
from sensor import excepts

class Status:
    def __init__(self, d):
        logging.debugv("menu/status.py->__init__(self, d)", [])
        self.d = d
        self.c = config.Config()

    def run(self):
        """ Submenu showing the different status overviews """
        logging.debugv("menu/status.py->run(self)", [])
        choices=[
                ("Sensor", "General information about the sensor"),
                ("Netconf", "Network configuration info"),
                ("Interfaces", "Interface information"),
            ]
        if f.ipmiStatus():        
            choices += [("IPMI", "IPMI information")]

        title = "\\ZbStart > Status\\n\\ZB"
        subtitle = "Which status overview do you want to see?"
        title += subtitle
        choice = self.d.menu(title, choices=choices, cancel="Back", colors=1)

        # cancel
        if choice[0] == 1:
            return
        elif choice[1] == "Sensor": self.sensor()
        elif choice[1] == "Netconf": self.netconf()
        elif choice[1] == "Interfaces": self.interfaces()
        elif choice[1] == "IPMI": self.ipmi()
        self.run()

    def interfaces(self):
        """ Prints information about the actual network interfaces """
        logging.debugv("menu/status.py->interfaces(self)", [])

        infList = f.ifList()

        report = t.formatTitle("Network interfaces")
        for (inf) in infList:
            status = infStatus(inf)
            if status == 0:
                statustxt = "Non-existant"
            elif status == 1:
                statustxt = "Down"
            elif status == 2:
                statustxt = "Up"
            elif status == 3:
                statustxt = "Up, configured"
            report += t.formatLog("Interface", inf)
            report += t.formatLog("  Status", statustxt)
            if status != 0:
                try:
                    mac = f.getMac(inf)
                except excepts.InterfaceException:
                    mac = "false"
                report += t.formatLog("    MAC", mac)
            if status == 3:
                ip = f.getIp(inf)
                nm = f.getNm(inf)
                bc = t.broadcast(ip, nm)
                gw = f.getGw(inf)
                if ip: report += t.formatLog("    Address", ip)
                if nm: report += t.formatLog("    Netmask", nm)
                if bc: report += t.formatLog("    Broadcast", bc)
                if gw: report += t.formatLog("    Gateway", gw)
            if status != 0:
                active_flags = f.getIfFlags(inf)
                report += t.formatLog("    Flags", active_flags)
            report += "\n"

        return self.d.msgbox(report, width=100, height=40, no_collapse=1, colors=1)
        
    def netconf(self):
        """ Prints the network configuration as saved in the config file """
        logging.debugv("menu/status.py->netconf(self)", [])
        infs = self.r.listInf()
        report = t.formatTitle("Main network configuration")

        try:
            self.c.validNetConf()
        except excepts.ConfigException, e:
            e = str(e)
            e = e.strip('"')
            report += t.formatLog("Valid network config", False, 1)
            report += "    %s\n" % str(e)
        else:
            report += t.formatLog("Valid network config", True, 1)

        report += "\n"
        sensorType = self.c.getSensorType()
        if sensorType == "":
            report += t.formatLog("Sensor type", "Not configured")
        else:
            report += t.formatLog("Sensor type", sensorType)
        report += "\n"

        # Only use the first interface that is configured
        try:
            manInf = self.c.getMainIf()
            if manInf == "":
                manInf = "Not configured"
                manInfConf = "Not configured"
                manInfType = "Not configured"
            else:
                manInfConf = self.c.getIf(manInf)
                manInfType = manInfConf['type']
        except excepts.InterfaceException:
            logging.warning("No active interface configuration found")
            manInf = "Not configured"
            manInfConf = "Not configured"
            manInfType = "Not configured"

        report += t.formatLog("Main network interface", manInf)
        report += t.formatLog("  Configuration", manInfType)

        if manInfType == "static":
            ip = manInfConf['address']
            bc = manInfConf['broadcast']
            nm = manInfConf['netmask']
            gw = manInfConf['gateway']
            tn = manInfConf['tunnel']
            (dnsType, prim, sec) = self.c.getDNS()

            report += t.formatLog("    IP address", ip)
            report += t.formatLog("    Netmask", nm)
            report += t.formatLog("    Broadcast address", bc)
            report += t.formatLog("    Gateway", gw)
            report += t.formatLog("    Endpoint IP address", tn)
            report += "\n"
            report += t.formatLog("    DNS configuration type", dnsType)
            if dnsType != "dhcp":
                report += t.formatLog("    Primary DNS", prim)
                report += t.formatLog("    Secondary DNS", sec)

        report += "\n"
        if self.c.netconf['sensortype'] == "vlan":
            trunk = self.c.getTrunkIf()
            report += t.formatLog("Trunk network interface", trunk)
            for (vlan, vlanConf) in self.c.getVlans().items():
                try:
                    desc = vlanConf['description']
                except KeyError:
                    desc = ""
                try:
                    vlanID = vlanConf['vlanid']
                except KeyError:
                    vlanID = "False"
                try:
                    vlanType = vlanConf['type']
                except KeyError:
                    vlanType = "False"

                report += "  VLAN%s\n" % vlan
                report += t.formatLog("    Description", desc)
                report += t.formatLog("    VLAN ID", vlanID)
                report += t.formatLog("    Configuration", vlanType)
                if vlanType == "static":
                    report += t.formatLog("      IP address", vlanConf['tunnel'])
                    report += t.formatLog("      Netmask", vlanConf['netmask'])
                    report += t.formatLog("      Broadcast", vlanConf['broadcast'])
                    report += t.formatLog("      Gateway", vlanConf['gateway'])

        report += "\n"
        return self.d.msgbox(report, width=70, height=40, no_collapse=1, colors=1)


    def sensor(self):
        """ Prints information about the sensor status """
        logging.debugv("menu/status.py->sensor(self)", [])
        sid = self.c.getSensorID()
        mainInf = self.c.getMainIf()
        status = f.tunnelStatus()
        networkStatus = f.networkStatus(mainInf)
        pversion = f.getPackageVersion()

        # Subtitle
        report = t.formatTitle("General sensor info")

        # Package version
        report += t.formatLog("Package version", str(pversion))

        # Sensor name
        report += t.formatLog("Sensor", sid)

        # Sensor status
        report += t.formatLog("Status", status, 1)

        # Network status
        report += t.formatLog("Network", networkStatus, 1)

        report += "\n"

        # Subtitle
        report += t.formatTitle("Sanity checks")

        if networkStatus:
            # OpenVPN port check
            ovnport = f.scanPort(self.c.getServer(), 1194)
            report += t.formatLog("OpenVPN port", ovnport, 1)

            # Updates port check
            upport = f.scanPort(self.c.getServer(), 4443)
            report += t.formatLog("Updates port", upport, 1)
        else:
            report += t.formatLog("OpenVPN port", "Unchecked")
            report += t.formatLog("Updates port", "Unchecked")

        # Check crt existance
        report += t.formatLog("Sensor certificate", f.verifyCrt(), 1)
        # Check key existance
        report += t.formatLog("Sensor key", f.verifyKey(), 1)

        report += "\n"

        # Subtitle
        report += t.formatTitle("Program checks")

        # Check SSH status
        report += t.formatLog("SSH daemon running", f.sshStatus(), 1)

        if status:
            # Checking OpenVPN daemon
            report += t.formatLog("OpenVPN daemon running", f.openvpnStatus(), 1)

        return self.d.msgbox(report, width=70, height=25, no_collapse=1, colors=1)

    def ipmi(self):
        """ Status overview of the configured IPMI interface """
        info = f.ipmiLanStatus()
        report = t.formatTitle("IPMI interface info")

        report += t.formatLog("IP address", info["IP Address"])
        report += t.formatLog("Subnet Mask", info["Subnet Mask"])
        report += t.formatLog("MAC address", info["MAC Address"])
        report += "\n"
        report += t.formatLog("Gateway IP address", info["Default Gateway IP"])
        report += t.formatLog("Gateway MAC address", info["Default Gateway MAC"])
        if self.c.getIpmiVlanID():
            report += "\n"
            report += t.formatLog("VLAN ID", self.c.ipmi["vlanid"])

        return self.d.msgbox(report, width=70, height=25, no_collapse=1, colors=1)
