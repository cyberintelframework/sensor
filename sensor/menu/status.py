 
import logging
import os
import pdb
import configobj

from sensor import runtime
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
        self.r = runtime.Runtime()

    def run(self):
        """ Submenu showing the different status overviews """
        logging.debugv("menu/status.py->run(self)", [])
        choices=[
                ("Sensor", "General information about the sensor"),
                ("Netconf", "Network configuration info"),
                ("Interfaces", "Interface information"),
                ("Version", "Version information"),
                ("Debug", "Debug information"),
            ]
        if f.ipmiStatus():        
            choices += [("IPMI", "IPMI information")]

        choice = self.d.menu("Which status overview do you want to see?", choices=choices, cancel="back")

        # cancel
        if choice[0] == 1:
            return
        elif choice[1] == "Sensor": self.sensor()
        elif choice[1] == "Netconf": self.netconf()
        elif choice[1] == "Interfaces": self.interfaces()
        elif choice[1] == "Version": self.version()
        elif choice[1] == "Debug": self.debug()
        elif choice[1] == "IPMI": self.ipmi()
#        elif choice[1] == "NewConfig": self.networkConfig()
        self.run()

    def interfaces(self):
        """ Prints information about the actual network interfaces """
        logging.debugv("menu/status.py->interfaces(self)", [])
        infstatus = self.r.listInfStatus()
        report = t.formatTitle("Network interfaces")
        for (inf, status) in infstatus:
            status = int(status)
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
                mac = f.getMac(inf)
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
                desc = vlanConf['description']
                vlanID = vlanConf['vlanid']
                vlanType = vlanConf['type']

                report += "  VLAN%s\n" % vlan
                report += t.formatLog("    Description", desc)
                report += t.formatLog("    VLAN ID", vlanID)
                report += t.formatLog("    Configuration", vlanType)
                if vlanType == "static":
                    report += t.formatLog("      IP address", vlanConf['address'])
                    report += t.formatLog("      Netmask", vlanConf['netmask'])
                    report += t.formatLog("      Broadcast", vlanConf['broadcast'])
                    report += t.formatLog("      Gateway", vlanConf['gateway'])

        report += "\n"
        return self.d.msgbox(report, width=70, height=40, no_collapse=1, colors=1)

#    def networkConfig(self):
#        """ Prints the network configuration as saved in the config file """
#        logging.debugv("menu/status.py->netconf(self)", [])
#        infs = self.r.listInf()
#        report = t.formatTitle("Main network configuration")
#        choices = [(t.formatMenu("Sensor type"), self.c.netconf['sensortype'])]
#        choices += [("", "")]

#        # Only use the first interface that is configured
#        try:
#            manInf = self.c.getMainIf()

#            manInfConf = self.c.getIf(manInf)
#            manInfType = manInfConf['type']
#        except excepts.InterfaceException:
#            logging.warning("No active interface configuration found")
#            manInf = "None configured"
#            manInfConf = "None configured"
#            manInfType = "None"

#        choices += [(t.formatMenu("Main network interface"), manInf)]
#        choices += [(t.formatMenu("  Configuration"), manInfType)]

#        choice = self.d.menu("Network configuration", choices=choices, width=70, height=40, no_collapse=1, colors=1, cancel="back")

#        if choice[0] == 1: return
#        elif choice[1] == "Endpoint IP address": self.editTunnelIP(interface)
#        self.networkConfig()


    def sensor(self):
        """ Prints information about the sensor status """
        logging.debugv("menu/status.py->sensor(self)", [])
        sid = self.c.getSensorID()
        status = self.r.sensorStatus()
#        if self.r.sensorStatus():
#            status = self.r.config['status']['sensor']
        networkStatus = self.r.networkStatus()
#        networkStatus = self.r.config['status']['network']

        # Subtitle
        report = t.formatTitle("General sensor info")

        # Sensor name
        report += t.formatLog("Sensor", sid)

        # Sensor status
        report += t.formatLog("Status", status)

        # Network status
        report += t.formatLog("Network", networkStatus)

        report += "\n"

        # Subtitle
        report += t.formatTitle("Sanity checks")

        if networkStatus:
            # OpenVPN port check
            ovnport = f.scanPort(self.c.getServer(), 1194)
            report += t.formatLog("OpenVPN port", ovnport)

            # Updates port check
            upport = f.scanPort(self.c.getServer(), 4443)
            report += t.formatLog("Updates port", upport)
        else:
            report += t.formatLog("OpenVPN port", "Unchecked")
            report += t.formatLog("Updates port", "Unchecked")

        # Check crt existance
        report += t.formatLog("Sensor certificate", f.verifyCrt())
        # Check key existance
        report += t.formatLog("Sensor key", f.verifyKey())

        report += "\n"

        # Subtitle
        report += t.formatTitle("Program checks")

        # Check SSH status
        report += t.formatLog("SSH daemon running", f.sshStatus())

        if status:
            # Checking OpenVPN daemon
            report += t.formatLog("OpenVPN daemon running", f.openvpnStatus())

        return self.d.msgbox(report, width=70, height=25, no_collapse=1, colors=1)

    def ipmi(self):
        """ Status overview of the configured IPMI interface """
        info = f.ipmiLanStatus()
        report = t.formatTitle("IPMI interface info")

        report += t.formatLog("IP address", info["IP Address"])
        report += t.formatLog("MAC address", info["MAC Address"])
        report += t.formatLog("Subnet Mask", info["Subnet Mask"])
        report += "\n"
        report += t.formatLog("Gateway IP address", info["Default Gateway IP"])
        report += t.formatLog("Gateway MAC address", info["Default Gateway MAC"])
        if self.c.getIpmiVlanID():
            report += "\n"
            report += t.formatLog("VLAN ID", self.c.ipmi["vlanid"])

        return self.d.msgbox(report, width=70, height=25, no_collapse=1, colors=1)


    def version(self):
        logging.debugv("menu/status.py->version(self)", [])
        report = t.formatTitle("General version info")

        # Revision info
        report += t.formatLog("Revision", version.getRev())
        report += t.formatLog("Last change", version.getDate())

        report += "\n"

        # subtitle
        report += t.formatTitle("Scripts version info")

        # Scripts versions
        report += t.formatLog("client.py", f.getVer("client"))
        report += t.formatLog("config.py", f.getVer("config"))
        report += t.formatLog("dialog.py", f.getVer("dialog"))
        report += t.formatLog("excepts.py", f.getVer("excepts"))
        report += t.formatLog("log.py", f.getVer("log"))
        report += t.formatLog("runtime.py", f.getVer("runtime"))
        report += t.formatLog("tools.py", f.getVer("tools"))
        report += t.formatLog("version.py", f.getVer("version"))

        return self.d.msgbox(report, width=70, height=25, no_collapse=1, colors=1)

    def debug(self):
        """ Prints the runtime dictionary for debugging purposes """
        logging.debugv("menu/status.py->debug(self)", [])
        report = t.debugDict(self.r.config)            
        return self.d.msgbox(report, width=70, height=25, no_collapse=1, colors=1)
