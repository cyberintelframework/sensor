 
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
        choice = self.d.menu("Which status overview do you want to see?",
            choices=[
                ("Sensor", "General information about the sensor"),
                ("Netconf", "Network configuration info"),
		("Interfaces", "Interface information"),
		("Version", "Version information"),
                ("Debug", "Debug information"),
                ], cancel="back")

        # cancel
        if choice[0] == 1:
            return
        elif choice[1] == "Sensor": self.sensor()
        elif choice[1] == "Netconf": self.netconf()
	elif choice[1] == "Interfaces": self.interfaces()
        elif choice[1] == "Version": self.version()
        elif choice[1] == "Debug": self.debug()
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
                if gw: report += t.formatLog("    Gateway", gw)
                if nm: report += t.formatLog("    Netmask", nm)
                if bc: report += t.formatLog("    Broadcast", bc)
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
	report += t.formatLog("Sensor type", self.c.config['sensortype'])
	report += "\n"

	# Only use the first interface that is configured
	try:
	    manInf = f.getFirstIf(["dhcp", "static"])

	    manInfConf = self.c.getIf(manInf)
	    manInfType = manInfConf['type']
	except excepts.InterfaceException:
	    logging.warning("No active interface configuration found")
	    manInf = "None configured"
	    manInfConf = "None configured"
	    manInfType = "None"

	report += t.formatLog("Main network interface", manInf)
	report += t.formatLog("  Configuration", manInfType)

	if manInfType == "static":
	    ip = manInfConf['address']
#	    bc = manInfConf['broadcast']
	    nm = manInfConf['netmask']
	    gw = manInfConf['gateway']
	    tn = manInfConf['tunnel']
	    (dnsType, prim, sec) = self.c.getDNS()

	    report += t.formatLog("    IP address", ip)
	    report += t.formatLog("    Netmask", nm)
#	    report += t.formatLog("    Broadcast address", bc)
	    report += t.formatLog("    Gateway", gw)
	    report += t.formatLog("    Endpoint IP address", tn)
	    report += "\n"
	    report += t.formatLog("    DNS configuration type", dnsType)
	    if dnsType != "dhcp":
	        report += t.formatLog("    Primary DNS", prim)
	        report += t.formatLog("    Secondary DNS", sec)

	report += "\n"
	if self.c.config['sensortype'] == "vlan":
	    trunk = f.getFirstIf(["trunk"])
	    report += t.formatLog("Trunk network interface", trunk)
#	    vlannum = self.c.getVlanNum()
#	    report += t.formatLog("  Amount of VLANs", vlannum)
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


    def sensor(self):
	""" Prints information about the sensor status """
	logging.debugv("menu/status.py->sensor(self)", [])
	sid = self.c.config.get("sensorid", "Unknown")
	status = "Unknown"
	if self.r.config['status']:
	    status = self.r.config['status']['sensor']

	# Subtitle
	report = t.formatTitle("General sensor info")

	# Sensor name
	report += t.formatLog("Sensor", sid)

	# Sensor status
	report += t.formatLog("Status", status)

	report += "\n"

	# Subtitle
	report += t.formatTitle("Sanity checks")

	# OpenVPN port check
	ovnport = f.scanPort(self.c.config.get("server", "127.0.0.1"), 1194)
	report += t.formatLog("OpenVPN port", ovnport)

	# Updates port check
	upport = f.scanPort(self.c.config.get("server", "127.0.0.1"), 4443)
	report += t.formatLog("Updates port", upport)

	# Check key existance
	report += t.formatLog("Certificate check", f.checkKey())

	report += "\n"

	# Subtitle
	report += t.formatTitle("Program checks")

	# Check SSH status
	report += t.formatLog("SSH daemon running", f.sshStatus())

	if status:
	    # Checking OpenVPN daemon
	    report += t.formatLog("OpenVPN daemon running", f.openvpnStatus())

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
