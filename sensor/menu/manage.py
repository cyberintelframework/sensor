 
import logging
import pdb

from sensor import dialog
from sensor import functions
from sensor import config
from sensor import tools
from sensor import runtime
from sensor import excepts
from sensor import client

class Manage:
    def __init__(self, d):
        # d = dialog object
        logging.debugv("menu/manage.py->__init__(self, d)", [])
        self.d = d
        self.r = runtime.Runtime()

        # c = config object
        self.c = config.Config()

    def run(self):
        """ Submenu of main to for sensor management """
        logging.debugv("menu/manage.py->run(self)", [])

        # Checking for network configuration
        try:
            chk = self.c.validNetConf()
        except excepts.ConfigException, e:
            self.d.msgbox("The network configuration is invalid: \n%s" % str(e), width=60)
            return

        choices = []

        if self.r.sensorStatus():
            choices.append( ("Sensor Down", "Bring sensor down") )
            choices.append( ("Sensor Restart", "Restart the sensor") )
        else:
            choices.append( ("Sensor Up", "Bring sensor up") )

        if self.r.networkStatus():
            choices.append( ("Update", "Sync with server now") )
            #choices.append( ("Get Config", "Get the latest network config") )
            choices.append( ("Ping", "Check if connection is okay") )

        if functions.sshStatus():
            choices.append( ("SSH server off", "Disable remote shell access") )
        else:
            choices.append( ("SSH server on", "Enable remote shell access") )

        if functions.checkKey():
            choices.append( ("Reinit sensor", "Removes keys and sensor ID") )

        # TODO
        #choices.append( ("Startup on", "Enable SURFids at startup") ) 

        title = "\\ZbStart > Manage\\n\\ZB"
        subtitle = "Select an action"
        title += subtitle
        choice = self.d.menu(title, choices=choices, cancel="Back", colors=1)

        # cancel 
        if choice[0] == 1: return
        elif choice[1] == "Sensor Up": self.sensorUp()
        elif choice[1] == "Sensor Down": self.sensorDown()
        elif choice[1] == "Sensor Restart": self.sensorUp()
        elif choice[1] == "Update": self.update()
        #elif choice[1] == "Get Config": self.getConfig()
        elif choice[1] == "SSH server on":
            functions.sshUp()
            self.d.msgbox("SSH server enabled")
        elif choice[1] == "SSH server off":
            functions.sshDown()
            self.d.msgbox("SSH server disabled")
        elif choice[1] == "Reinit sensor":
            if not self.d.yesno("Are you sure you want to reinit this sensor? " + 
                    "This will result in a new sensor ID"):
                functions.sensorDown()
                functions.delKey()
                self.c.setSensorID("")
                self.d.msgbox("Sensor cleaned (removed key & certificate). Ignore the old sensor in the web interface. Restart the sensor.", width=60)
        elif choice[1] == "Ping": self.ping()
        else: self.d.msgbox("not yet implemented")
        self.run()

    def sensorUp(self):
        """ Bring the sensor up """
        logging.debugv("menu/manage.py->sensorUp(self)", [])

        # Validate network config
        try:
            self.c.validNetConf()
        except excepts.ConfigException, err:
            self.d.msgbox("The network configuration is invalid: \n%s" % str(err), width=60)
            return

        # Validate DNS config
        try:
            self.c.validDNSConf()
        except excepts.ConfigException, err:
            self.d.msgbox("The DNS configuration is invalid: \n%s" % str(err), width=60)
            return

        self.d.infobox("Bringing sensor up...")
        functions.sensorDown()
        try:
            if functions.sensorUp():
                self.d.msgbox("Sensor succesfully brought online")
            else:
                self.d.msgbox("Unable to start the sensor")
        except excepts.NetworkException, msg:
            self.d.msgbox(str(msg) + "\nplease see logfile for details", width=60)
            self.sensorDown()
        except excepts.ConfigException, msg:
            self.d.msgbox(str(msg) + "\nplease see logfile for details", width=60)
            self.sensorDown()

    def sensorDown(self):
        """ Bring down the sensor """
        logging.debugv("menu/manage.py->sensorDown(self)", [])
        try:
            self.d.infobox("Bringing sensor down...")
            functions.sensorDown()
        except excepts.NetworkException:
            logging.info("No network connection, so can't deregister")
            functions.allInfsDown()

            # Get network working again
            functions.networkUp()

        self.d.msgbox("Sensor succesfully brought offline")


    def getConfig(self):
        """ Display the latest configuration from the server """
        logging.debugv("menu/manage.py->getConfig(self)", [])

        config = client.getConfig()
        #functions.saveNetConf(config)
        self.d.msgbox(config, height=20, width=60)


    def update(self):
        """ Update the sensor scripts """
        logging.debugv("menu/manage.py->update(self)", [])
        self.d.infobox("Syncing sensor with SURFids server...")
        functions.update()
        self.d.msgbox("Sensor succesfully synced")

    def ping(self):
        """ Send a ping to predefined addresses """
        logging.debugv("menu/manage.py->ping(self)", [])
        self.d.infobox("Sending ping...")
        result = tools.ping(tools.hosts)
        if result: self.d.msgbox("Ping OK")
        else: self.d.msgbox("Ping failed, there is something wrong with your settings or you can't sent ICMP packages")

    def shutdown(self):
        """ Shutdown the machine gracefully """
        logging.debugv("menu/manage.py->shutdown(self)", [])
        try:
            self.d.infobox("Bringing sensor down...")
            functions.sensorDown()
        except:
            logging.info("Sensor down failed before shutdown")
        self.d.infobox("Shutting down machine...")
        functions.shutdown()
