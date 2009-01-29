 
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
        if not self.r.configStatus():
            self.d.msgbox("Network configuration was not found. Configure network first!")
            return

        choices = []

        if self.r.sensorStatus():
            choices.append( ("Sensor Down", "Bring sensor down") )
            choices.append( ("Sensor Restart", "Restart the sensor") )
        else:
            choices.append( ("Sensor Up", "Bring sensor up") )

        if self.r.networkStatus():
            choices.append( ("Update", "Sync with server now") )
            choices.append( ("Get Config", "Get the latest network config") )
            choices.append( ("Ping", "Check if connection is okay") )

        if functions.sshStatus():
            choices.append( ("SSH server off", "Disable remote shell access") )
        else:
            choices.append( ("SSH server on", "Enable remote shell access") )

        if functions.checkKey():
            choices.append( ("Reinit sensor", "Removes keys and sensor ID") )

        # TODO
        #choices.append( ("Startup on", "Enable SURFids at startup") ) 

        choice = self.d.menu("What do you want to manage?", choices=choices, cancel="back")

        # cancel 
        if choice[0] == 1: return
        elif choice[1] == "Sensor Up": self.sensorUp()
        elif choice[1] == "Sensor Down": self.sensorDown()
        elif choice[1] == "Sensor Restart": self.sensorUp()
        elif choice[1] == "Update": self.update()
        elif choice[1] == "Get Config": self.getConfig()
        elif choice[1] == "SSH server on":
            functions.sshUp()
            self.d.msgbox("SSH server enabled")
        elif choice[1] == "SSH server off":
            functions.sshDown()
            self.d.msgbox("SSH server disabled")
        elif choice[1] == "Reinit sensor":
            if not self.d.yesno("Are you sure you want to reinit this sensor? " + 
                    "This will result in a new sensor ID"):
                if self.sensorDown():
                    functions.delKey()
                    self.d.msgbox("Sensor cleaned (removed key & certificate)")
        elif choice[1] == "Ping": self.ping()
        else: self.d.msgbox("not yet implemented")
        self.run()

    def sensorUp(self):
        """ Bring the sensor up """
        logging.debugv("menu/manage.py->sensorUp(self)", [])
        self.d.infobox("Bringing sensor up...")
        functions.sensorDown()
        try:
            if functions.sensorUp():
                self.d.msgbox("Sensor succesfully brought online")
            else:
                self.d.msgbox("Unable to start the sensor")
        except excepts.NetworkException, msg:
            self.d.msgbox(str(msg) + "\nplease see logfile for details", width=70)
            self.sensorDown()
        except excepts.ConfigException, msg:
            self.d.msgbox(str(msg) + "\nplease see logfile for details", width=70)
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
        functions.saveNetConf(config)
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
        (result, log) = tools.ping(tools.hosts)
        logging.debug(log)
        if result: self.d.msgbox("Ping OK")
        else: self.d.msgbox("Ping failed, there is something wrong with your settings or you can't sent ICMP packages")
