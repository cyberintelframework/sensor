
import logging

from sensor import locations
from sensor import config

class Lock:
    def __init__(self, d):
        logging.debugv("menu/about.py->__init__(self, d)", [])
        self.d = d

        # c = config object
        self.c = config.Config()

    def run(self):
        """ subitem of main menu, locks the sensor menu """
        logging.debugv("menu/lock.py->run(self)", [])
        if self.c.getSensorID() == "Unknown":
            text = "The sensor has not yet registered with the server and received a sensor ID.\n"
            text += "Configure and start the sensor first before locking the menu."
            self.d.msgbox(text, width=50, height=10)
        else:
            self.lock()

    def lock(self):
        """ Locks the sensor menu """
        logging.debugv("menu/lock.py->lock(self)", [])

        self.c.setLock("Enabled")

        title = "The sensor menu is locked\n"
        title += "Enter the sensor ID to unlock..."

        while True:
            choice = self.d.passwordbox(title, 10, 50, "", insecure=1, nocancel=1, ok_label="Unlock")
            if choice[0]: return
            elif self.c.getSensorID() == choice[1]:
                self.c.setLock("Disabled")
                return
                

