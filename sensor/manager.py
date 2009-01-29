#!/usr/bin/env python

import logging
import sys
import os

from sensor import log
from sensor import functions as f
from sensor import menu
from sensor import runtime
from sensor import config
from sensor import dialog
from sensor import excepts

class Manager:
    def __init__(self):
    	logging.debugv("manager.py->__init__(self)", [])

        os.putenv('LANG', 'en_US.UTF-8')
        os.environ['LANG'] = 'en_US.UTF-8'

        self.r = runtime.Runtime()
        self.c = config.Config()
        self.d = dialog.Dialog()

        if not f.managerStatus():
            logging.debug("WATCHME No manager running, cleaning up, writing PID")
            f.cleanUp()
            f.writePID()

        f.suppressDmesg()

        if not f.checkRoot():
            logging.error("Not root, you should run the manager as root")
            sys.exit(1)

    def run(self):
    	logging.debugv("manager.py->run(self)", [])
        logging.info("SURFids manager starting")
        logging.debug("Initializing runtime info")
        f.initRuntime()
        if not self.r.sensorStatus():
            if self.c.getAutoStart() == "Enabled":
                logging.info("Sensor not active - Auto Starting")
                self.d.setBackgroundTitle('SURFids v2.10 running on ' + f.system())
                self.d.infobox("Auto Starting sensor...")
                try:
                    f.sensorUp()
                except excepts.NetworkException, msg:
                    msg = str(msg)
                    self.d.msgbox("NETWORK ERROR: " + msg)
                except excepts.ConfigException, msg:
                    msg = str(msg)
                    self.d.msgbox("CONFIG ERROR: " + msg)

    	logging.info("Starting up menu")
        menu.Menu().run()


if __name__ == '__main__':
    manager = Manager()
    manager.run()
    

