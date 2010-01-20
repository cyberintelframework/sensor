#!/usr/bin/env python

import logging
import sys
import os
import signal

from sensor import log
from sensor import functions as f
from sensor import menu
from sensor import runtime
from sensor import config
from sensor import dialog
from sensor import excepts
from sensor import locations

class Manager:
    def __init__(self):
    	logging.debugv("manager.py->__init__(self)", [])

        os.putenv('LANG', 'en_US.UTF-8')
        os.environ['LANG'] = 'en_US.UTF-8'

        self.r = runtime.Runtime()
        self.c = config.Config()
        self.d = dialog.Dialog()

        if not f.managerStatus():
            logging.debug("No manager running, cleaning up, writing PID")
            f.cleanUp()
            f.writePID()

        f.suppressDmesg()

        if not f.checkRoot():
            logging.error("Not root, you should run the manager as root")
            sys.exit(1)

    def run(self):
    	logging.debugv("manager.py->run(self)", [])
        logging.info("SURFids manager starting")
        try:
            f.networkUp()
        except excepts.ConfigException, msg:
            logging.warn(msg)
        except excepts.InterfaceException, msg:
            logging.warn(msg)
        except:
            self.handleException()
        logging.debug("Initializing runtime info")
        f.initRuntime()
        if not self.r.sensorStatus():
            if self.c.getAutoStart() == "Enabled":
                logging.info("Sensor not active - Auto Starting")
                self.d.setBackgroundTitle('SURFids v3.0 running on ' + f.system())
                self.d.infobox("Auto Starting sensor...")
                try:
                    self.c.validNetConf()
                except excepts.ConfigException, err:
                    self.d.infobox("Autostart Failed\n\nCONFIG ERROR: %s" % str(err))
                else:
                    try:
                        f.sensorUp()
                    except excepts.NetworkException, msg:
                        msg = str(msg)
                        self.d.msgbox("Autostart Failed\n\nNETWORK ERROR: " + msg)
                    except excepts.ConfigException, msg:
                        msg = str(msg)
                        self.d.msgbox("Autostart Failed\n\nCONFIG ERROR: " + msg)
                    except excepts.InterfaceException, msg:
                        msg = str(msg)
                        self.d.msgbox("Autostart Failed\n\nINTERFACE ERROR: " + msg)
                    except:
                        self.handleException()

    	logging.info("Starting up menu")
        try:
            menu.Menu().run()
        except SystemExit:
            logging.info("Sensor manager exiting")
        except:
            self.handleException()

    def handleException(self):
        """ Handle any uncaught exception in the manager """
        logging.debugv("manager.py->handleException(self)", [])

        f.do_verbose_exception()
        ex = False
        while ex == False:
            title = "\\Z1Unexpected error detected!!\\Z0\\nIf this problem persists, contact an administrator.\\nWhat do you want to do?"
            choices = [
                    ("Restart GUI", "Restart the sensor manager GUI"),
                    ("Reset network config", "Reset the network configuration"),
                    ("View error dump", "View the latest error dump"),
                ]
            choice = self.d.menu(title, choices=choices, no_cancel=1, colors=1, width=70)
            if choice[0]: return
            elif choice[1] == "Restart GUI": 
                log.inthandler(signal.SIGINT, "")
                ex = True
            elif choice[1] == "Reset network config":
                self.c.resetNetConfig()
                text = "Network config reset. Press OK to restart the sensor manager GUI"
                self.d.msgbox(text, width=70, no_collapse=1, colors=1)
                log.inthandler(signal.SIGINT, "")
                ex = True
            elif choice[1] == "View error dump":
                logText = ""
                logFile = open(locations.DUMP, 'r')
                for line in logFile.readlines():
                    logText += line
                self.d.msgbox(logText, width=70, height=40, no_collapse=1, colors=1)

if __name__ == '__main__':
    manager = Manager()
    manager.run()
    

