#!/usr/bin/env python

import logging
import sys
import os

from sensor import log
from sensor import functions as f
from sensor import menu

class Manager:
    def __init__(self):
    	logging.debugv("manager.py->__init__(self)", [])

        os.putenv('LANG', 'en_US.UTF-8')
        os.environ['LANG'] = 'en_US.UTF-8'

        if not f.checkRoot():
            logging.error("not root, you should run the manager as root")
            sys.exit(1)

    def run(self):
    	logging.debugv("manager.py->run(self)", [])
        logging.info("SURFids manager starting")
        logging.debug("Initializing runtime info")
        f.initRuntime()
    	logging.info("Starting up menu")
        menu.Menu().run()


if __name__ == '__main__':
    manager = Manager()
    manager.run()
    

