
import logging

from sensor import locations


class About:
    def __init__(self, d):
        logging.debugv("menu/about.py->__init__(self, d)", [])
        self.d = d

    def run(self):
        """ subitem of main, shows content of ABOUT file """
        logging.debugv("menu/about.py->run(self)", [])
        return self.d.textbox(locations.ABOUT, 0,0)


