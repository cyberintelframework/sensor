 
import logging
from sensor import locations
import sensor.dialog

class Log:
    def __init__(self, d):
	logging.debugv("menu/log.py->__init__(self, d)", [])
        self.d = d

    def run(self):
	logging.debugv("menu/log.py->run(self)", [])
        logging.info("opening log dialog")
        try:
            return self.d.tailbox(locations.LOGFILE, 0, 0)
        except sensor.dialog.DialogError:
            self.d.msgbox("can't open logfile: "+locations.LOGFILE)
            return


