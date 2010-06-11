 
import logging


class Update:
    def __init__(self, d):
        logging.debugv("menu/update.py->__init__(self, d)", [])
        self.d = d

    def run(self):
        """ updates SURFids to latest version """
        logging.debugv("menu/update.py->run(self)", [])
        import time
        self.d.gauge_start("doing nothing...")
        time.sleep(2)
        self.d.gauge_update(50, "still doing completely nothing...", True)
        time.sleep(2)
        self.d.gauge_update(98, "almost ready doing completely nothing...", True)
        time.sleep(2)
        self.d.gauge_update(99, "doing a little more nothing...", True)
        time.sleep(2)
        self.d.gauge_update(100, "done...", True)
        return self.d.gauge_stop()


