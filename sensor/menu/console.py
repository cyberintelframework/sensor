 
import os
import logging

class Console:
    def __init__(self, d):
        logging.debugv("menu/console.py->__init__(self, d)", [])
        pass

    def run(self):
        logging.debugv("menu/console.py->run(self)", [])
        os.system("clear")
        os.system("bash")


