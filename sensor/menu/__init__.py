 
import logging

from sensor import functions
from sensor import dialog

# menu modules
import status
import about
import update
import log
import config
import manage
import console

class Menu:
    def __init__(self):
        #self.d = dialog.Dialog(dialog="/usr/bin/Xdialog", compat="Xdialog")
        #self.d = dialog.Dialog(dialog="/usr/bin/zenity", compat="")
        logging.debugv("menu/__init__.py->__init__(self)", [])
        self.d = dialog.Dialog()

        self.d.setBackgroundTitle('SURFids sensor v2.10 running on ' + functions.system())

    def run(self):
        """ The main menu """
        logging.debugv("menu/__init__.py->run(self)", [])
        choice = self.d.menu("What's do you want to do today?",
            choices=[
                ("Configure", "Configure this sensor"),
                ("Manage", "Start/stop sensor functions"),
                ("Status", "View the status of this sensor"),
                ("Log", "View the logfile of this sensor"),
                #("Update", "Update the sensor scripts"),
                #("Console", "Open a management console"),
                ("About", "Learn more about the SURFnet IDS sensor"),
            ], nocancel=1, width="63")
        #cancel
        if choice[0] == 1: return
        elif choice[1] == "Configure": config.Config(self.d).run()
        elif choice[1] == "Manage": manage.Manage(self.d).run()
        elif choice[1] == "Status": status.Status(self.d).run()
        elif choice[1] == "Log": log.Log(self.d).run()
        elif choice[1] == "Console": console.Console(self.d).run()
        elif choice[1] == "About": about.About(self.d).run()
        #elif choice[1] == "Update": update.Update(self.d)
        self.run()
