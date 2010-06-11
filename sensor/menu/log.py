import re
import os
import logging
from sensor import locations
import sensor.dialog

class Log:
    def __init__(self, d):
        logging.debugv("menu/log.py->__init__(self, d)", [])
        self.d = d

    def run(self):
        """ Submenu showing the different log overviews """
        logging.debugv("menu/log.py->run(self)", [])
        choices=[
                ("All", "Show everything"),
                ("Error", "Filter on error messages"),
                ("Warning", "Filter on warning messages"),
                ("Info", "Filter on info messages"),
                ("Debug", "Filter on debug messages"),
                ("Debugv", "Filter on debugv messages"),
                ("Manual", "Manually enter a search keyword"),
                ("Update", "Show the update log"),
                ("Dump", "Show the latest exception dump"),
            ]

        title = "\\ZbStart > Log\\n\\ZB"
        subtitle = "Which log overview do you want to see?"
        title += subtitle
        choice = self.d.menu(title, choices=choices, cancel="Back", colors=1, menu_height=11, height=17)

        # cancel
        if choice[0] == 1: return
        elif choice[1] == "All": self.showAll()
        elif choice[1] == "Error": self.showFilter(" ERROR ")
        elif choice[1] == "Warning": self.showFilter(" WARN ")
        elif choice[1] == "Info": self.showFilter(" INFO ")
        elif choice[1] == "Debug": self.showFilter(" DEBUG ")
        elif choice[1] == "Debugv": self.showFilter(" DEBUGVV{0,1} ")
        elif choice[1] == "Manual": self.manual()
        elif choice[1] == "Update": self.showUpdateLog()
        elif choice[1] == "Dump": self.errorDump()
        self.run()

    def showAll(self):
        """ Show the entire log file """
        logging.debugv("menu/log.py->showAll(self)", [])
        if os.access(locations.LOGFILE, os.R_OK):
            return self.d.textbox(locations.LOGFILE, width=70, height=20, no_collapse=1, colors=1)
        else:
            return self.d.msgbox("No logfile present")


    def showUpdateLog(self):
        """ Show the update log """
        logging.debugv("menu/log.py->showUpdateLog(self)", [])
        if os.access(locations.UPDATELOG, os.R_OK):
            return self.d.textbox(locations.UPDATELOG, width=70, height=20, no_collapse=1, colors=1)
        else:
            return self.d.msgbox("No update logfile present")


    def showFilter(self, filter):
        """ Show the log file with a certain filter text """
        logging.debugv("menu/log.py->showFilter(self, filter)", [filter])

        expr = r".*%s.*" % filter

        if os.access(locations.LOGFILE, os.R_OK):
            logFile = open(locations.LOGFILE, 'r')
            tempLogFile = open(locations.TEMPLOG, 'w')
            for line in logFile.readlines():
                compiled = re.compile(expr)
                if compiled.match(line) != None:
                    tempLogFile.write(line)
            tempLogFile.close()
            logFile.close()
            self.d.textbox(locations.TEMPLOG, width=70, height=20, no_collapse=1, colors=1)
            os.unlink(locations.TEMPLOG)
        else:
            return self.d.msgbox("No logfile present")

    def manual(self):
        """ Dialog window for entering the manual search keyword """
        logging.debug("menu/log.py->manual(self)", [])

        title = "Enter a keyword to search the logfile for!"
        output = self.d.inputbox(title, 10, 50, "", colors=1, ok_label="Ok")
        if output[0]: return            # returns to run()
        else:
            if output[1] == "":
                return                  # returns to run()
            else:
                self.showFilter(output[1])


    def errorDump(self):
        """ Show the latest exception dump """
        logging.debug("menu/log.py->errorDump(self)", [])

        if os.access(locations.DUMP, os.R_OK):
            return self.d.textbox(locations.DUMP, width=70, height=20, no_collapse=1, colors=1)
        else:
            return self.d.msgbox("No exception dump present")
