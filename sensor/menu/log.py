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
                ("Dump", "Show the latest exception dump"),
            ]

        title = "\\ZbStart > Log\\n\\ZB"
        subtitle = "Which log overview do you want to see?"
        title += subtitle
        choice = self.d.menu(title, choices=choices, cancel="Back", colors=1, menu_height=10, height=16)

        # cancel
        if choice[0] == 1: return
        elif choice[1] == "All": self.showAll()
        elif choice[1] == "Error": self.showFilter(" ERROR ")
        elif choice[1] == "Warning": self.showFilter(" WARN ")
        elif choice[1] == "Info": self.showFilter(" INFO ")
        elif choice[1] == "Debug": self.showFilter(" DEBUG ")
        elif choice[1] == "Debugv": self.showFilter(" DEBUGVV{0,1} ")
        elif choice[1] == "Manual": self.manual()
        elif choice[1] == "Dump": self.errorDump()
        self.run()


    def showFilter(self, filter):
        """ Show the log file with a certain filter text """
        logging.debugv("menu/log.py->showFilter(self, filter)", [filter])

        expr = r".*%s.*" % filter

        logText = ""
        logFile = open(locations.LOGFILE, 'r')
        for line in logFile.readlines():
            compiled = re.compile(expr)
            if compiled.match(line) != None:
                logText += line
        return self.d.msgbox(logText, width=70, height=40, no_collapse=1, colors=1)

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

        logText = ""
        if os.access(locations.DUMP, os.R_OK):
            logFile = open(locations.DUMP, 'r')
            for line in logFile.readlines():
                logText += line
            return self.d.msgbox(logText, width=70, height=40, no_collapse=1, colors=1)
        else:
            return self.d.msgbox("No exception dump present")


#    def run(self):
#        logging.debugv("menu/log.py->run(self)", [])
#        try:
#            return self.d.tailbox(locations.LOGFILE, 0, 0)
#        except sensor.dialog.DialogError:
#            self.d.msgbox("can't open logfile: "+locations.LOGFILE)
#            return


