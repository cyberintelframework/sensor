import logging

REVISION="$Revision: 26 $"
LASTCHANGE="$Date: 2008-10-27 14:28:46 +0100 (Mon, 27 Oct 2008) $"
VERSION="0.3"

changeset = "001"

def getRev():
    logging.debugv("version.py->getRev()", [])
    return REVISION.split()[1]

def getDate():
    logging.debugv("version.py->getDate()", [])
    return " ".join(LASTCHANGE.split()[1:-1])
