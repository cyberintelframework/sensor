import re
import sys
import os
import time
import math
import logging

from threading import Thread

changeset = "001"

def chkReg(expr, match):
    """ Check a string against a regular expression """
    logging.debugv("tools.py->chkReg(expr, match)", [expr, match])
    compiled = re.compile(expr)
    return (compiled.match(match) != None)

def ipv4check(ip):
    """ Check if IP is a valid IP address """
    logging.debugv("tools.py->ipv4check(ip)", [ip])
    ipexpression = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    compiled = re.compile(ipexpression)
    return (compiled.match(ip) != None)

def macCheck(mac):
    """ Check if MAC is a valid MAC address """
    logging.debugv("tools.py->macCheck(mac)", [mac])
    macexpression = r"^([a-fA-F0-9]{2}:{1}){5}[a-fA-F0-9]{2}$"
    compiled = re.compile(macexpression)
    return (compiled.match(mac) != None)

def urlCheck(url):
    """ Check if an URL is starting with http:// and ending with a valid / """
    logging.debugv("tools.py->urlCheck(url)", [url])
    urlexpression = r"^http{1}s?:\/\/.*\/$"
    compiled = re.compile(urlexpression)
    return (compiled.match(url) != None)

def broadcast(ip, netmask):
    """ Calculates the broadcast address from a given IP address and netmask """
    logging.debugv("tools.py->broadcast(ip, netmask)", [ip, netmask])
    ipv4check(ip)
    ipv4check(netmask)

    i = [int(x) for x in ip.split(".")]
    n = [int(x) for x in netmask.split(".")]

    bc = []
    for x in range(4):
        bc.append(i[x]|(n[x]^255))
    return ".".join([str(x) for x in bc])

def hex2ip(hexIp):
    """ Converts a 8 digit hex IP to normal IP string """
    logging.debugv("tools.py->hex2ip(hexIp)", [hexIp])
    elements = [str(int(hexIp[i:i+2], 16)) for i in range(0,8,2)]
    elements.reverse()
    return ".".join(elements)

def dec2bin(n):
    """ Converts a decimal integer to a binary string """
    logging.debugv("tools.py->dec2bin(n)", [n])
    bStr = ''
    if n < 0: raise ValueError, "must be a positive integer"
    if n == 0: return '0'
    while n > 0:
        bStr = str(n % 2) + bStr
        n = n >> 1
    return bStr

def formatMenuItem(msg, val, valid=True):
    """ Validates a menu item and returns dict for usage in dialog menu """
    logging.debugv("tools.py->formatMenuItem(msg, val, valid)", [msg, val, valid])
    if val == "" or not valid:
        return [(msg, ">>To be configured<<"),]
    else:
        return [(msg, val),]

def formatBool(msg):
    """ Formats a msg based on a boolean value """
    logging.debugv("tools.py->formatBool(msg)", [msg])
    msg = str(msg)
    if msg == "enabled" or msg == "True":
        return "\Z2" + str(msg) + "\Z0"
    else:
        return "\Z1" + str(msg) + "\Z0"

def formatLog(msg,result,color = 0):
    """ Formats the string and result for usage in dialog """
    logging.debugv("tools.py->formatLog(msg, result)", [msg, result])
    lent = len(msg)
    if color:
        result = formatBool(result)
    tabcount = int(math.ceil(30 - lent))
    tabstring = " " * tabcount
    logstr = "%s:%s%s\n" % (msg, tabstring, result)
    return logstr

#def formatMenu(msg):
#    """ Formats the string and result for usage in dialog menu """
#    logging.debugv("tools.py->formatMenu(msg)", [msg])
#    lent = len(msg)
#    tabcount = int(math.ceil(40 - lent))
#    tabstring = " " * tabcount
#    logstr = "%s%s:\n" % (msg, tabstring)
#    return logstr

def formatTitle(msg):
    """ Formats the string for use as a title in dialog """
    logging.debugv("tools.py->formatTitle(msg)", [msg])
    msg = "\Zb\Z7" + msg + "\Zn\n"
    return msg

def debugDict(d, level = 0):
    """ Formats a dictionary to a human readable string """
    ret = ""
    if isinstance(d, dict):
        for (k, v) in d.items():
            if isinstance(k, str):
                k = "'" + k + "'"
            pre = level * "  "
            if isinstance(v, dict):
                if v.__len__() != 0:
                    level = level + 1
                    ret += pre + str(k) + " = {\n"
                    ret += debugDict(v, level)
                    ret += pre + "} "
                    level = level - 1
                else:
                    ret += pre + str(k) + " = {}"
            else:
                if isinstance(v, str):
                    v = "'" + v + "'"
                ret += pre + str(k) + " = " + str(v)
            ret += "\n"
        return ret

class Pinger(Thread):
    """ Threaded ping class """
    def __init__ (self,host):
        self.lifeline = re.compile(r"(\d) received")
        report = ("No response","Partial Response","Alive")
        Thread.__init__(self)
        self.host = host
        self.alive = False
        self.log = ""

    def run(self):
        logging.debugv("tools.py->Pinger->run(Thread)", [Thread])
        pingaling = os.popen("ping -q -c2 "+self.host,"r")
        while 1:
            line = pingaling.readline()
            if not line: break
            igot = re.findall(self.lifeline,line)
            if igot and int(igot[0]) > 0: self.alive = True


# TODO: for now this is here, don't know a better place yet. These hosts will be pinged
hosts = ['www.surfnet.nl', 'www.sara.nl', 'publicids.surfnet.nl']

def ping(hosts):
    """ Pings a list of hosts. returns True if one or more hosts is reachable """
    logging.debugv("tools.py->ping(hosts)", [hosts])
    pings = []
    for host in hosts:
        current = Pinger(host)
        pings.append(current)
        current.start()
    for pingi in pings:
        pingi.join()
        if pingi.alive: return True
    return False


