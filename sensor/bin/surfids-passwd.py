#!/usr/bin/python
import hashlib
import sys

def usage():
    """ Prints usage info for the surfids-passwd script """
    print "Usage: surfids-passwd [PASSWORD]"
    print "This script will generate the password string"
    print "for usage with the surfids-sensor."
    print ""
    print "The result needs to be added to /etc/surfids/surfids.conf "
    print "in the following format: "
    print "adminpass = result"
    

if len(sys.argv) == 2:
    o = sys.argv[1]
    if o == "-h":
        usage()
        exit
    elif o == "--help":
        usage()
        exit
    else:
        m = hashlib.md5()
        m.update(o)
        p = m.hexdigest()
        print "%s" % (p)
else:
    usage()
    exit




