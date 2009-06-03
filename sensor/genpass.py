#!/usr/bin/python
import md5
import sys

if len(sys.argv) == 2:
    o = sys.argv[1]
    m = md5.new()
    m.update(o)
    p = m.hexdigest()
    print "%s -> %s" % (o, p)
else:
    print "Usage: ./genpass.py <password string>"
    exit




