#!/usr/bin/env python

import sys, re

if len(sys.argv) < 2:
    sys.stderr.write("Usage: %s gpgme.h\n" % sys.argv[0])
    sys.exit(1)

deprec_func=re.compile('^(typedef.*|.*\(.*\))\s*_GPGME_DEPRECATED;\s*',re.S)
line_break=re.compile(';|\\$|^\s*#');
try:
    gpgme = file(sys.argv[1])
    tmp = gpgme.readline()
    text = ''
    while tmp:
        text += re.sub(' class ', ' _py_obsolete_class ', tmp)
        if line_break.search(tmp):
            if not deprec_func.search(text):
                sys.stdout.write(text)
            text = ''
        tmp = gpgme.readline()
    sys.stdout.write(text)
    gpgme.close()
except IOError, errmsg:
    sys.stderr.write("%s: %s\n" % (sys.argv[0], errmsg))
    sys.exit(1)
