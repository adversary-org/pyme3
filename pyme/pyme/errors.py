# Copyright (C) 2002 John Goerzen
# <jgoerzen@complete.org>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

from __future__ import nested_scopes
import gpgme

class GPGMEError(Exception):
    def __init__(self, error = None, message = None):
        self.error = error
        self.message = message
    
    def getstring(self):
        message = gpgme.gpgme_strerror_r(self.error, 1024);
        if self.message != None:
            message = "%s: source(%d), code(%d) %s" % \
                      (self.message,self.getsource(),self.getcode(),message)
        return message

    def getcode(self):
        return gpgme.gpgme_err_code(self.error)

    def getsource(self):
        return gpgme.gpgme_err_source(self.error)
    
    def __str__(self):
        return "%s (%d,%d)"%(self.getstring(),self.getsource(),self.getcode())

EOF = getattr(gpgme, "EOF")

def errorcheck(retval, extradata = None):
    if retval != 0:
        raise GPGMEError(retval, extradata)
