# $Id$
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

import gpgme
from getpass import getpass

def passphrase_stdin(hint, desc, hook):
    """This is a sample callback that will read a passphrase from
    the terminal.  The hook here, if present, will be used to describe
    why the passphrase is needed."""
    why = ''
    if hook != None:
        why = ' ' + hook
    print "Please supply %s' password%s:" % (hint, why)
    return getpass()

def progress_stdout(what, type, current, total, hook):
    print "PROGRESS UPDATE: what = %s, type = %d, current = %d, total = %d" %\
          (what, type, current, total)
    
def readcb_fh(count, hook):
    """A callback for data.  hook should be a Python file-like object."""
    if count:
        # Should return '' on EOF
        return hook.read(count)
    else:
        # Wants to rewind.
        if not hasattr(hook, 'seek'):
            return None
        hook.seek(0, 0)
        return None
