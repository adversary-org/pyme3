#!/usr/bin/env python
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

import sys
from pyme import core, constants, callbacks, errors
import pyme.constants.validity

# Set up our input and output buffers.

pubkey = core.Data()
seckey = core.Data()

# Initialize our context.

c = core.Context()
c.set_armor(1)
c.set_progress_cb(callbacks.progress_stdout, None)

# This example from the GPGME manual

parms = """<GnupgKeyParms format="internal">
Key-Type: DSA
Key-Length: 1024
Subkey-Type: ELG-E
Subkey-Length: 1024
Name-Real: Joe Tester
Name-Comment: with stupid passphrase
Name-Email: joe@foo.bar
Passphrase: abcdabcdfs
Expire-Date: 2010-08-15
</GnupgKeyParms>
"""

try:
    c.op_genkey(parms, pubkey, seckey)
except errors.GPGMEError, excp:
    print excp.getstring()

seckey.seek(0,0)
print seckey.read()
