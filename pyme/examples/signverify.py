#!/usr/bin/env python
# $Id$
# Copyright (C) 2004 Igor Belyi
# <belyi@users.sourceforge.net>
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

from pyme import core, callbacks
from pyme.constants.sig import mode

plain = core.Data("Test message")
sig = core.Data()
c = core.Context()

c.signers_clear()
# Add joe2@foo.bar's and joe@foo.bar's key in the list of signers
sigkey = [x for x in c.op_keylist_all("joe2@foo.bar", 1)][0]
c.signers_add(sigkey)
sigkey = [x for x in c.op_keylist_all("joe@foo.bar", 1)][0]
c.signers_add(sigkey)

# This is a map between signer e-mail and its password
passlist = {
    "<joe2@foo.bar>": "abc",
    "<joe@foo.bar>": "abcdabcdfs"
    }
    
# callback will return password based on the e-mail listed in the hint.
c.set_passphrase_cb(lambda x,y,z: passlist[x[x.rindex("<"):]], "")

c.op_sign(plain, sig, mode.CLEAR)

# Print out the signature (don't forget to rewind since signing put sig at EOF)
sig.seek(0,0)
signedtext = sig.read()
print signedtext

# Create Data with signed text.
sig2 = core.Data(signedtext)
plain2 = core.Data()

# Verify.
c.op_verify(sig2, None, plain2)
result = c.op_verify_result()

# List results for all signatures. Status equal 0 means "Ok".
sign = result.signatures
index = 0
while sign:
    index += 1
    print "signature", index, ":"
    print "  status:     ", sign.status
    print "  timestamp:  ", sign.timestamp
    print "  fingerprint:", sign.fpr
    print "  uid:        ", c.get_key(sign.fpr, 0).uids.uid
    sign = sign.next

# Print "unsigned" text. Rewind since verify put plain2 at EOF.
plain2.seek(0,0)
print "\n", plain2.read()
