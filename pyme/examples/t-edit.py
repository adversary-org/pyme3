import os
from pyme.core import Data, Context

class KeyEditor:
    def __init__(self):
        self.steps = ["fpr", "expire", "1", "primary", "quit"]
        self.step = 0

    def edit_fnc(self, status, args, out):
        print "[-- Response --]"
        out.seek(0,0)
        print out.read(),
        print "[-- Code: %d, %s --]" % (status, args)
    
        if args == "keyedit.prompt":
            result = self.steps[self.step]
            self.step += 1
        elif args == "keyedit.save.okay":
            result = "Y"
        elif args == "keygen.valid":
            result = "0"
        else:
            result = None

        return result

if not os.getenv("GNUPGHOME"):
    print "Please, set GNUPGHOME env.var. pointing to GPGME's tests/gpg dir"
else:
    c = Context()
    c.set_passphrase_cb(lambda x,y,z: "abc", "")
    out = Data()
    c.op_keylist_start("Alpha", 0)
    key = c.op_keylist_next()
    c.op_edit(key, KeyEditor().edit_fnc, out, out)
    print "[-- Last response --]"
    out.seek(0,0)
    print out.read(),
