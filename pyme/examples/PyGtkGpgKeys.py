#!/usr/bin/python
# $Id$
# Copyright (C) 2005 Igor Belyi <belyi@users.sourceforge.net>
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

import gtk, gobject, gtk.glade
import time, sys, os
from pyme import callbacks
from pyme.core import Data, Context, pubkey_algo_name
from pyme.constants import validity
from pyme.constants.keylist import mode

# Convert trust constant into a string
trusts = {validity.UNKNOWN: "",
          validity.UNDEFINED: "Undefined",
          validity.NEVER: "Never",
          validity.MARGINAL: "Marginal",
          validity.FULL: "Full",
          validity.ULTIMATE: "Ultimate"}

# Convert seconds into a date
def sec2str(secs):
    if secs > 0:    return time.strftime("%Y-%m-%d", time.gmtime(secs))
    elif secs == 0: return "Unlimited"
    else:           return ""

index = 0
class KeyColumn:
    "Helper class for data columns. Sortable by self.index"
    def __init__(self, gtype, vattr, func):
        """new(qtype, vattr, func):
        qtype - gobject type to use in TreeStore for this column
        vattr - column data is visible is method vattr present in the object
        func  - function converting object data into viewable presentation"""
        global index
        self.type = gtype
        self.vattr = vattr
        self.func = func
        self.index = index
        self.attrs = {"text": index}
        self.name = None
        index += 1

    def __cmp__(self, other):
        return self.index - other.index

# Explicite columns
columns = {
    "Name":    KeyColumn(gobject.TYPE_STRING, "name",
                         lambda x: x.name+(x.comment and " (%s)"%x.comment)),
    "Email":   KeyColumn(gobject.TYPE_STRING, "email",
                         lambda x: x.email),
    "Trust":   KeyColumn(gobject.TYPE_STRING, "owner_trust",
                         lambda x: trusts[x.owner_trust]),
    "Type":    KeyColumn(gobject.TYPE_STRING, "pubkey_algo",
                         lambda x: pubkey_algo_name(x.pubkey_algo)),
    "Length":  KeyColumn(gobject.TYPE_INT, "length",
                         lambda x: x.length),
    "Created": KeyColumn(gobject.TYPE_STRING, "timestamp",
                         lambda x: sec2str(x.timestamp)),
    "Expires": KeyColumn(gobject.TYPE_STRING, "expires",
                         lambda x: sec2str(x.expires)),
    "Id":      KeyColumn(gobject.TYPE_STRING, "keyid",
                         lambda x: x.keyid),
    "NameRev": KeyColumn(gobject.TYPE_BOOLEAN, None,
                         lambda x: x.revoked or x.invalid),
    "KeyRev":  KeyColumn(gobject.TYPE_BOOLEAN, None,
                         lambda x: x.revoked or x.invalid or x.expired),
    "CanDel":  KeyColumn(gobject.TYPE_BOOLEAN, None, lambda x: x)
    }

# The last column represented as a TreeViewColumn
last_visible = columns["Id"].index

# Calculate implicite columns - defining visibility of the data in a column.
# Also put names into column classes to use after sort.
name_only = ()
for name in columns.keys():
    columns[name].name = name
    if columns[name].index <= last_visible:
        columns["Show"+name] = KeyColumn(gobject.TYPE_BOOLEAN,None,lambda x: x)
        columns[name].attrs["visible"] = columns["Show"+name].index
        name_only += (columns["Show"+name].index, name == "Name")

# Use strikethrough to indicate revoked or invalid keys and uids
columns["Name"].attrs["strikethrough"] = columns["NameRev"].index
columns["Id"].attrs["strikethrough"] = columns["KeyRev"].index

# List columns specific to an object type
key_columns = ["Trust"]
uid_columns = ["Name", "Email", "NameRev"]
sub_columns = ["Type", "Expires", "Length", "Created", "Id", "KeyRev"]

def pair(name, value):
    "pair(name, value) creates (index, func(value)) tuple based on column name"
    item = columns[name]
    if item.index <= last_visible:
        view = columns["Show"+name]
        if hasattr(value, item.vattr):
            return (item.index, item.func(value), view.index, True)
        else:
            return (view.index, False)
    else:
        return (item.index, item.func(value))

class PyGtkGpgKeys:
    "Main class representing PyGtkGpgKeys application"
    
    def add_key(self, key):
        "self.add_key(key) - add key to the TreeStore model"
        uid = key.uids
        subkey = key.subkeys
        iter = self.model.append(None)
        param = (iter,)
        for col in key_columns: param += pair(col, key)
        for col in uid_columns: param += pair(col, uid)
        for col in sub_columns: param += pair(col, subkey)
        param += pair("CanDel", True)
        self.model.set(*param)
        if uid:
            self.add_signatures(uid.signatures, iter)
            self.add_uids(uid.next, iter)
        self.add_subkeys(subkey.next, iter)

    def add_subkeys(self, subkey, iter):
        "self.add_subkeys(subkey, iter) - add subkey as child to key's iter"
        if not subkey:
            return
        key_iter = self.model.append(iter)
        self.model.set(key_iter, 0, "Subkeys", *name_only)
        while subkey:
            child_iter = self.model.append(key_iter)
            param = (child_iter,)
            for col in sub_columns: param += pair(col, subkey)
            param += pair("CanDel", False)
            self.model.set(*param)
            subkey = subkey.next

    def add_uids(self, uid, iter):
        "self.add_uids(uid, iter) - add uid as a child to key's iter"
        if not uid:
            return
        uid_iter = self.model.append(iter)
        self.model.set(uid_iter,0, "Other UIDs", *name_only)
        while uid:
            child_iter = self.model.append(uid_iter)
            param = (child_iter,)
            for col in uid_columns: param += pair(col, uid)
            param += pair("CanDel", False)
            self.model.set(*param)
            self.add_signatures(uid.signatures, child_iter)
            uid=uid.next

    def add_signatures(self, sign, iter):
        "self.add_signatures(sign, iter) - add signature as a child to iter"
        if not sign:
            return
        sign_iter = self.model.append(iter)
        self.model.set(sign_iter, 0, "Signatures", *name_only)
        while sign:
            child_iter = self.model.append(sign_iter)
            param = (child_iter,)
            for col in uid_columns: param += pair(col, sign)
            for col in sub_columns: param += pair(col, sign)
            param += pair("CanDel", False)
            self.model.set(*param)
            sign = sign.next

    def add_columns(self):
        "Add viewable columns for the data in TreeStore model"
        visibles = [x for x in columns.values() if x.index <= last_visible]
        visibles.sort()
        for item in visibles:
            renderer = gtk.CellRendererText()
            column = self.treeview.insert_column_with_attributes(
                item.index, item.name, renderer, **item.attrs)
            column.set_sort_column_id(item.index)
            # Create callback for a View menu item
            check = self.wtree.get_widget(item.vattr + "_check")
            if check:
                check.connect("activate",
                              lambda x, y: y.set_visible(x.get_active()),
                              column)

    def on_delete_activate(self, obj):
        "self.on_delete_activate(obj) - callback for key deletion request"
        selection = self.treeview.get_selection()
        if selection:
            model, iter = selection.get_selected()
            if iter and model.get_value(iter, columns["CanDel"].index):
                keyid = model.get_value(iter, columns["Id"].index)
                key = self.context.get_key(keyid, 0)
                dialog = gtk.MessageDialog(self.mainwin,
                                           gtk.DIALOG_MODAL |
                                           gtk.DIALOG_DESTROY_WITH_PARENT,
                                           gtk.MESSAGE_QUESTION,
                                           gtk.BUTTONS_YES_NO,
                                           "Delete selected key?")
                if dialog.run() == gtk.RESPONSE_YES:
                    self.context.op_delete(key, 1)
                    model.remove(iter)
                dialog.destroy()

    def get_widget_values(self, widgets):
        "Create an array of values from widgets' getter methods"
        return [getattr(self.wtree.get_widget(w),"get_"+f)() for w,f in widgets]

    def set_widget_values(self, widgets, values):
        "Set values using widgets' setter methods"
        for (w,f), v in zip(widgets, values):
            # ComboBox.set_active_iter(None) does not reset active. Fixing.
            if f == "active_iter" and v == None:
                f, v = "active", -1
            getattr(self.wtree.get_widget(w), "set_"+f)(v)

    def key_type_changed(self, which):
        """self.key_type_changed([\"key\"|\"subkey\"]) - helper function to
        adjust allowed key length based on the Algorithm selected"""
        (key_type,) = self.get_widget_values([(which+"_type", "active_iter")])
        if key_type:
            key_type = self.wtree.get_widget(which+"_type").get_model(
                ).get_value(key_type,0)
            length_widget = self.wtree.get_widget(which+"_length")
            if key_type == "DSA":
                length_widget.set_range(1024, 1024)
                length_widget.set_value(1024)
            elif key_type == "RSA" or key_type == "ELG-E":
                length_widget.set_range(1024, 4096)

    def on_key_type_changed(self, obj):
        self.key_type_changed("key")

    def on_subkey_type_changed(self, obj):
        self.key_type_changed("subkey")

    def on_expire_calendar_day_selected(self, obj):
        "Callback for selecting a day on the calendar"
        (year, month, day)=self.wtree.get_widget("expire_calendar").get_date()
        expander = self.wtree.get_widget("expire_date")
        # Past dates means no expiration date
        if time.localtime() < (year, month+1, day):
            expander.set_label("%04d-%02d-%02d" % (year, month+1, day))
        else:
            expander.set_label("Unlimited")
        expander.set_expanded(False)

    def on_generate_activate(self, obj):
        "Callback to generate new key"
        
        # Set of (widget, common suffix of getter/setter function) tuples.
        widgets = [
            ("key_type", "active_iter"),
            ("key_length", "value"),
            ("key_encrypt", "active"),
            ("key_sign", "active"),
            ("subkey_type", "active_iter"),
            ("subkey_length", "value"),
            ("subkey_encrypt", "active"),
            ("subkey_sign", "active"),
            ("name_real", "text"),
            ("name_comment", "text"),
            ("name_email", "text"),
            ("expire_date", "label"),
            ("passphrase", "text"),
            ("passphrase_repeat", "text")
            ]

        saved_values = self.get_widget_values(widgets)
        result = None
        dialog = self.wtree.get_widget("GenerateDialog")
        if dialog.run() == gtk.RESPONSE_OK:
            (key_type, key_length, key_encrypt, key_sign,
             subkey_type, subkey_length, subkey_encrypt, subkey_sign,
             name_real, name_comment, name_email, expire_date,
             passphrase, passphrase2) = self.get_widget_values(widgets)
            if key_type and key_length and passphrase == passphrase2:
                key_type = self.wtree.get_widget("key_type").get_model(
                    ).get_value(key_type,0)
                result = "<GnupgKeyParms format=\"internal\">\n"
                result += "Key-Type: %s\n" % key_type
                result += "Key-Length: %d\n" % int(key_length)
                if key_encrypt or key_sign:
                    result += "Key-Usage:" + \
                              ((key_encrypt and " encrypt") or "") + \
                              ((key_sign and " sign") or "") + "\n"
                if subkey_type:
                    subkey_type=self.wtree.get_widget("subkey_type").get_model(
                        ).get_value(subkey_type,0)
                    result += "Subkey-Type: %s\n" % subkey_type
                    result += "Subkey-Length: %d\n" % int(subkey_length)
                    if subkey_encrypt or subkey_sign:
                        result += "Subkey-Usage:" + \
                                  ((subkey_encrypt and " encrypt") or "") + \
                                  ((subkey_sign and " sign") or "") + "\n"
                if name_real:
                    result += "Name-Real: %s\n" % name_real
                if name_comment:
                    result += "Name-Comment: %s\n" % name_comment
                if name_email:
                    result += "Name-Email: %s\n" % name_email
                if passphrase:
                    result += "Passphrase: %s\n" % passphrase
                if expire_date != "Unlimited":
                    result += "Expire-Date: %s\n" % expire_date
                else:
                    result += "Expire-Date: 0\n"
                result += "</GnupgKeyParms>\n"
            else:
                pass
        else:
            self.set_widget_values(widgets, saved_values)

        dialog.hide()
        if result:
            # Setup and show progress Dialog
            self.progress = ""
            self.progress_entry = self.wtree.get_widget(
                "progress_entry").get_buffer()
            self.progress_entry.set_text("")
            gobject.timeout_add(500, self.update_progress)
            self.wtree.get_widget("GenerateProgress").show_all()
            # Start anynchronous key generation
            self.context.op_genkey_start(result, None, None)

    def gen_progress(self, what=None, type=None, current=None,
                     total=None, hook=None):
        "Gpg's progress_cb"
        if self.progress != None:
            self.progress += "%c" % type
        else:
            sys.stderr.write("%c" % type)

    def update_progress(self):
        "Timeout callback to yeild to gpg and update progress Dialog view"
        status = self.context.wait(False)
        if status == None:
            self.progress_entry.set_text(self.progress)
            return True
        elif status == 0:
            fpr = self.context.op_genkey_result().fpr
            self.add_key(self.context.get_key(fpr, 0))                    
            
        self.wtree.get_widget("GenerateProgress").hide()
        self.progress = None

        # FIXME. Should be a popup window on an error...
        if status:
            sys.stderr.write("Function return %d\n" % status)

        # Let callback to be removed.
        return False

    def on_generating_close_clicked(self, obj):
        # Request cancelation of the outstanding asynchonous call
        self.context.cancel()

    def get_password(self, hint, desc, hook):
        "Gpg's password_cb"
        dialog = self.wtree.get_widget("PasswordDialog")
        label = self.wtree.get_widget("pwd_prompt")
        entry = self.wtree.get_widget("password")
        label.set_text("Please supply %s's password%s:" %
                       (hint, (hook and (' '+hook)) or ''))
        if dialog.run() == gtk.RESPONSE_OK:
            result = entry.get_text()
        else:
            result = ""
        entry.set_text("")
        dialog.hide()
        return result

    def on_about_activate(self, obj):
        about = self.wtree.get_widget("AboutDialog")
        about.run()
        about.hide()

    def __init__(self, path):
        "new(path) path - location of the glade file"
        gladefile = os.path.join(path, "PyGtkGpgKeys.glade")
        self.wtree = gtk.glade.XML(gladefile)
        self.wtree.signal_autoconnect(self)

        self.mainwin = self.wtree.get_widget("GPGAdminWindow")
        self.treeview = self.wtree.get_widget("GPGKeysView")

        types = columns.values()
        types.sort()
        self.model = gtk.TreeStore(*[x.type for x in types])        

        self.context = Context()
        self.context.set_passphrase_cb(self.get_password, "")
        self.progress = None
        self.context.set_progress_cb(self.gen_progress, None)
        # Use mode.SIGS to include signatures in the list.
        self.context.set_keylist_mode(mode.SIGS)
        for key in self.context.op_keylist_all(None, 0):
            self.add_key(key)

        self.treeview.set_model(self.model)
        self.add_columns()

        gtk.main()

    def on_Exit(self, obj):
        gtk.main_quit()

try:
    # Glade file is expected to be in the same location as this script
    PyGtkGpgKeys(os.path.dirname(sys.argv[0]))
except IOError, message:
    print "%s:%s" %(sys.argv[0], message)
