# $Id$
# Copyright (C) 2004 Igor Belyi <belyi@users.sourceforge.net>
# Copyright (C) 2002 John Goerzen <jgoerzen@complete.org>
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

# import generators for portability with python2.2
from __future__ import generators

import gpgme
from errors import errorcheck
import errors
from util import GpgmeWrapper

class Context(GpgmeWrapper):
    """From the GPGME C documentation:

    * All cryptographic operations in GPGME are performed within a
    * context, which contains the internal state of the operation as well as
    * configuration parameters.  By using several contexts you can run
    * several cryptographic operations in parallel, with different
    * configuration.

    Thus, this is the place that you will usually start."""

    def _getctype(self):
        return 'gpgme_ctx_t'
    
    def _getnameprepend(self):
        return 'gpgme_'

    def _errorcheck(self, name):
        """This function should list all functions returning gpgme_error_t"""
        if (name.startswith('gpgme_op_') and \
            not name.endswith('_result')) or \
            name == 'gpgme_signers_add' or \
            name == 'gpgme_set_locale' or \
            name == 'gpgme_set_keylist_mode' or \
            name == 'gpgme_set_protocol':
            return 1
        return 0

    def __init__(self):
        tmp = gpgme.new_gpgme_ctx_t_p()
        errorcheck(gpgme.gpgme_new(tmp))
        self.wrapped = gpgme.gpgme_ctx_t_p_value(tmp)
        gpgme.delete_gpgme_ctx_t_p(tmp)
        self.last_passcb = None
        self.last_progresscb = None

    def __del__(self):
        self._free_passcb()
        self._free_progresscb()
        gpgme.gpgme_release(self.wrapped)

    def _free_passcb(self):
        if self.last_passcb != None:
            gpgme.pygpgme_clear_generic_cb(self.last_passcb)
            gpgme.delete_PyObject_p_p(self.last_passcb)
            self.last_passcb = None

    def _free_progresscb(self):
        if self.last_progresscb != None:
            gpgme.pygpgme_clear_generic_cb(self.last_progresscb)
            gpgme.delete_PyObject_p_p(self.last_progresscb)
            self.last_progresscb = None

    def op_keylist_all(self, *args, **kwargs):
        apply(self.op_keylist_start, args, kwargs)
        key = self.op_keylist_next()
        while key:
            yield key
            key = self.op_keylist_next()

    def op_keylist_next(self):
        """Returns the next key in the list created
        by a call to op_keylist_start().  The object returned
        is of type Key."""
        ptr = gpgme.new_gpgme_key_t_p()
        try:
            errorcheck(gpgme.gpgme_op_keylist_next(self.wrapped, ptr))
            key = gpgme.gpgme_key_t_p_value(ptr)
        except errors.GPGMEError, excp:
            key = None
            if excp.getcode() != errors.EOF:
                raise excp
        gpgme.delete_gpgme_key_t_p(ptr)
        return key
    
    def get_key(self, fpr, secret):
        """Return the key corresponding to the fingerprint 'fpr'"""
        ptr = gpgme.new_gpgme_key_t_p()
        errorcheck(gpgme.gpgme_get_key(self.wrapped, fpr, ptr, secret))
        key = gpgme.gpgme_key_t_p_value(ptr)
        gpgme.delete_gpgme_key_t_p(ptr)
        return key

    def op_trustlist_all(self, *args, **kwargs):
        apply(self.op_trustlist_start, args, kwargs)
        trust = self.ctx.op_trustlist_next()
        while trust:
            yield trust
            trust = self.ctx.op_trustlist_next()

    def op_trustlist_next(self):
        """Returns the next trust item in the list created
        by a call to op_trustlist_start().  The object returned
        is of type TrustItem."""
        ptr = gpgme.new_gpgme_trust_item_t_p()
        try:
            errorcheck(gpgme.gpgme_op_trustlist_next(self.wrapped, ptr))
            trust = gpgme.gpgme_trust_item_t_p_value(ptr)
        except errors.GPGMEError, excp:
            trust = None
            if excp.getcode() != errors.EOF:
                raise
        gpgme.delete_gpgme_trust_item_t_p(ptr)
        return trust

    def set_passphrase_cb(self, func, hook):
        """Sets the passphrase callback to the function specified by func.

        When the system needs a passphrase, it will call func with two args:
        desc, a string describing the passphrase it needs; and hook,
        the data passed in as hook here.

        The hook argument is mandatory for obscure technical reasons
        (Python hands the C code a 'cell' instead of a tuple if I made
        this optional.)  It is suggested that you pass a None value for
        hook if your called functions do not require a specific hook value.

        Please see the GPGME manual for more information.
        """
        self._free_passcb()
        self.last_passcb = gpgme.new_PyObject_p_p()
        hookdata = (func, hook)
        gpgme.pygpgme_set_passphrase_cb(self.wrapped, hookdata, self.last_passcb)

    def set_progress_cb(self, func, hook):
        """Sets the progress meter callback to the function specified by

        This function will be called to provide an interactive update of
        the system's progress.

        The hook argument is mandatory for obscure technical reasons
        (Python hands the C code a 'cell' instead of a tuple if I made
        this optional.)  It is suggested that you pass a None value for
        hook if your called functions do not require a specific hook value.

        Please see the GPGME manual for more information."""
        self._free_progresscb()
        self.last_progresscb = gpgme.new_PyObject_p_p()
        hookdata = (func, hook)
        gpgme.pygpgme_set_progress_cb(self.wrapped, hookdata, self.last_progresscb)

    def wait(self, hang):
        """Wait for asynchronous call to finish. Wait forever if hang is True

        Return:
            On an async call completion its return status.
            On timeout - None.

        Please read the GPGME manual for more information."""
        ptr = gpgme.new_gpgme_error_t_p()
        context = gpgme.gpgme_wait(self.wrapped, ptr, hang)
        status = gpgme.gpgme_error_t_p_value(ptr)
        gpgme.delete_gpgme_error_t_p(ptr)
        
        if context == None:
            errorcheck(status)
            return None
        else:
            return status

    def op_edit(self, key, func, fnc_value, out):
        """Start key editing using supplied callback function"""
        opaquedata = (func, fnc_value)
        errorcheck(gpgme.gpgme_op_edit(self.wrapped, key, opaquedata, out))
    
class Data(GpgmeWrapper):
    """From the GPGME C manual:

* A lot of data has to be exchanged between the user and the crypto
* engine, like plaintext messages, ciphertext, signatures and information
* about the keys.  The technical details about exchanging the data
* information are completely abstracted by GPGME.  The user provides and
* receives the data via `gpgme_data_t' objects, regardless of the
* communication protocol between GPGME and the crypto engine in use.

        This Data class is the implementation of the GpgmeData objects.

        Please see the information about __init__ for instantiation."""

    def _getctype(self):
        return 'gpgme_data_t'
    
    def _getnameprepend(self):
        return 'gpgme_data_'

    def _errorcheck(self, name):
        """This function should list all functions returning gpgme_error_t"""
        if name == 'gpgme_data_release_and_get_mem' or \
               name == 'gpgme_data_get_encoding' or \
               name == 'gpgme_data_seek':
            return 0
        return 1
    
    def __init__(self, string = None, file = None, offset = None,
                 length = None, cbs = None):
        """Initialize a new gpgme_data_t object.

        If no args are specified, make it an empty object.

        If string alone is specified, initialize it with the data
        contained there.

        If file, offset, and length are all specified, file must
        be either a filename or a file-like object, and the object
        will be initialized by reading the specified chunk from the file.

        If cbs is specified, it MUST be a tuple of the form:

        ((read_cb, write_cb, seek_cb, release_cb), hook)

        where func is a callback function taking two arguments (count,
        hook) and returning a string of read data, or None on EOF.
        This will supply the read() method for the system.

        If file is specified without any other arguments, then
        it must be a filename, and the object will be initialized from
        that file.

        Any other use will result in undefined or erroneous behavior."""
        self.wrapped = None
        self.last_readcb = None

        if cbs != None:
            apply(self.new_from_cbs, cbs)
        elif string != None:
            self.new_from_mem(string)
        elif file != None and offset != None and length != None:
            self.new_from_filepart(file, offset, length)
        elif file != None:
            if type(file) == type("x"):
                self.new_from_file(file)
            else:
                self.new_from_fd(file)
        else:
            self.new()

    def __del__(self):
        if self.wrapped != None:
            gpgme.gpgme_data_release(self.wrapped)
        self._free_readcb()

    def _free_readcb(self):
        if self.last_readcb != None:
            gpgme.pygpgme_clear_generic_cb(self.last_readcb)
            gpgme.delete_PyObject_p_p(self.last_readcb)
            self.last_readcb = None

    def new(self):
        tmp = gpgme.new_gpgme_data_t_p()
        errorcheck(gpgme.gpgme_data_new(tmp))
        self.wrapped = gpgme.gpgme_data_t_p_value(tmp)
        gpgme.delete_gpgme_data_t_p(tmp)

    def new_from_mem(self, string, copy = 1):
        tmp = gpgme.new_gpgme_data_t_p()
        errorcheck(gpgme.gpgme_data_new_from_mem(tmp,string,len(string),copy))
        self.wrapped = gpgme.gpgme_data_t_p_value(tmp)
        gpgme.delete_gpgme_data_t_p(tmp)

    def new_from_file(self, filename, copy = 1):
        tmp = gpgme.new_gpgme_data_t_p()
        errorcheck(gpgme.gpgme_data_new_from_file(tmp, filename, copy))
        self.wrapped = gpgme.gpgme_data_t_p_value(tmp)
        gpgme.delete_gpgme_data_t_p(tmp)

    def new_from_cbs(self, funcs, hook):
        """Argument funcs must be a 4 element tuple with callbacks:
        (read_cb, write_cb, seek_cb, release_cb)"""
        tmp = gpgme.new_gpgme_data_t_p()
        self._free_readcb()
        self.last_readcb = gpgme.new_PyObject_p_p()
        hookdata = (funcs, hook)
        gpgme.pygpgme_data_new_from_cbs(tmp, hookdata, self.last_readcb)
        self.wrapped = gpgme.gpgme_data_t_p_value(tmp)
        gpgme.delete_gpgme_data_t_p(tmp)

    def new_from_filepart(self, file, offset, length):
        """This wraps the GPGME gpgme_data_new_from_filepart() function.
        The argument "file" may be:

        1. a string specifying a file name, or
        3. a a file-like object. supporting the fileno() call and the mode
           attribute."""

        tmp = gpgme.new_gpgme_data_t_p()
        filename = None
        fp = None

        if type(file) == type("x"):
            filename = file
        else:
            fp = gpgme.fdopen(file.fileno(), file.mode)
            if fp == None:
                raise ValueError, "Failed to open file from %s arg %s" % \
                      (str(type(file)), str(file))

        errorcheck(gpgme.gpgme_data_new_from_filepart(tmp, filename, fp,
                                                      offset, length))
        self.wrapped = gpgme.gpgme_data_t_p_value(tmp)
        gpgme.delete_gpgme_data_t_p(tmp)

    def new_from_fd(self, file):
        """This wraps the GPGME gpgme_data_new_from_fd() function.
        The argument "file" may be a file-like object, supporting the fileno()
        call and the mode attribute."""
        
        tmp = gpgme.new_gpgme_data_t_p()
        fp = gpgme.fdopen(file.fileno(), file.mode)
        if fp == None:
            raise ValueError, "Failed to open file from %s arg %s" % \
                  (str(type(file)), str(file))
        errorcheck(gpgme_data_new_from_fd(tmp, fp))
        self.wrapped = gpgme.gpgme_data_t_p_value(tmp)
        gpgme.delete_gpgme_data_t_p(tmp)

    def new_from_stream(self, file):
        """This wrap around gpgme_data_new_from_stream is an alias for
        new_from_fd() method since in python there's not difference
        between file stream and file descriptor"""
        self.new_from_fd(file)
    
    def write(self, buffer):
        errorcheck(gpgme.gpgme_data_write(self.wrapped, buffer, len(buffer)))

    def read(self, size = -1):
        """Read at most size bytes, returned as a string.
        
        If the size argument is negative or omitted, read until EOF is reached.

        Returns the data read, or the empty string if there was no data
        to read before EOF was reached."""
        
        if size == 0:
            return ''

        if size > 0:
            return gpgme.gpgme_data_read(self.wrapped, size)
        else:
            retval = ''
            while 1:
                result = gpgme.gpgme_data_read(self.wrapped, 10240)
                if len(result) == 0:
                    break
                retval += result
            return retval

def pubkey_algo_name(algo):
    return gpgme.gpgme_pubkey_algo_name(algo)

def hash_algo_name(algo):
    return gpgme.gpgme_hash_algo_name(algo)

def get_protocol_name(proto):
    return gpgme.gpgme_get_protocol_name(proto)

def check_version(version):
    return gpgme.gpgme_check_version(version)

def engine_check_version (proto):
    try:
        errorcheck(gpgme.gpgme_engine_check_version(proto))
        return True
    except errors.GPGMEError:
        return False

def get_engine_info():
    ptr = gpgme.new_gpgme_engine_info_t_p()
    try:
        errorcheck(gpgme.gpgme_get_engine_info(ptr))
        info = gpgme.gpgme_engine_info_t_p_value(ptr)
    except errors.GPGMEError:
        info = None
    gpgme.delete_gpgme_engine_info_t_p(ptr)
    return info

def wait(hang):
    """Wait for asynchronous call on any Context  to finish.
    Wait forever if hang is True.
    
    For finished anynch calls it returns a tuple (status, context):
        status  - status return by asnynchronous call.
        context - context which caused this call to return.
    On timeout it returns None
        
    Please read the GPGME manual of more information."""
    ptr = gpgme.new_gpgme_error_t_p()
    context = gpgme.gpgme_wait(None, ptr, hang)
    status = gpgme.gpgme_error_t_p_value(ptr)
    gpgme.gpgme_error_t_p_delete(ptr)
    if context == None:
        errorcheck(status)
        return None
    else:
        return (status, context)
