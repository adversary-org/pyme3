/*
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
*/
#include <stdio.h>
#include <gpgme.h>
#include <stdlib.h>
#include <string.h>
#include "Python.h"
#include "helpers.h"

void pygpgme_clear_generic_cb(PyObject **cb) {
  Py_DECREF(*cb);
}

static gpgme_error_t pyPassphraseCb(void *hook,
				    const char *uid_hint,
				    const char *passphrase_info,
				    int prev_was_bad,
				    int fd) {
  PyObject *pyhook = NULL;
  PyObject *func = NULL;
  PyObject *args = NULL;
  PyObject *retval = NULL;
  PyObject *dataarg = NULL;

  pyhook = (PyObject *) hook;
  func = PyTuple_GetItem(pyhook, 0);
  dataarg = PyTuple_GetItem(pyhook, 1);

  args = PyTuple_New(3);
  PyTuple_SetItem(args, 0, PyString_FromString(uid_hint));
  PyTuple_SetItem(args, 1, PyString_FromString(passphrase_info));
  Py_INCREF(dataarg);		/* Because GetItem doesn't give a ref but SetItem taketh away */
  PyTuple_SetItem(args, 2, dataarg);
  retval = PyObject_CallObject(func, args);
  Py_DECREF(args);
  if (!retval) {
    write(fd, "\n", 1);
  } else {
    write(fd, PyString_AsString(retval), PyString_Size(retval));
    write(fd, "\n", 1);
    Py_DECREF(retval);
  }
  return 0;
}

void pygpgme_set_passphrase_cb(gpgme_ctx_t ctx, PyObject *cb,
			       PyObject **freelater) {
  Py_INCREF(cb);
  *freelater = cb;
  gpgme_set_passphrase_cb(ctx, (gpgme_passphrase_cb_t)pyPassphraseCb, (void *) cb);
}

static void pyProgressCb(void *hook, const char *what, int type, int current,
			 int total) {
  PyObject *func = NULL, *dataarg = NULL, *args = NULL, *retval = NULL;
  PyObject *pyhook = (PyObject *) hook;
  
  func = PyTuple_GetItem(pyhook, 0);
  dataarg = PyTuple_GetItem(pyhook, 1);

  args = PyTuple_New(5);
  
  PyTuple_SetItem(args, 0, PyString_FromString(what));
  PyTuple_SetItem(args, 1, PyInt_FromLong((long) type));
  PyTuple_SetItem(args, 2, PyInt_FromLong((long) current));
  PyTuple_SetItem(args, 3, PyInt_FromLong((long) total));
  Py_INCREF(dataarg);		/* Because GetItem doesn't give a ref but SetItem taketh away */
  PyTuple_SetItem(args, 4, dataarg);
  
  retval = PyObject_CallObject(func, args);
  Py_DECREF(args);
  Py_DECREF(retval);
}

void pygpgme_set_progress_cb(gpgme_ctx_t ctx, PyObject *cb, PyObject **freelater){
  Py_INCREF(cb);
  *freelater = cb;
  gpgme_set_progress_cb(ctx, (gpgme_progress_cb_t) pyProgressCb, (void *) cb);
}

int pyReadCb(void *hook, char *buffer, size_t count, size_t *nread) {
  PyObject *func = NULL, *dataarg = NULL, *args = NULL, *retval = NULL;
  PyObject *pyhook = (PyObject *) hook;
  int strsize = 0;
  
  func = PyTuple_GetItem(pyhook, 0);
  dataarg = PyTuple_GetItem(pyhook, 1);

  args = PyTuple_New(2);
  
  PyTuple_SetItem(args, 0, PyInt_FromLong((long) count));
  Py_INCREF(dataarg);
  PyTuple_SetItem(args, 1, dataarg);
  
  retval = PyObject_CallObject(func, args);
  Py_DECREF(args);

  if ((!nread) || (!buffer)) {
    /* Returned EOF -- signal EOF OR
       nread is NULL OR
       buffer is NULL */
    Py_DECREF(retval);
    return 0;
  }
  strsize = PyString_Size(retval);
  if (strsize == 0) {
    Py_DECREF(retval);
    *nread = 0;
    return -1;
  }
  *nread = strsize;
  memcpy(buffer, PyString_AsString(retval), strsize);
  Py_DECREF(retval);
  return 0;
}

void pygpgme_data_new_with_read_cb(gpgme_data_t *dh, PyObject *cb, 
                                   PyObject **freelater){
  Py_INCREF(cb);
  *freelater = cb;
  gpgme_data_new_with_read_cb(dh, pyReadCb, (void *) cb);
}

