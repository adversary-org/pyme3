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
%module gpgme
%include "cpointer.i"
%include "cstring.i"

// Allow use of None for strings.

%typemap(python,in) const char * {
  if ($input == Py_None)
    $1 = NULL;
  else if (PyString_Check($input))
    $1 = PyString_AsString($input);
  else {
    PyErr_Format(PyExc_TypeError,
                 "arg %d: expected string or None, got %s",
		 $argnum, $input->ob_type->tp_name);
    return NULL;
  }
}

// Release returned buffers as necessary.
%typemap(newfree) char * "free($1);";
%newobject gpgme_data_release_and_get_mem;

%{
/* Convert object to a pointer to gpgme type */
PyObject* object_to_gpgme_t(PyObject* input, const char* objtype, int argnum) {
  PyObject *pyname = NULL, *pypointer = NULL;
  pyname = PyObject_CallMethod(input, "_getctype", NULL);
  if (pyname == NULL) {
    PyErr_Format(PyExc_TypeError,
		 "arg %d: Expected an instance of type %s, but got %s",
		 argnum, objtype,
		 input == Py_None ? "None" : input->ob_type->tp_name);
    return NULL;
  }
  if (strcmp(PyString_AsString(pyname), objtype) != 0) {
    PyErr_Format(PyExc_TypeError,
		 "arg %d: Expected value of type %s, but got %s",
		 argnum, objtype, PyString_AsString(pyname));
    Py_DECREF(pyname);
    return NULL;
  }
  Py_DECREF(pyname);
  pypointer = PyObject_GetAttrString(input, "wrapped");
  if (pypointer == NULL) {
    PyErr_Format(PyExc_TypeError,
		 "arg %d: Use of uninitialized Python object %s",
		 argnum, objtype);
    return NULL;
  }
  return pypointer;
}
%}

%typemap(python,in) gpgme_key_t recp[] {
  int i, numb = 0;
  if (!PySequence_Check($input)) {
    PyErr_Format(PyExc_ValueError, "arg %d: Expected a list of gpgme_key_t",
		 $argnum);
    return NULL;
  }
  if((numb = PySequence_Length($input)) == 0) {
    $1 = NULL;
  } else {
    $1 = (gpgme_key_t*)malloc((numb+1)*sizeof(gpgme_key_t));
    for(i=0; i<numb; i++) {
      PyObject *pypointer = PySequence_GetItem($input, i);

      /* input = $input, 1 = $1, 1_descriptor = $1_descriptor */
      /* &1_descriptor = $&1_descriptor *1_descriptor = $*1_descriptor */

      // Following code is from swig's python.swg
      if ((SWIG_ConvertPtr(pypointer,(void **) &$1[i], $*1_descriptor,SWIG_POINTER_EXCEPTION | $disown )) == -1) {
	Py_DECREF(pypointer);
	return NULL;
      }
      Py_DECREF(pypointer);
    }
    $1[numb] = NULL;
  }
}
%typemap(freearg) gpgme_key_t recp[] {
  if ($1) free($1);
}

// Special handling for references to our objects.
%typemap(python,in) gpgme_data_t DATAIN {
  if ($input == Py_None)
    $1 = NULL;
  else {
    PyObject *pypointer = NULL;

    if((pypointer=object_to_gpgme_t($input, "$1_ltype", $argnum)) == NULL)
      return NULL;

    /* input = $input, 1 = $1, 1_descriptor = $1_descriptor */

    // Following code is from swig's python.swg

    if ((SWIG_ConvertPtr(pypointer,(void **) &$1, $1_descriptor,
         SWIG_POINTER_EXCEPTION | $disown )) == -1) {
      Py_DECREF(pypointer);
      return NULL;
    }
    Py_DECREF(pypointer);
  }
}

%apply gpgme_data_t DATAIN {gpgme_data_t plain, gpgme_data_t cipher,
			gpgme_data_t sig, gpgme_data_t signed_text,
			gpgme_data_t plaintext, gpgme_data_t keydata,
			gpgme_data_t pubkey, gpgme_data_t seckey,
			gpgme_data_t out};

// SWIG has problem interpreting ssize_t, off_t or gpgme_error_t in gpgme.h
%typemap(out) ssize_t, off_t, gpgme_error_t, gpgme_err_code_t, gpgme_err_source_t, gpg_error_t {
  $result = PyLong_FromLong($1);
}
%typemap(in) ssize_t, off_t, gpgme_error_t, gpgme_err_code_t, gpgme_err_source_t, gpg_error_t {
  $1 = PyLong_AsLong($input);
}

// Those are for gpgme_data_read() and gpgme_strerror_r()
%typemap(in) (void *buffer, size_t size), (char *buf, size_t buflen) {
   $2 = PyInt_AsLong($input);
   if ($2 < 0) {
     PyErr_SetString(PyExc_ValueError, "Positive integer expected");
     return NULL;
   }
   $1 = ($1_ltype) malloc($2+1);
}
%typemap(argout) (void *buffer, size_t size), (char *buf, size_t buflen) {
  Py_XDECREF($result);   /* Blow away any previous result */
  if (result < 0) {      /* Check for I/O error */
    free($1);
    return NULL;
  }
  $result = PyString_FromStringAndSize($1,result);
  free($1);
}

// Include mapper for edit callbacks
%typemap(python,in) (gpgme_edit_cb_t fnc, void *fnc_value) {
  $1 = (gpgme_edit_cb_t) pyEditCb;
  if ($input == Py_None)
    $2 = NULL;
  else
    $2 = $input;
}

// Include the header file both for cc (first) and for swig (second)
// Include for swig locally since we need to fix 'class' usage there.
%{
#include <gpgme.h>
%}
%include "gpgme.h"

%constant long EOF = GPG_ERR_EOF;

// Generating and handling pointers-to-pointers.

%pointer_functions(gpgme_ctx_t, gpgme_ctx_t_p);
%pointer_functions(gpgme_data_t, gpgme_data_t_p);
%pointer_functions(gpgme_key_t, gpgme_key_t_p);
%pointer_functions(gpgme_error_t, gpgme_error_t_p);
%pointer_functions(gpgme_trust_item_t, gpgme_trust_item_t_p);
%pointer_functions(gpgme_engine_info_t, gpgme_engine_info_t_p);
%pointer_functions(PyObject *, PyObject_p_p);
%pointer_functions(void *, void_p_p);

// Helper functions.

%{
#include <stdio.h>
%}
FILE *fdopen(int fildes, const char *mode);

%{
#include "helpers.h"
%}
%include "helpers.h"

%{
gpgme_error_t pyEditCb(void *opaque, gpgme_status_code_t status,
		       const char *args, int fd) {
  PyObject *func = NULL, *dataarg = NULL, *pyargs = NULL, *retval = NULL;
  PyObject *pyopaque = (PyObject *) opaque;
  gpgme_error_t err_status = 0;

  pygpgme_exception_init();

  if (PyTuple_Check(pyopaque)) {
    func = PyTuple_GetItem(pyopaque, 0);
    dataarg = PyTuple_GetItem(pyopaque, 1);
    pyargs = PyTuple_New(3);
  } else {
    func = pyopaque;
    pyargs = PyTuple_New(2);
  }
  
  PyTuple_SetItem(pyargs, 0, PyInt_FromLong((long) status));
  PyTuple_SetItem(pyargs, 1, PyString_FromString(args));
  if (dataarg) {
    Py_INCREF(dataarg);		/* Because GetItem doesn't give a ref but SetItem taketh away */
    PyTuple_SetItem(pyargs, 2, dataarg);
  }
  
  retval = PyObject_CallObject(func, pyargs);
  Py_DECREF(pyargs);
  if (PyErr_Occurred()) {
    err_status = pygpgme_exception2code();
  } else {
    if (fd>=0 && retval) {
      write(fd, PyString_AsString(retval), PyString_Size(retval));
      write(fd, "\n", 1);
    }
  }

  Py_XDECREF(retval);
  return err_status;
}
%}

