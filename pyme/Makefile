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

FILE = gpgme
PYPATH = pyme
PYFILE = $(FILE).py
CFILE = $(FILE)_wrap.c
HFILE = $(FILE).h
USRHFILE = /usr/include/$(HFILE)
SWIGSOURCE = $(FILE).i
DOCMODSDIRS := $(shell find pyme -type d | grep -v CVS | sed 'sx/x.xg')
DOCMODSFILES := $(shell find pyme -name "*.py" | egrep -v __init__ | grep -v gpgme.py | grep -v CVS | sed 'sx/x.xg')
DOCMODS := $(DOCMODSDIRS) $(DOCMODSFILES:.py=)
SWIGOPT := `gpgme-config --cflags` -I/usr/include 

build: swig
	$(PYTHON) setup.py build -b build

install: build
	$(PYTHON) setup.py install

info:
	@echo $(DOCMODS)

swig: $(CFILE) $(PYPATH)/$(PYFILE)

# Work around a problem of gpgme.h containing class structure fields.
$(HFILE): $(USRHFILE)
	sed -e 's/ class / _py_obsolete_class /' $(USRHFILE) >$(HFILE)

$(CFILE) $(PYPATH)/$(PYFILE): $(SWIGSOURCE) $(HFILE) helpers.h
	swig -python $(SWIGOPT) $(SWIGSOURCE)
	mv $(PYFILE) $(PYPATH)/$(PYFILE)

clean:
	-python setup.py clean --all
	-rm -r build build2.2 build2.3 setup.cfg
	-rm `find . -name "*~"` `find . -name "*.pyc"` `find . -name "*.so"`
	-find . -name auth -exec rm -vf {}/password {}/username \;

#changelog:
#	svn log -v > ChangeLog

reallyclean: clean
	-rm doc/*.html doc/gpgme/*.html $(CFILE) $(PYPATH)/$(PYFILE) $(HFILE)

docs:
	-rm doc/*.html
	cd doc; for MOD in $(DOCMODS); do PYTHONPATH=`echo ../build/lib*` pydoc -w $$MOD; done

