#!/usr/bin/env python

# $Id$

# Module: installer
# COPYRIGHT #
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
# END OF COPYRIGHT #


from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext
import os, os.path, sys

sys.path.append("pyme")
import version

def getconfig(what):
    cmd = os.popen("gpgme-config --%s" % what, "r")
    confdata = cmd.read()
    confdata = confdata.replace("\n", " ")
    assert cmd.close() == None, "error getting GPG config"
    confdata = confdata.replace("  ", " ")
    return [x for x in confdata.split(' ') if x != '']

cflags = getconfig('cflags')
libs = getconfig('libs')

swige = Extension("pyme._gpgme", ["gpgme_wrap.c", "helpers.c"],
                  extra_compile_args = cflags,
                  include_dirs = [os.getcwd()],
                  extra_link_args = cflags + libs)

setup(name = "gpgme",
      version = version.versionstr,
      description = version.description,
      author = version.author,
      author_email = version.author_email,
      url = version.homepage,
      ext_modules=[swige],
      packages = ['pyme', 'pyme.constants', 'pyme.constants.data',
                  'pyme.constants.keylist', 'pyme.constants.sig'], 
      license = version.copyright + \
                ", Licensed under the GPL version 2"
)

