# $Id$

WEBFILES=index.html
PROJPATH=/home/groups/p/py/pyme
DOCPATH=$(PROJPATH)/htdocs

install:
	scp $(WEBFILES) shell.sf.net:$(DOCPATH)
	ssh shell.sf.net "cd $(DOCPATH) && chmod a+r $(WEBFILES)"

clean:
	rm -f *~
