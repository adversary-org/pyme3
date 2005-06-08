# $Id$

WEBFILES=index.html $(shell find doc -name "*.html")
PROJPATH=/home/groups/p/py/pyme
DOCPATH=$(PROJPATH)/htdocs

install:
	for FILE in $(WEBFILES); do \
	  scp -p $$FILE shell.sf.net:$(DOCPATH)/$$FILE; \
	  ssh shell.sf.net "cd $(DOCPATH) && chmod a+r $$FILE"; \
	done

clean:
	$(shell find ./ -name '*~' -exec rm -f {} \;)
