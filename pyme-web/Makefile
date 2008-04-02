# $Id$

WEBFILES=index.html default.css $(shell find doc -name "*.html")
PROJPATH=/home/groups/p/py/pyme
DOCPATH=$(PROJPATH)/htdocs

install:
	ssh shell.sf.net "cd $(DOCPATH) && rm -f $(WEBFILES)"
	for FILE in $(WEBFILES); do \
	  scp -p $$FILE shell.sf.net:$(DOCPATH)/$$FILE; \
	done
	ssh shell.sf.net "cd $(DOCPATH) && chmod a+r $(WEBFILES)"

clean:
	$(shell find ./ -name '*~' -exec rm -f {} \;)
