# Makefile to generate a zip file with IOCs
# Olivier Bilodeau <bilodeau@eset.com>
# Copyright (c) ESET 2014

HEAD=$(shell git show -s --format=%h)

default: distrib

clean:
	rm -f *.zip

distrib: clean zip

zip:
	git archive -v -o malware-ioc-$(HEAD).zip HEAD
