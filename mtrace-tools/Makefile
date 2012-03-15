Q = @

QEMUDIR = ..
INSTDIR = /usr/local/bin
PYFLAKES = $(shell which pyflakes)

CXX  = g++
CC   = gcc

CWARNS	= -Wformat=2 -Wextra -Wmissing-noreturn -Wwrite-strings -Wshadow \
	   -Wno-unused-parameter -Wmissing-format-attribute \
	   -Wswitch-default -Wmissing-declarations -Wno-format-nonliteral \
	   -Wno-deprecated -Wno-format-security

CFLAGS  = -Wall -Werror $(CWARNS) -I$(QEMUDIR) -g -O3
LDFLAGS = -lz

HDRS	= $(QEMUDIR)/mtrace-magic.h util.h
MSCAN_HDRS = addr2line.hh \
	     argparse.hh \
	     calltrace.hh \
	     dissys.hh \
	     eyerman.hh \
	     false.hh \
	     hash.h \
	     json.hh \
	     mscan.hh \
	     sersec.hh \
	     sysaccess.hh \
	     percallstack.hh \
	     asharing.hh

all: mscan m2text mtrace-magic check-py

mscan: mscan.cc addr2line.cc hash.c $(HDRS) $(MSCAN_HDRS)
	@echo "  CXX      $@"
	$(Q)$(CXX) -o $@ $< addr2line.cc hash.c $(CFLAGS) -std=c++0x $(LDFLAGS)

m2text: m2text.c $(HDRS)
	@echo "  CC       $@"
	$(Q)$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

mtrace-magic: mtrace-magic.c $(HDRS)
	@echo "  CC       $@"
	$(Q)$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

.PHONY: install clean astyle check-py

ASTYLE = astyle
ASTYLE_OPTS = --suffix=none \
	      --style=stroustrup \
	      --align-pointer=type \
	      --convert-tabs \
	      --pad-header \
	      --lineend=linux \
	      --min-conditional-indent=4 \
	      --indent=spaces=4
astyle:
	$(ASTYLE) $(ASTYLE_OPTS) $(MSCAN_HDRS) mscan.cc addr2line.cc

check-py:
ifneq ($(PYFLAKES),)
	$(Q)pyflakes new-mtrace-image qemu-mtrace-linux mtrace-mosbench \
		     sersec-summary sersec-sort sersec-model
endif

install: mscan
	@echo "  INSTALL  $(INSTDIR)"
	$(Q)cp mscan $(INSTDIR)/mscan

clean:
	@echo "  CLEAN"
	$(Q)rm -f mscan m2text mtrace-magic
