Q = @

QEMUDIR = ..
INSTDIR = /usr/local/bin

CXX  = g++
CC   = gcc

CWARNS	= -Wformat=2 -Wextra -Wmissing-noreturn -Wwrite-strings -Wshadow \
	   -Wno-unused-parameter -Wmissing-format-attribute -fno-builtin \
	   -Wswitch-default -Wmissing-declarations -Wno-format-nonliteral \
	   -Wno-deprecated -Wno-format-security

CFLAGS  = -Wall -Werror $(CWARNS) -I$(QEMUDIR) -g -O3
LDFLAGS = -lz

HDRS	= $(QEMUDIR)/mtrace-magic.h util.h
MSCAN_HDRS = addr2line.hh \
	     calltrace.hh \
	     dissys.hh \
	     false.hh \
	     hash.h \
	     json.hh \
	     mscan.hh \
	     sersec.hh \
	     sysaccess.hh

all: mscan m2text

mscan: mscan.cc addr2line.cc hash.c $(HDRS) $(MSCAN_HDRS)
	@echo "  CXX      $@"
	$(Q)$(CXX) -o $@ $< addr2line.cc hash.c $(CFLAGS) -std=c++0x $(LDFLAGS)

m2text: m2text.c $(HDRS)
	@echo "  CC       $@"
	$(Q)$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

.PHONY: install clean

install: mscan
	@echo "  INSTALL  $(INSTDIR)"
	$(Q)cp mscan $(INSTDIR)/mscan

clean:
	@echo "  CLEAN"
	$(Q)rm -f mscan
