Q = @

QEMUDIR = ..
INSTDIR = /usr/local/bin

CXX  = g++

CWARNS	= -Wformat=2 -Wextra -Wmissing-noreturn -Wwrite-strings -Wshadow \
	   -Wno-unused-parameter -Wmissing-format-attribute -fno-builtin \
	   -Wswitch-default -Wmissing-declarations -Wno-format-nonliteral \
	   -Wno-deprecated -Wno-format-security

CFLAGS  = -Wall -Werror $(CWARNS) -I$(QEMUDIR) -g -O3
LDFLAGS = -lz

HDRS	= $(QEMUDIR)/mtrace-magic.h util.h

all: mscan

mscan: mscan.cc addr2line.cc hash.c $(HDRS) dissys.hh mscan.hh addr2line.hh sersec.hh json.hh hash.h sysaccess.hh false.hh
	@echo "CXX	$@"
	$(Q)$(CXX) -o $@ $< addr2line.cc hash.c $(CFLAGS) -std=c++0x $(LDFLAGS)

.PHONY: install clean

install: mscan
	@echo "INSTALL  $(INSTDIR)"
	$(Q)cp mscan $(INSTDIR)/mscan

clean:
	@echo "CLEAN"
	$(Q)rm -f mscan
