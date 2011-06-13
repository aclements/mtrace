Q = @

QEMUDIR = ..
INSTDIR = /usr/local/bin

CXX  = g++
CC   = gcc

CWARNS	= -Wformat=2 -Wextra -Wmissing-noreturn -Wwrite-strings -Wshadow \
	   -Wno-unused-parameter -Wmissing-format-attribute -fno-builtin \
	   -Wswitch-default -Wmissing-declarations -Wno-format-nonliteral \
	   -Wno-deprecated -Wno-format-security

CFLAGS  = -Wall -Werror $(CWARNS) -I$(QEMUDIR) -g -O0
LDFLAGS = -lsqlite3 -lz

HDRS	= $(QEMUDIR)/mtrace-magic.h syms.hh calltrace.hh util.h objinfo.h

all: mscan

mscan: mscan.cc addr2line.cc hash.c $(HDRS) dissys.hh mscan.hh addr2line.hh sersec.hh json.hh hash.h
	@echo "CXX	$@"
	$(Q)$(CXX) -o $@ $< addr2line.cc hash.c $(CFLAGS) -std=c++0x $(LDFLAGS)

mt2db: mt2db.cc $(HDRS) sql.h lockset.hh block.h
	@echo "CXX	$@"
	$(Q)$(CXX) -o $@ $< $(CFLAGS) $(LDFLAGS)

mt2text: mt2text.c $(HDRS)
	@echo "CC	$@"
	$(Q)$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

objinfo: objinfo.cc $(HDRS)
	@echo "CXX	$@"
	$(Q)$(CXX) -DTEST -o $@ $< $(CFLAGS) $(LDFLAGS) -ldwarf -lelf

lockinfer: lockinfer.cc objinfo.cc addr2line.cc $(HDRS) addr2line.hh
	@echo "CXX	$@"
	$(Q)$(CXX) -o $@ lockinfer.cc objinfo.cc addr2line.cc $(CFLAGS) $(LDFLAGS) -ldwarf -lelf

install: mt2db mt2text
	@echo "INSTALL  $(INSTDIR)"
	$(Q)cp mt2db $(INSTDIR)/mt2db
	$(Q)cp mt2text $(INSTDIR)/mt2text

clean:
	@echo "CLEAN"
	$(Q)rm -f mt2db mt2text mscan
