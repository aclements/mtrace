Q = @

QEMUDIR = ..
INSTDIR = /usr/local/bin

CXX  = g++

CWARNS	= -Wformat=2 -Wextra -Wmissing-noreturn -Wwrite-strings -Wshadow \
	   -Wno-unused-parameter -Wmissing-format-attribute -fno-builtin \
	   -Wswitch-default -Wmissing-declarations -Wno-format-nonliteral \
	   -Wno-deprecated -Wno-format-security

CFLAGS  = -Wall -Werror $(CWARNS) -I$(QEMUDIR) -g -O2
LDFLAGS = -lsqlite3

HDRS	= $(QEMUDIR)/mtrace-magic.h syms.hh callstack.hh util.h

all: mt2db

mt2db: mt2db.cc $(HDRS)
	@echo "CXX	$@"
	$(Q)$(CXX) -o $@ $< $(CFLAGS) $(LDFLAGS)

install: mt2db
	@echo "INSTALL  $(INSTDIR)"
	$(Q)cp mt2db $(INSTDIR)/mt2db

clean:
	@echo "CLEAN"
	$(Q)rm -f mt2db
