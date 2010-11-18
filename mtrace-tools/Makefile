Q = @

QEMUDIR = ..

CXX  = g++

CWARNS	= -Wformat=2 -Wextra -Wmissing-noreturn -Wwrite-strings -Wshadow \
	   -Wno-unused-parameter -Wmissing-format-attribute -fno-builtin \
	   -Wswitch-default -Wmissing-declarations -Wno-format-nonliteral \
	   -Wno-deprecated -Wno-format-security

CFLAGS  = -Wall -Werror $(CWARNS) -I$(QEMUDIR) -g -O2
LDFLAGS = -lsqlite3

all: mt2db

mt2db: mt2db.cc $(QEMUDIR)/mtrace-file.h
	@echo "CXX	$@"
	$(Q)$(CXX) -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
	@echo "CLEAN"
	$(Q)rm -f mt2db
