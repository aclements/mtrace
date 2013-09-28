Q = @

QEMUDIR = ..
INSTDIR = /usr/local/bin
PYFLAKES = $(shell which pyflakes)
# Search for a local check-out of libelfin
export PKG_CONFIG_PATH += :../../libelfin/elf:../../libelfin/dwarf

CXX  = g++
CC   = gcc

CWARNS	= -Wformat=2 -Wextra -Wmissing-noreturn -Wwrite-strings -Wshadow \
	   -Wno-unused-parameter -Wmissing-format-attribute \
	   -Wswitch-default -Wmissing-declarations -Wno-format-nonliteral \
	   -Wno-deprecated -Wno-format-security

CFLAGS   := -Wall -Werror $(CWARNS) -g -O3 \
	$$(pkg-config --cflags 'libdwarf++ >= 0.1')
CXXFLAGS := $(CFLAGS) -std=c++0x
CPPFLAGS := -I$(QEMUDIR)
LDLIBS   := -lz $$(pkg-config --libs 'libdwarf++ >= 0.1')

MSCAN_SRCS = mscan.cc addr2line.cc hash.c bininfo.cc addrs.cc sbw0.cc serlen.cc demangle.cc

CLEAN =

all: mscan m2text mtrace-magic check-py m2json

mscan: $(addsuffix .o,$(basename $(MSCAN_SRCS)))
	@echo "  LD       $@"
	$(Q)$(CXX) $(LDFLAGS) -o $@ $(filter %.o %.a,$^) $(LOADLIBES) $(LDLIBS)
CLEAN += mscan $(addsuffix .o,$(basename $(MSCAN_SRCS)))

m2text: m2text.o
	@echo "  LD       $@"
	$(Q)$(CC) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS)
CLEAN += m2text m2text.o

m2json: m2json.o
	@echo "  LD       $@"
	$(Q)$(CXX) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS)
CLEAN += m2json m2json.o

mtrace-magic: mtrace-magic.o
	@echo "  LD       $@"
	$(Q)$(CC) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS)
CLEAN += mtrace-magic mtrace-magic.o

%.o: %.c
	@echo "  CC       $@"
	$(Q)$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $< -MD -MP -MF .$*.d

%.o: %.cc
	@echo "  CXX      $@"
	$(Q)$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $< -MD -MP -MF .$*.d

-include .*.d

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
	$(Q)pyflakes new-mtrace-image qemu-mtrace-linux mtrace-mosbench
endif

install: mscan
	@echo "  INSTALL  $(INSTDIR)"
	$(Q)cp mscan $(INSTDIR)/mscan

clean:
	@echo "  CLEAN"
	$(Q)rm -f $(CLEAN) .*.d
