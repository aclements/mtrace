Q = @

QEMUDIR = ..
INSTDIR = /usr/local/bin
PYFLAKES = $(shell which pyflakes)

# Author date (e.g., from git log) of known-working libelfin commit
LIBELFIN_DATE := Mon Apr 2 15:11:27 2012 -0400

CXX  = g++
CC   = gcc

CWARNS	= -Wformat=2 -Wextra -Wmissing-noreturn -Wwrite-strings -Wshadow \
	   -Wno-unused-parameter -Wmissing-format-attribute \
	   -Wswitch-default -Wmissing-declarations -Wno-format-nonliteral \
	   -Wno-deprecated -Wno-format-security

CFLAGS   := -Wall -Werror $(CWARNS) -g -O3
CXXFLAGS := $(CFLAGS) -std=c++0x
CPPFLAGS := -I$(QEMUDIR) -Ilibelfin/elf -Ilibelfin/dwarf
LDLIBS   := -lz

MSCAN_SRCS = mscan.cc addr2line.cc hash.c bininfo.cc sersec.cc addrs.cc

CLEAN =

all: mscan m2text mtrace-magic check-py

mscan: $(addsuffix .o,$(basename $(MSCAN_SRCS))) \
		libelfin/dwarf/libdwarf++.a libelfin/elf/libelf++.a
	@echo "  LD       $@"
	$(Q)$(CXX) $(LDFLAGS) -o $@ $(filter %.o %.a,$^) $(LOADLIBES) $(LDLIBS)
CLEAN += mscan $(addsuffix .o,$(basename $(MSCAN_SRCS)))

m2text: m2text.o
	@echo "  LD       $@"
	$(Q)$(CC) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS)
CLEAN += m2text m2text.o

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

libelfin/%: check-libelfin
	@$(MAKE) -C $(@D) -q $(@F) || $(MAKE) -C $(@D) $(@F)

check-libelfin:
	@if [ ! -d libelfin/.git ]; then \
	 echo "libelfin not found; please"; \
	 echo "$$ git clone git+ssh://am.lcs.mit.edu/home/am6/mpdev/libelfin.git"; \
	 false; fi
	@cd libelfin; \
	 REV=$$(git log --format='%H %ad' --all | awk '/$(LIBELFIN_DATE)/ {print $$1; exit}'); \
	 if [ "x$$REV" = x ]; then \
	   echo "WARNING: libelfin commit from $(LIBELFIN_DATE) not found"; \
	   if [ "x$$(git rev-list -n 1 --after=\"$$REV\" --all)" = x ]; then \
	     echo "WARNING: Your libelfin clone appears to be out of date"; \
	   fi; \
	 elif [ "x$$(git rev-list -n 1 $$REV..HEAD)" != x ]; then \
	   echo "WARNING: libelfin is ahead of expected rev $$REV"; \
	 elif [ "x$$(git rev-list -n 1 HEAD..$$REV)" != x ]; then \
	   echo "WARNING: libelfin is behind expected rev $$REV"; \
	 fi

.PHONY: install clean astyle check-py check-libelfin

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
	$(Q)rm -f $(CLEAN) .*.d
