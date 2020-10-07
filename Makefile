NAME = evtssl
VERSION = 0.6

LIBSRCDIR = src
LIBOBJDIR = libobj

EXSRCDIR = examples
EXOBJDIR = examplesobj

INCDIR = include

BINDIR = bin


DIRS = $(BINDIR) $(LIBOBJDIR) $(EXOBJDIR)


CFLAGS += -std=gnu99 -pedantic -Wall -Wextra -I$(INCDIR)
DEBUG = 1

ifeq (1,$(DEBUG))
CFLAGS += -g
else
CFLAGS += -O2
endif

LDFLAGS += -levent -levent_openssl -lssl -lcrypto

LIBCFLAGS := $(CFLAGS) -fPIC
LIBLDFLAGS := $(LDFLAGS) -shared -Lbin

EXLDFLAGS := $(LDFLAGS) -l$(NAME)

LIBSOURCES = $(wildcard $(LIBSRCDIR)/*.c)
LIBOBJECTS = $(patsubst $(LIBSRCDIR)/%.c,$(LIBOBJDIR)/%.o,$(LIBSOURCES))
LIBHEADERS = $(wildcard $(INCDIR)/*.h)
LIBBIN = $(BINDIR)/lib$(NAME).so

EXSOURCES = $(wildcard $(EXSRCDIR)/*.c)
EXOBJECTS = $(patsubst $(EXSRCDIR)/%.c,$(EXOBJDIR)/%.o,$(EXSOURCES))
EXBINS = $(patsubst $(EXSRCDIR)/%.c,$(BINDIR)/%,$(wildcard $(EXSRCDIR)/*.c))

SOURCES = $(LIBSOURCES) $(EXSOURCES)
HEADERS = $(wildcard $(LIBSRCDIR)/*.h) $(wildcard $(EXSRCDIR)/*.h) $(LIBHEADERS)

.PHONY: all clean default examples debug install uninstall

default: $(LIBBIN)

all: default examples

examples: $(EXBINS)

debug:
	$(MAKE) DEBUG=1

$(LIBBIN): % : %.$(VERSION)
	cd $(BINDIR) ; ln -sf $(patsubst $(BINDIR)/%,%,$^) $(patsubst $(BINDIR)/%,%,$@)


$(LIBBIN).$(VERSION): $(LIBOBJECTS) | $(BINDIR)
	$(CC) $^ -o $@ $(LIBLDFLAGS)
	chmod 755 $@

$(EXBINS): $(BINDIR)/% : $(EXOBJDIR)/%.o | $(BINDIR) $(LIBBIN)
	$(CC) $^ -o $@ $(EXLDFLAGS) $(CFLAGS)


$(LIBOBJECTS): $(LIBOBJDIR)/%.o : $(LIBSRCDIR)/%.c | $(LIBOBJDIR)
	$(CC) -c $< -o $@ $(LIBCFLAGS)

$(EXOBJECTS): $(EXOBJDIR)/%.o : $(EXSRCDIR)/%.c | $(EXOBJDIR)
	$(CC) -c $< -o $@ $(CFLAGS)


$(DIRS):
	mkdir -p $@

clean::
	rm -rf $(DIRS)

#from here on it's cheap install-stuff. probably rubbish

ROOT ?= /
usr ?= usr/local/

usrdir = $(ROOT)$(usr)
libdir = $(usrdir)lib/
includedir = $(usrdir)include/
bindir = $(usrdir)bin/

INSTALL_BIN_CMD=install -m 0755

install_lib: $(LIBBIN).$(VERSION)
	mkdir -p $(libdir)
	$(INSTALL_BIN_CMD) $^ $(libdir)
	cd $(libdir) ; ln -fs $(patsubst $(BINDIR)/%,%,$(LIBBIN).$(VERSION)) $(patsubst $(BINDIR)/%,%,$(LIBBIN))

install_headers: $(LIBHEADERS)
	mkdir -p $(includedir)
	install $(LIBHEADERS) $(includedir)

install_examples: $(EXBINS)
	mkdir -p $(bindir)
	$(INSTALL_BIN_CMD) $^ $(bindir)

install: install_lib install_headers install_examples

uninstall_lib:
	rm -f $(patsubst $(BINDIR)/%,$(libdir)/%*,$(LIBBIN))

uninstall_headers:
	rm -f $(patsubst $(INCDIR)/%,$(includedir)/%,$(LIBHEADERS))

uninstall_examples:
	rm -f $(patsubst $(BINDIR)/%,$(bindir)/%,$(EXBINS))

uninstall: uninstall_lib uninstall_headers uninstall_examples
