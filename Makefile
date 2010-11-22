PREFIX ?= /usr/local
CXXFLAGS ?= -O0
override CXXFLAGS += -g -Wall -std=c++0x
CPPFLAGS := $(shell pkg-config --cflags dbus-1)
LDFLAGS := -Wl,--as-needed
LDLIBS := $(shell pkg-config --libs dbus-1)
LDLIBS += -lreadline

dbustop: pysakki.cc
	$(LINK.cc) $< $(LDLIBS) -o $@

clean:
	-rm -f dbustop *.o

install:
	install -d $(DESTDIR)$(PREFIX)/bin
	install dbustop $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install dbustop.1 $(DESTDIR)$(PREFIX)/share/man/man1
