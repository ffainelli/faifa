#
# Makefile for the faifa program and library
#
#
# Copyright (C) 2007-2009
#	Xavier Carcelle <xavier.carcelle@gmail.com>
#	Florian Fainelli <florian@openwrt.org>
#	Nicolas Thill <nico@openwrt.org>
#
# License:
#	GPLv2
#

OS=$(shell uname -s | tr a-z A-Z)
CFLAGS:= -W -Wall -g 
ifneq ($(OS),CYGWIN_NT-5.1)
CFLAGS+= -fPIC
endif
APP:=faifa
SVN_REV?=$(shell set LC_ALL=C; svn info | grep "Revision" | awk '{ print $$2}')

# Object files for the library
LIB_OBJS:=faifa.o frame.o crypto.o
LIB_NAME:=lib$(APP)
LIB_SONAME:=lib$(APP).so.0

# Object files for the program
OBJS:= main.o
HEADERS:= faifa.h faifa_compat.h faifa_priv.h homeplug.h homeplug_av.h crypto.h device.h endian.h
LIBS:=$(LDFLAGS) -lpthread -lssl -lcrypto

ifeq ($(OS),CYGWIN_NT-5.1)
LIBS+=-lwpcap
APP:=$(APP).exe
else
LIBS+=-lpcap
endif

# Man page
MANDIR=/usr/share/man
MANTYP=8
MANFIL=$(APP).$(MANTYP).gz
MANINSTALLDIR=$(MANDIR)/man$(MANTYP)

all: $(APP) $(LIB_NAME).a $(LIB_SONAME)

$(APP): $(OBJS) $(HEADERS) $(LIB_SONAME)
	$(CC) -D$(OS) -DSVN_REV=$(SVN_REV) $(CFLAGS) -o $@ $(OBJS) $(LIBS) $(LIB_SONAME)

$(LIB_NAME).a: $(LIB_OBJS) $(HEADERS)
	$(AR) rcs $(LIB_NAME).a	$(LIB_OBJS)

$(LIB_SONAME): $(LIB_OBJS) $(HEADERS)
	$(CC) -shared -Wl,-soname,$(LIB_SONAME) -o $(LIB_SONAME) $(LIB_OBJS) $(LIBS)

%.o: %.c $(HEADERS)
	$(CC) -D$(OS) -DSVN_REV=$(SVN_REV) $(CFLAGS) -c $<

clean:
	rm -f $(APP) faifa-dump-devel-stdout \
		*.o \
		*.a \
		*.so* \
		$(MANFIL)

distclean: clean

install: installman strip
	install -d $(DESTDIR)/usr/sbin/
	install -m0755 $(APP) $(DESTDIR)/usr/sbin/
	install -d $(DESTDIR)/usr/lib/
	install -m0644 $(LIB_SONAME) $(DESTDIR)/usr/lib/
	install -d $(DESTDIR)/usr/include/faifa
	cp $(HEADERS) $(DESTDIR)/usr/include/faifa/

strip:
	strip $(APP) 
	strip $(LIB_SONAME)

man:
	-rm $(MANFIL)
	cp $(APP).$(MANTYP) $(APP).$(MANTYP).orig
	gzip -9v $(APP).$(MANTYP)
	mv $(APP).$(MANTYP).orig $(APP).$(MANTYP)

installman: man
	install -d $(DESTDIR)/$(MANINSTALLDIR)
	install -m0644 $(MANFIL) $(DESTDIR)/$(MANINSTALLDIR)

uninstallman:
	rm $(MANINSTALLDIR)/$(MANFIL)

uninstall: uninstallman
	rm $(DESTDIR)/usr/sbin/faifa
	rm $(DESTDIR)/usr/lib/libfaifa.so

.PHONY:
	clean
