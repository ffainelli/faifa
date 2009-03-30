#
# Makefile for the faifa program and library
#
#
# Copyright (C) 2007-2008 
#	Xavier Carcelle <xavier.carcelle@gmail.com>
#	Florian Fainelli <florian@openwrt.org>
#	Nicolas Thill <nico@openwrt.org>
#
# License:
#	GPLv2
#

OS=$(shell uname -s | tr a-z A-Z)
ARCH=$(shell uname -m | sed -e 's/i.86/i386/' -e 's/x86_64/amd64'/)
CFLAGS:= -W -Wall -g -fPIC 
APP:=faifa
SVN_REV=$(shell set LC_ALL=C; svn info | grep "Revision" | awk '{ print $$2}')

# Object files for the library
LIB_OBJS:=faifa.o frame.o crypto.o
LIB_NAME:=lib$(APP)

# Object files for the program
OBJS:= main.o $(LIB_OBJS)
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

all: $(APP) $(LIB_NAME).a $(LIB_NAME).so

$(APP): $(OBJS) $(HEADERS)
	$(CC) -D$(OS) -DSVN_REV=$(SVN_REV) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

$(LIB_NAME).a: $(LIB_OBJS) $(HEADERS)
	$(AR) rcs $(LIB_NAME).a	$(LIB_OBJS)

$(LIB_NAME).so: $(LIB_OBJS) $(HEADERS)
	$(CC) -shared -Wl,-soname,$(LIB_NAME).so -o $(LIB_NAME).so $(LIB_OBJS) $(LIBS)

%.o: %.c $(HEADERS)
	$(CC) -D$(OS) -DSVN_REV=$(SVN_REV) $(CFLAGS) -c $<

clean:
	rm -f $(APP) faifa-dump-devel-stdout \
		*.o \
		*.a \
		*.so \
		$(MANFIL) \
		../*.deb \
		../*.dsc \
		../*.tar.gz \
		../*.changes
distclean: clean

install: installman strip
	install -d $(DESTDIR)/usr/sbin/
	install -m0755 $(APP) $(DESTDIR)/usr/sbin/
	install -d $(DESTDIR)/usr/lib/
	install -m0644 lib$(APP).so $(DESTDIR)/usr/lib/
	install -d $(DESTDIR)/usr/include
	cp $(HEADERS) $(DESTDIR)/usr/include/

strip:
	strip $(APP) 
	strip $(LIB_NAME).so

debs:
	sed -i -e 's/ARCH/$(ARCH)/' debian/control
	dpkg-buildpackage -r
	sed -i -e 's/$(ARCH)/ARCH/' debian/control

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
