
AUTOMAKE_OPTIONS = gnu
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = AUTHORS CREDITS COPYING autogen.sh

MAINTAINERCLEANFILES=\
	$(srcdir)/configure \
	$(srcdir)/Makefile.in \
	$(srcdir)/aclocal.m4 \
	$(srcdir)/compile \
	$(srcdir)/depcomp \
	$(srcdir)/install-sh \
	$(srcdir)/ltmain.sh \
	$(srcdir)/missing \
	$(srcdir)/config.guess \
	$(srcdir)/config.sub \
	$(srcdir)/config.h.in \
	$(srcdir)/config.h.in~ \
	$(srcdir)/INSTALL \
	$(srcdir)/m4/ltsugar.m4 \
	$(srcdir)/m4/libtool.m4 \
	$(srcdir)/m4/ltversion.m4 \
	$(srcdir)/m4/lt~obsolete.m4 \
	$(srcdir)/m4/ltoptions.m4

SUBDIRS = include libntfs-3g src

doc_DATA = README.md

dist-hook:
	$(MKDIR_P) "$(distdir)/m4"

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

libs:
	(cd libntfs-3g && $(MAKE) libs) || exit 1;

libntfs:
	(cd libntfs-3g && $(MAKE) libs) || exit 1;

ntfsprogs: libntfs
	(cd src && $(MAKE)) || exit 1;

strip:
	(cd src && $(MAKE) strip) || exit 1;

extra:	extras

extras: libs
	(cd src && $(MAKE) extras) || exit 1;
