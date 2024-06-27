
MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

if INSTALL_LIBRARY
rootlib_LTLIBRARIES=#Create directory
lib_LTLIBRARIES    = libntfs.la
else
noinst_LTLIBRARIES = libntfs.la
endif

libntfs_la_CFLAGS  = $(AM_CFLAGS)
libntfs_la_CPPFLAGS= $(AM_CPPFLAGS) $(LIBNTFS_CPPFLAGS) -I$(top_srcdir)/include
libntfs_la_LIBADD  = $(LIBNTFS_LIBS)
libntfs_la_LDFLAGS = -version-info $(LIBNTFS_VERSION) -no-undefined

libntfs_la_SOURCES =	\
	acls.c 		\
	attrib.c 	\
	attrlist.c 	\
	bitmap.c 	\
	bootsect.c 	\
	cache.c 	\
	collate.c 	\
	compat.c 	\
	compress.c 	\
	debug.c 	\
	device.c 	\
	dir.c 		\
	ea.c 		\
	efs.c 		\
	fsck.c		\
	index.c 	\
	inode.c 	\
	ioctl.c 	\
	lcnalloc.c 	\
	lib_utils.c	\
	logfile.c 	\
	logging.c 	\
	mft.c 		\
	misc.c 		\
	mst.c 		\
	object_id.c 	\
	problem.c	\
	realpath.c	\
	reparse.c 	\
	runlist.c 	\
	security.c 	\
	unistr.c 	\
	volume.c 	\
	xattrs.c

if NTFS_DEVICE_DEFAULT_IO_OPS
if WINDOWS
libntfs_la_SOURCES += win32_io.c
else
libntfs_la_SOURCES += unix_io.c
endif
endif

# We may need to move .so files to root
# And create ldscript or symbolic link from /usr
install-exec-hook: install-rootlibLTLIBRARIES
if INSTALL_LIBRARY
	if [ ! "$(DESTDIR)/$(rootlibdir)" -ef "$(DESTDIR)/$(libdir)" ]; then \
		$(MV) -f "$(DESTDIR)/$(libdir)"/libntfs.so* "$(DESTDIR)/$(rootlibdir)";  \
	fi
if GENERATE_LDSCRIPT
	if [ ! "$(DESTDIR)/$(rootlibdir)" -ef "$(DESTDIR)/$(libdir)" ]; then \
		$(install_sh_PROGRAM) "libntfs.script.so" "$(DESTDIR)/$(libdir)/libntfs.so"; \
	fi
else
	if [ ! "$(DESTDIR)/$(rootlibdir)" -ef "$(DESTDIR)/$(libdir)" ]; then \
		$(LN_S) "$(rootlibdir)/libntfs.so" "$(DESTDIR)/$(libdir)/libntfs.so"; \
	fi
endif
endif

uninstall-local:
if INSTALL_LIBRARY
	$(RM) -f "$(DESTDIR)/$(rootlibdir)"/libntfs.so*
endif

libs:	$(lib_LTLIBRARIES)
