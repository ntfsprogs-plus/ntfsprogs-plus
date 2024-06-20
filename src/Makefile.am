if REALLYSTATIC
AM_LIBS		= $(top_builddir)/libntfs/.libs/libntfs.a $(NTFSPROGS_STATIC_LIBS)
# older builds may need -static instead of newer -all-static
AM_LFLAGS	= -static
STATIC_LINK     = $(CC) $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@
else
AM_LIBS		= $(top_builddir)/libntfs/libntfs.la
AM_LFLAGS	= $(all_libraries)
LIBTOOL_LINK    = $(LIBTOOL) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@
endif

# Workaround to make REALLYSTATIC work with automake 1.5.
LINK=$(STATIC_LINK) $(LIBTOOL_LINK)

bin_PROGRAMS		= ntfsinfo ntfscluster
sbin_PROGRAMS		= mkntfs ntfslabel ntfsclone ntfsck

man_MANS		= mkntfs.8 ntfslabel.8 ntfsinfo.8 ntfsck.8 \
			  ntfsprogs-plus.8 ntfsclone.8 ntfscluster.8

EXTRA_MANS		=

MAINTAINERCLEANFILES = Makefile.in

# Set the include path.
AM_CPPFLAGS		= -I$(top_srcdir)/include $(all_includes)

mkntfs_CPPFLAGS		= $(AM_CPPFLAGS) $(MKNTFS_CPPFLAGS)
mkntfs_SOURCES		= attrdef.c attrdef.h sd.c sd.h mkntfs.c utils.c utils.h
mkntfs_LDADD		= $(AM_LIBS) $(MKNTFS_LIBS)
mkntfs_LDFLAGS		= $(AM_LFLAGS)

ntfslabel_SOURCES	= ntfslabel.c utils.c utils.h
ntfslabel_LDADD		= $(AM_LIBS)
ntfslabel_LDFLAGS	= $(AM_LFLAGS)

ntfsinfo_SOURCES	= ntfsinfo.c utils.c utils.h
ntfsinfo_LDADD		= $(AM_LIBS)
ntfsinfo_LDFLAGS	= $(AM_LFLAGS)

ntfsclone_SOURCES	= ntfsclone.c utils.c utils.h
ntfsclone_LDADD		= $(AM_LIBS)
ntfsclone_LDFLAGS	= $(AM_LFLAGS)

ntfscluster_SOURCES	= ntfscluster.c ntfscluster.h cluster.c cluster.h utils.c utils.h
ntfscluster_LDADD	= $(AM_LIBS)
ntfscluster_LDFLAGS	= $(AM_LFLAGS)

ntfsck_SOURCES		= ntfsck.c utils.c utils.h
ntfsck_LDADD		= $(AM_LIBS)
ntfsck_LDFLAGS		= $(AM_LFLAGS)

# Extra targets

strip:	$(bin_PROGRAMS) $(sbin_PROGRAMS)
	$(STRIP) $^

libs:
	(cd ../libntfs && $(MAKE) libs) || exit 1;

# mkfs.ntfs[.8] hard link

install-exec-hook:
	$(INSTALL) -d $(DESTDIR)/$(sbindir)
	$(LN_S) -f $(sbindir)/mkntfs $(DESTDIR)$(sbindir)/mkfs.ntfs
	$(LN_S) -f $(sbindir)/ntfsck $(DESTDIR)$(sbindir)/fsck.ntfs

install-data-hook:
	$(INSTALL) -d $(DESTDIR)$(man8dir)
	$(LN_S) -f mkntfs.8 $(DESTDIR)$(man8dir)/mkfs.ntfs.8
	$(LN_S) -f ntfsck.8 $(DESTDIR)$(man8dir)/fsck.ntfs.8

uninstall-local:
	$(RM) -f $(DESTDIR)/sbin/mkfs.ntfs
	$(RM) -f $(DESTDIR)/sbin/fsck.ntfs
	$(RM) -f $(DESTDIR)$(man8dir)/mkfs.ntfs.8
	$(RM) -f $(DESTDIR)$(man8dir)/fsck.ntfs.8
