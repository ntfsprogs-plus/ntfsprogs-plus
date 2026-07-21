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

bin_PROGRAMS		= ntfsinfo ntfscluster ntfsls ntfscat ntfscmp
sbin_PROGRAMS		= mkntfs ntfslabel ntfsclone ntfsck ntfsresize \
			  ntfsundelete ntfscp

# Built only with --enable-extras (and ntfsmove also needs --enable-quarantined),
# matching upstream ntfsprogs classification.
EXTRA_PROGRAM_NAMES	= ntfswipe
QUARANTINED_PROGRAM_NAMES = ntfsmove

CLEANFILES		= $(EXTRA_PROGRAMS)

if ENABLE_EXTRAS
bin_PROGRAMS		+= $(EXTRA_PROGRAM_NAMES)
if ENABLE_QUARANTINED
bin_PROGRAMS		+= $(QUARANTINED_PROGRAM_NAMES)
endif
else
EXTRA_PROGRAMS		= $(EXTRA_PROGRAM_NAMES) $(QUARANTINED_PROGRAM_NAMES)
endif

MAINTAINERCLEANFILES = Makefile.in

# Set the include path.
AM_CPPFLAGS		= -I$(top_srcdir)/include $(all_includes)

mkntfs_CPPFLAGS		= $(AM_CPPFLAGS) $(MKNTFS_CPPFLAGS)
mkntfs_SOURCES		= attrdef.c attrdef.h sd.c sd.h mkntfs.c utils.c utils.h
mkntfs_LDADD		= $(AM_LIBS) $(MKNTFS_LIBS) $(BLKID_LIBS)
mkntfs_LDFLAGS		= $(AM_LFLAGS)

ntfslabel_SOURCES	= ntfslabel.c utils.c utils.h
ntfslabel_LDADD		= $(AM_LIBS)
ntfslabel_LDFLAGS	= $(AM_LFLAGS)

ntfsinfo_SOURCES	= ntfsinfo.c utils.c utils.h
ntfsinfo_LDADD		= $(AM_LIBS)
ntfsinfo_LDFLAGS	= $(AM_LFLAGS)

ntfsresize_SOURCES	= ntfsresize.c utils.c utils.h
ntfsresize_LDADD	= $(AM_LIBS)
ntfsresize_LDFLAGS	= $(AM_LFLAGS)

ntfsclone_SOURCES	= ntfsclone.c utils.c utils.h
ntfsclone_LDADD		= $(AM_LIBS)
ntfsclone_LDFLAGS	= $(AM_LFLAGS)

ntfscluster_SOURCES	= ntfscluster.c ntfscluster.h cluster.c cluster.h utils.c utils.h
ntfscluster_LDADD	= $(AM_LIBS)
ntfscluster_LDFLAGS	= $(AM_LFLAGS)

ntfsck_SOURCES		= ntfsck.c utils.c utils.h
ntfsck_LDADD		= $(AM_LIBS)
ntfsck_LDFLAGS		= $(AM_LFLAGS)

ntfsls_SOURCES		= ntfsls.c utils.c utils.h list.h
ntfsls_LDADD		= $(AM_LIBS)
ntfsls_LDFLAGS		= $(AM_LFLAGS)

ntfscat_SOURCES		= ntfscat.c ntfscat.h utils.c utils.h
ntfscat_LDADD		= $(AM_LIBS)
ntfscat_LDFLAGS		= $(AM_LFLAGS)

ntfscmp_SOURCES		= ntfscmp.c utils.c utils.h
ntfscmp_LDADD		= $(AM_LIBS)
ntfscmp_LDFLAGS		= $(AM_LFLAGS)

ntfsundelete_SOURCES	= ntfsundelete.c ntfsundelete.h utils.c utils.h list.h
ntfsundelete_LDADD	= $(AM_LIBS)
ntfsundelete_LDFLAGS	= $(AM_LFLAGS)

ntfscp_SOURCES		= ntfscp.c utils.c utils.h
ntfscp_LDADD		= $(AM_LIBS)
ntfscp_LDFLAGS		= $(AM_LFLAGS)

ntfswipe_SOURCES	= ntfswipe.c ntfswipe.h utils.c utils.h
ntfswipe_LDADD		= $(AM_LIBS)
ntfswipe_LDFLAGS	= $(AM_LFLAGS)

ntfsmove_SOURCES	= ntfsmove.c ntfsmove.h utils.c utils.h
ntfsmove_LDADD		= $(AM_LIBS)
ntfsmove_LDFLAGS	= $(AM_LFLAGS)

# Extra targets

strip:	$(bin_PROGRAMS) $(sbin_PROGRAMS)
	$(STRIP) $^

libs:
	(cd ../libntfs && $(MAKE) libs) || exit 1;

extras:	libs $(EXTRA_PROGRAMS)

# mkfs.ntfs and fsck.ntfs symbolic links

install-exec-hook:
	$(INSTALL) -d $(DESTDIR)/$(sbindir)
	$(LN_S) -f $(sbindir)/mkntfs $(DESTDIR)$(sbindir)/mkfs.ntfs
	$(LN_S) -f $(sbindir)/ntfsck $(DESTDIR)$(sbindir)/fsck.ntfs

uninstall-local:
	$(RM) -f $(DESTDIR)/sbin/mkfs.ntfs
	$(RM) -f $(DESTDIR)/sbin/fsck.ntfs
