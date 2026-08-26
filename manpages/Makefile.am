man_MANS		= mkntfs.8 ntfslabel.8 ntfsinfo.8 ntfsck.8 \
			  ntfsprogs-plus.8 ntfsclone.8 ntfscluster.8 \
			  ntfsresize.8 ntfsls.8 ntfscat.8 ntfscmp.8 \
			  ntfswipe.8 ntfsundelete.8 ntfscp.8

EXTRA_MANS		=

MAINTAINERCLEANFILES = Makefile.in

# mkfs.ntfs.8 and fsck.ntfs.8 symbolic links

install-data-hook:
	$(INSTALL) -d $(DESTDIR)$(man8dir)
	$(LN_S) -f mkntfs.8 $(DESTDIR)$(man8dir)/mkfs.ntfs.8
	$(LN_S) -f ntfsck.8 $(DESTDIR)$(man8dir)/fsck.ntfs.8

uninstall-local:
	$(RM) -f $(DESTDIR)$(man8dir)/mkfs.ntfs.8
	$(RM) -f $(DESTDIR)$(man8dir)/fsck.ntfs.8
