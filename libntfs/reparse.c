/**
 * reparse.c - Processing of reparse points
 *
 *	This module is part of ntfs-3g library
 *
 * Copyright (c) 2008-2021 Jean-Pierre Andre
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the NTFS-3G
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef MAJOR_IN_MKDEV
#include <sys/mkdev.h>
#endif
#ifdef MAJOR_IN_SYSMACROS
#include <sys/sysmacros.h>
#endif

#include "compat.h"
#include "types.h"
#include "debug.h"
#include "layout.h"
#include "attrib.h"
#include "inode.h"
#include "dir.h"
#include "volume.h"
#include "mft.h"
#include "index.h"
#include "lcnalloc.h"
#include "logging.h"
#include "misc.h"
#include "reparse.h"
#include "xattrs.h"
#include "ea.h"

struct MOUNT_POINT_REPARSE_DATA {      /* reparse data for junctions */
	le16	subst_name_offset;
	le16	subst_name_length;
	le16	print_name_offset;
	le16	print_name_length;
	char	path_buffer[0];      /* above data assume this is char array */
} ;

struct SYMLINK_REPARSE_DATA {          /* reparse data for symlinks */
	le16	subst_name_offset;
	le16	subst_name_length;
	le16	print_name_offset;
	le16	print_name_length;
	le32	flags;		     /* 1 for full target, otherwise 0 */
	char	path_buffer[0];      /* above data assume this is char array */
} ;

struct WSL_LINK_REPARSE_DATA {
	le32	type;
	char	link[0];
} ;

struct REPARSE_INDEX {			/* index entry in $Extend/$Reparse */
	INDEX_ENTRY_HEADER header;
	REPARSE_INDEX_KEY key;
	le32 filling;
} ;

static ntfschar reparse_index_name[] = { const_cpu_to_le16('$'),
	const_cpu_to_le16('R') };

/*
 *		Do some sanity checks on reparse data
 *
 *	Microsoft reparse points have an 8-byte header whereas
 *	non-Microsoft reparse points have a 24-byte header.  In each case,
 *	'reparse_data_length' must equal the number of non-header bytes.
 *
 *	If the reparse data looks like a junction point or symbolic
 *	link, more checks can be done.
 *
 */

static BOOL valid_reparse_data(ntfs_inode *ni,
		const REPARSE_POINT *reparse_attr, size_t size)
{
	BOOL ok;
	unsigned int offs;
	unsigned int lth;
	const struct MOUNT_POINT_REPARSE_DATA *mount_point_data;
	const struct SYMLINK_REPARSE_DATA *symlink_data;
	const struct WSL_LINK_REPARSE_DATA *wsl_reparse_data;

	ok = ni && reparse_attr
		&& (size >= sizeof(REPARSE_POINT))
		&& (reparse_attr->reparse_tag != IO_REPARSE_TAG_RESERVED_ZERO)
		&& (((size_t)le16_to_cpu(reparse_attr->reparse_data_length)
			+ sizeof(REPARSE_POINT)
			+ ((reparse_attr->reparse_tag &
					IO_REPARSE_TAG_IS_MICROSOFT) ? 0 : sizeof(GUID))) == size);
	if (ok) {
		switch (reparse_attr->reparse_tag) {
		case IO_REPARSE_TAG_MOUNT_POINT :
			if (size < sizeof(REPARSE_POINT) +
					sizeof(struct MOUNT_POINT_REPARSE_DATA)) {
				ok = FALSE;
				break;
			}
			mount_point_data = (const struct MOUNT_POINT_REPARSE_DATA*)
				reparse_attr->reparse_data;
			offs = le16_to_cpu(mount_point_data->subst_name_offset);
			lth = le16_to_cpu(mount_point_data->subst_name_length);
			/* consistency checks */
			if (!(ni->mrec->flags & MFT_RECORD_IS_DIRECTORY)
					|| ((size_t)((sizeof(REPARSE_POINT)
						+ sizeof(struct MOUNT_POINT_REPARSE_DATA)
						+ offs + lth)) > size))
				ok = FALSE;
			break;
		case IO_REPARSE_TAG_SYMLINK :
			if (size < sizeof(REPARSE_POINT) +
					sizeof(struct SYMLINK_REPARSE_DATA)) {
				ok = FALSE;
				break;
			}
			symlink_data = (const struct SYMLINK_REPARSE_DATA*)
				reparse_attr->reparse_data;
			offs = le16_to_cpu(symlink_data->subst_name_offset);
			lth = le16_to_cpu(symlink_data->subst_name_length);
			if ((size_t)((sizeof(REPARSE_POINT)
					+ sizeof(struct SYMLINK_REPARSE_DATA)
					+ offs + lth)) > size)
				ok = FALSE;
			break;
		case IO_REPARSE_TAG_LX_SYMLINK :
			wsl_reparse_data = (const struct WSL_LINK_REPARSE_DATA*)
				reparse_attr->reparse_data;
			if ((le16_to_cpu(reparse_attr->reparse_data_length)
						<= sizeof(wsl_reparse_data->type))
					|| (wsl_reparse_data->type != const_cpu_to_le32(2)))
				ok = FALSE;
			break;
		case IO_REPARSE_TAG_AF_UNIX :
		case IO_REPARSE_TAG_LX_FIFO :
		case IO_REPARSE_TAG_LX_CHR :
		case IO_REPARSE_TAG_LX_BLK :
			if (reparse_attr->reparse_data_length
					|| !(ni->flags & FILE_ATTRIBUTE_RECALL_ON_OPEN))
				ok = FALSE;
			break;
		default :
			break;
		}
	}
	if (!ok)
		errno = EINVAL;
	return (ok);
}

/*
 *		Public wrapper around valid_reparse_data() so that fsck can
 *	structurally validate a reparse point (tag, length and payload
 *	bounds) using the same tested logic as the rest of libntfs.
 *
 *	Returns TRUE if the reparse data is structurally valid.
 */

BOOL ntfs_reparse_data_is_valid(ntfs_inode *ni,
		const REPARSE_POINT *reparse_attr, size_t size)
{
	return valid_reparse_data(ni, reparse_attr, size);
}

/*
 *		Check whether a reparse point looks like a junction point
 *	or a symbolic link.
 *	Should only be called for files or directories with reparse data
 *
 *	The validity of the target is not checked.
 */

BOOL ntfs_possible_symlink(ntfs_inode *ni)
{
	s64 attr_size = 0;
	REPARSE_POINT *reparse_attr;
	BOOL possible;

	possible = FALSE;
	reparse_attr = (REPARSE_POINT*)ntfs_attr_readall(ni,
			AT_REPARSE_POINT,(ntfschar*)NULL, 0, &attr_size);
	if (reparse_attr && attr_size) {
		switch (reparse_attr->reparse_tag) {
			case IO_REPARSE_TAG_MOUNT_POINT :
			case IO_REPARSE_TAG_SYMLINK :
			case IO_REPARSE_TAG_LX_SYMLINK :
				possible = TRUE;
			default : ;
		}
		free(reparse_attr);
	}
	return (possible);
}


/*
 *			Set the index for new reparse data
 *
 *	Returns 0 if success
 *		-1 if failure, explained by errno
 */

static int set_reparse_index(ntfs_inode *ni, ntfs_index_context *xr,
		le32 reparse_tag)
{
	struct REPARSE_INDEX indx;
	u64 file_id_cpu;
	le64 file_id;
	le16 seqn;

	seqn = ni->mrec->sequence_number;
	file_id_cpu = MK_MREF(ni->mft_no,le16_to_cpu(seqn));
	file_id = cpu_to_le64(file_id_cpu);
	indx.header.data_offset = const_cpu_to_le16(
			sizeof(INDEX_ENTRY_HEADER)
			+ sizeof(REPARSE_INDEX_KEY));
	indx.header.data_length = const_cpu_to_le16(0);
	indx.header.reservedV = const_cpu_to_le32(0);
	indx.header.length = const_cpu_to_le16(
			sizeof(struct REPARSE_INDEX));
	indx.header.key_length = const_cpu_to_le16(
			sizeof(REPARSE_INDEX_KEY));
	indx.header.flags = const_cpu_to_le16(0);
	indx.header.reserved = const_cpu_to_le16(0);
	indx.key.reparse_tag = reparse_tag;
	/* danger on processors which require proper alignment ! */
	memcpy(&indx.key.file_id, &file_id, 8);
	indx.filling = const_cpu_to_le32(0);
	ntfs_index_ctx_reinit(xr);
	return (ntfs_ie_add(xr,(INDEX_ENTRY*)&indx));
}


/*
 *		Remove a reparse data index entry if attribute present
 *
 *	Returns the size of existing reparse data
 *			(the existing reparse tag is returned)
 *		-1 if failure, explained by errno
 */

static int remove_reparse_index(ntfs_attr *na, ntfs_index_context *xr,
		le32 *preparse_tag)
{
	REPARSE_INDEX_KEY key;
	u64 file_id_cpu;
	le64 file_id;
	s64 size;
	le16 seqn;
	int ret;

	ret = na->data_size;
	if (ret) {
		/* read the existing reparse_tag */
		size = ntfs_attr_pread(na, 0, 4, preparse_tag);
		if (size == 4) {
			seqn = na->ni->mrec->sequence_number;
			file_id_cpu = MK_MREF(na->ni->mft_no,le16_to_cpu(seqn));
			file_id = cpu_to_le64(file_id_cpu);
			key.reparse_tag = *preparse_tag;
			/* danger on processors which require proper alignment ! */
			memcpy(&key.file_id, &file_id, 8);
			if (!ntfs_index_lookup(&key, sizeof(REPARSE_INDEX_KEY), xr)
					&& ntfs_index_rm(xr))
				ret = -1;
		} else {
			ret = -1;
			errno = ENODATA;
		}
	}
	return (ret);
}

/*
 *		Open the $Extend/$Reparse file and its index
 *
 *	Return the index context if opened
 *		or NULL if an error occurred (errno tells why)
 *
 *	The index has to be freed and inode closed when not needed any more.
 */

static ntfs_index_context *open_reparse_index(ntfs_volume *vol)
{
	u64 inum;
	ntfs_inode *ni;
	ntfs_inode *dir_ni;
	ntfs_index_context *xr;

	/* do not use path_name_to inode - could reopen root */
	dir_ni = ntfs_inode_open(vol, FILE_Extend);
	ni = (ntfs_inode*)NULL;
	if (dir_ni) {
		inum = ntfs_inode_lookup_by_mbsname(dir_ni,"$Reparse");
		if (inum != (u64)-1)
			ni = ntfs_inode_open(vol, inum);
		ntfs_inode_close(dir_ni);
	}
	if (ni) {
		xr = ntfs_index_ctx_get(ni, reparse_index_name, 2);
		if (!xr) {
			ntfs_inode_close(ni);
		}
	} else
		xr = (ntfs_index_context*)NULL;
	return (xr);
}


/*
 *		Check (and restore) the index entry of a reparse point
 *
 *	The $Extend/$Reparse index is re-initialized empty when found
 *	structurally corrupt, which also drops the entries of the intact
 *	reparse points on the volume; the per-inode fsck check re-inserts
 *	them through this helper.
 *
 *	Returns 0 if the entry is present
 *		1 if the entry is missing (restored when @add is TRUE)
 *		-1 if failure, explained by errno
 */

int ntfs_reparse_index_check(ntfs_inode *ni, le32 reparse_tag, BOOL add)
{
	ntfs_index_context *xr;
	ntfs_inode *xrni;
	REPARSE_INDEX_KEY key;
	le64 file_id;
	int ret;

	if (!ni || !ni->mrec) {
		errno = EINVAL;
		return -1;
	}

	xr = open_reparse_index(ni->vol);
	if (!xr)
		return -1;

	file_id = cpu_to_le64(MK_MREF(ni->mft_no,
			le16_to_cpu(ni->mrec->sequence_number)));
	key.reparse_tag = reparse_tag;
	/* danger on processors which require proper alignment ! */
	memcpy(&key.file_id, &file_id, 8);

	if (!ntfs_index_lookup(&key, sizeof(REPARSE_INDEX_KEY), xr))
		ret = 0;
	else if (errno != ENOENT)
		ret = -1;
	else {
		ret = 1;
		if (add) {
			if (set_reparse_index(ni, xr, reparse_tag)) {
				ret = -1;
			} else {
				ntfs_index_entry_mark_dirty(xr);
				NInoSetDirty(xr->ni);
			}
		}
	}
	xrni = xr->ni;
	ntfs_index_ctx_put(xr);
	ntfs_inode_close(xrni);
	return ret;
}

/*
 *		Update the reparse data and index
 *
 *	The reparse data attribute should have been created, and
 *	an existing index is expected if there is an existing value.
 *
 *	Returns 0 if success
 *		-1 if failure, explained by errno
 *	If could not remove the existing index, nothing is done,
 *	If could not write the new data, no index entry is inserted
 *	If failed to insert the index, data is removed
 */

static int update_reparse_data(ntfs_inode *ni, ntfs_index_context *xr,
		const char *value, size_t size)
{
	int res;
	int written;
	int oldsize;
	ntfs_attr *na;
	le32 reparse_tag;

	res = 0;
	na = ntfs_attr_open(ni, AT_REPARSE_POINT, AT_UNNAMED, 0);
	if (na) {
		/* remove the existing reparse data */
		oldsize = remove_reparse_index(na,xr,&reparse_tag);
		if (oldsize < 0)
			res = -1;
		else {
			/* resize attribute */
			res = ntfs_attr_truncate(na, (s64)size);
			/* overwrite value if any */
			if (!res && value) {
				written = (int)ntfs_attr_pwrite(na,
						(s64)0, (s64)size, value);
				if (written != (s64)size) {
					ntfs_log_error("Failed to update "
							"reparse data\n");
					errno = EIO;
					res = -1;
				}
			}
			if (!res
					&& set_reparse_index(ni,xr,
						((const REPARSE_POINT*)value)->reparse_tag)
					&& (oldsize > 0)) {
				/*
				 * If cannot index, try to remove the reparse
				 * data and log the error. There will be an
				 * inconsistency if removal fails.
				 */
				ntfs_attr_rm(na);
				ntfs_log_error("Failed to index reparse data."
						" Possible corruption.\n");
			}
		}
		ntfs_attr_close(na);
		NInoSetDirty(ni);
	} else
		res = -1;
	return (res);
}


/*
 *		Delete a reparse index entry
 *
 *	Returns 0 if success
 *		-1 if failure, explained by errno
 */

int ntfs_delete_reparse_index(ntfs_inode *ni)
{
	ntfs_index_context *xr;
	ntfs_inode *xrni;
	ntfs_attr *na;
	le32 reparse_tag;
	int res;

	res = 0;
	na = ntfs_attr_open(ni, AT_REPARSE_POINT, AT_UNNAMED, 0);
	if (na) {
		/*
		 * read the existing reparse data (the tag is enough)
		 * and un-index it
		 */
		xr = open_reparse_index(ni->vol);
		if (xr) {
			if (remove_reparse_index(na,xr,&reparse_tag) < 0)
				res = -1;
			xrni = xr->ni;
			ntfs_index_entry_mark_dirty(xr);
			NInoSetDirty(xrni);
			ntfs_index_ctx_put(xr);
			ntfs_inode_close(xrni);
		}
		ntfs_attr_close(na);
	}
	return (res);
}


/*
 *		Get the ntfs reparse data into an extended attribute
 *
 *	Returns the reparse data size
 *		and the buffer is updated if it is long enough
 */

int ntfs_get_ntfs_reparse_data(ntfs_inode *ni, char *value, size_t size)
{
	REPARSE_POINT *reparse_attr;
	s64 attr_size;

	attr_size = 0;	/* default to no data and no error */
	if (ni) {
		if (ni->flags & FILE_ATTR_REPARSE_POINT) {
			reparse_attr = (REPARSE_POINT*)ntfs_attr_readall(ni,
					AT_REPARSE_POINT,(ntfschar*)NULL, 0, &attr_size);
			if (reparse_attr) {
				if (attr_size <= (s64)size) {
					if (value)
						memcpy(value,reparse_attr,
								attr_size);
					else
						errno = EINVAL;
				}
				free(reparse_attr);
			}
		} else
			errno = ENODATA;
	}
	return (attr_size ? (int)attr_size : -errno);
}

/*
 *		Set the reparse data from an extended attribute
 *
 *	Warning : the new data is not checked
 *
 *	Returns 0, or -1 if there is a problem
 */

int ntfs_set_ntfs_reparse_data(ntfs_inode *ni,
		const char *value, size_t size, int flags)
{
	int res;
	u8 dummy;
	ntfs_inode *xrni;
	ntfs_index_context *xr;

	res = 0;
	/*
	 * reparse data compatibily with EA is not checked
	 * any more, it is required by Windows 10, but may
	 * lead to problems with earlier versions.
	 */
	if (ni && valid_reparse_data(ni, (const REPARSE_POINT*)value, size)) {
		xr = open_reparse_index(ni->vol);
		if (xr) {
			if (!ntfs_attr_exist(ni,AT_REPARSE_POINT,
						AT_UNNAMED,0)) {
				if (!(flags & XATTR_REPLACE)) {
					/*
					 * no reparse data attribute : add one,
					 * apparently, this does not feed the new value in
					 * Note : NTFS version must be >= 3
					 */
					if (ni->vol->major_ver >= 3) {
						res = ntfs_attr_add(ni,
								AT_REPARSE_POINT,
								AT_UNNAMED,0,&dummy,
								(s64)0);
						if (!res) {
							ni->flags |=
								FILE_ATTR_REPARSE_POINT;
							NInoFileNameSetDirty(ni);
						}
						NInoSetDirty(ni);
					} else {
						errno = EOPNOTSUPP;
						res = -1;
					}
				} else {
					errno = ENODATA;
					res = -1;
				}
			} else {
				if (flags & XATTR_CREATE) {
					errno = EEXIST;
					res = -1;
				}
			}
			if (!res) {
				/* update value and index */
				res = update_reparse_data(ni,xr,value,size);
			}
			xrni = xr->ni;
			ntfs_index_entry_mark_dirty(xr);
			NInoSetDirty(xrni);
			ntfs_index_ctx_put(xr);
			ntfs_inode_close(xrni);
		} else {
			res = -1;
		}
	} else {
		errno = EINVAL;
		res = -1;
	}
	return (res ? -1 : 0);
}

/*
 *		Remove the reparse data
 *
 *	Returns 0, or -1 if there is a problem
 */

int ntfs_remove_ntfs_reparse_data(ntfs_inode *ni)
{
	int res;
	int olderrno;
	ntfs_attr *na;
	ntfs_inode *xrni;
	ntfs_index_context *xr;
	le32 reparse_tag;

	res = 0;
	if (ni) {
		/*
		 * open and delete the reparse data
		 */
		na = ntfs_attr_open(ni, AT_REPARSE_POINT,
				AT_UNNAMED,0);
		if (na) {
			/* first remove index (reparse data needed) */
			xr = open_reparse_index(ni->vol);
			if (xr) {
				if (remove_reparse_index(na,xr,
							&reparse_tag) < 0) {
					res = -1;
				} else {
					/* now remove attribute */
					res = ntfs_attr_rm(na);
					if (!res) {
						ni->flags &=
							~FILE_ATTR_REPARSE_POINT;
						NInoFileNameSetDirty(ni);
					} else {
						/*
						 * If we could not remove the
						 * attribute, try to restore the
						 * index and log the error. There
						 * will be an inconsistency if
						 * the reindexing fails.
						 */
						set_reparse_index(ni, xr,
								reparse_tag);
						ntfs_log_error(
								"Failed to remove reparse data."
								" Possible corruption.\n");
					}
				}
				xrni = xr->ni;
				ntfs_index_entry_mark_dirty(xr);
				NInoSetDirty(xrni);
				ntfs_index_ctx_put(xr);
				ntfs_inode_close(xrni);
			}
			olderrno = errno;
			ntfs_attr_close(na);
			/* avoid errno pollution */
			if (errno == ENOENT)
				errno = olderrno;
		} else {
			errno = ENODATA;
			res = -1;
		}
		NInoSetDirty(ni);
	} else {
		errno = EINVAL;
		res = -1;
	}
	return (res ? -1 : 0);
}

/*
 *		Set reparse data for a WSL type symlink
 */

int ntfs_reparse_set_wsl_symlink(ntfs_inode *ni,
		const ntfschar *target, int target_len)
{
	int res;
	int len;
	int reparse_len;
	char *utarget;
	REPARSE_POINT *reparse;
	struct WSL_LINK_REPARSE_DATA *data;

	res = -1;
	utarget = (char*)NULL;
	len = ntfs_ucstombs(target, target_len, &utarget, 0);
	if (len > 0) {
		reparse_len = sizeof(REPARSE_POINT) + sizeof(data->type) + len;
		reparse = (REPARSE_POINT*)malloc(reparse_len);
		if (reparse) {
			data = (struct WSL_LINK_REPARSE_DATA*)
				reparse->reparse_data;
			reparse->reparse_tag = IO_REPARSE_TAG_LX_SYMLINK;
			reparse->reparse_data_length
				= cpu_to_le16(sizeof(data->type) + len);
			reparse->reserved = const_cpu_to_le16(0);
			data->type = const_cpu_to_le32(2);
			memcpy(data->link, utarget, len);
			res = ntfs_set_ntfs_reparse_data(ni,
					(char*)reparse, reparse_len, 0);
			free(reparse);
		}
	}
	ntfs_attr_name_free(&utarget);
	return (res);
}

/*
 *		Set reparse data for a WSL special file other than a symlink
 *	(socket, fifo, character or block device)
 */

int ntfs_reparse_set_wsl_not_symlink(ntfs_inode *ni, mode_t mode)
{
	int res;
	int len;
	int reparse_len;
	le32 reparse_tag;
	REPARSE_POINT *reparse;

	res = -1;
	len = 0;
	switch (mode) {
		case S_IFSOCK :
			reparse_tag = IO_REPARSE_TAG_AF_UNIX;
			break;
		case S_IFIFO :
			reparse_tag = IO_REPARSE_TAG_LX_FIFO;
			break;
		case S_IFCHR :
			reparse_tag = IO_REPARSE_TAG_LX_CHR;
			break;
		case S_IFBLK :
			reparse_tag = IO_REPARSE_TAG_LX_BLK;
			break;
		default :
			len = -1;
			errno = EOPNOTSUPP;
			break;
	}
	if (len >= 0) {
		reparse_len = sizeof(REPARSE_POINT) + len;
		reparse = (REPARSE_POINT*)malloc(reparse_len);
		if (reparse) {
			reparse->reparse_tag = reparse_tag;
			reparse->reparse_data_length = cpu_to_le16(len);
			reparse->reserved = const_cpu_to_le16(0);
			res = ntfs_set_ntfs_reparse_data(ni,
					(char*)reparse, reparse_len, 0);
			free(reparse);
		}
	}
	return (res);
}

