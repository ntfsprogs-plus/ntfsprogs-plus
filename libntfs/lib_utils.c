/**
 * utils.c - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2002-2005 Richard Russon
 * Copyright (c) 2003-2006 Anton Altaparmakov
 * Copyright (c) 2003 Lode Leroy
 * Copyright (c) 2005-2007 Yura Pakhuchiy
 * Copyright (c) 2014      Jean-Pierre Andre
 *
 * This file is from src/utils.c to use function in libntfs-3g.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "lib_utils.h"
#include "types.h"
#include "debug.h"
#include "logging.h"
#include "misc.h"

/**
 * find_attribute - Find an attribute of the given type
 * @type:  An attribute type, e.g. AT_FILE_NAME
 * @ctx:   A search context, created using ntfs_get_attr_search_ctx
 *
 * Using the search context to keep track, find the first/next occurrence of a
 * given attribute type.
 *
 * N.B.  This will return a pointer into @mft.  As long as the search context
 *       has been created without an inode, it won't overflow the buffer.
 *
 * Return:  Pointer  Success, an attribute was found
 *	    NULL     Error, no matching attributes were found
 */
ATTR_RECORD *find_attribute(const ATTR_TYPES type, ntfs_attr_search_ctx *ctx)
{
	if (!ctx) {
		errno = EINVAL;
		return NULL;
	}

	if (ntfs_attr_lookup(type, NULL, 0, 0, 0, NULL, 0, ctx) != 0) {
		ntfs_log_debug("find_attribute didn't find an attribute of type: 0x%02x.\n", le32_to_cpu(type));
		return NULL;	/* None / no more of that type */
	}

	ntfs_log_debug("find_attribute found an attribute of type: 0x%02x.\n", le32_to_cpu(type));
	return ctx->attr;
}

/**
 * find_first_inode_attribute - Find the first attribute of a given type
 * it is same as find_first_attribute except using ctx
 * which have inode structure(ni).
 * find_first_attribute() can not find attribute if first attribute is
 * in extent mft record.
 */
ATTR_RECORD *find_first_inode_attribute(const ATTR_TYPES type, ntfs_inode *ni)
{
	ntfs_attr_search_ctx *ctx;
	MFT_RECORD *mft;
	ATTR_RECORD *rec;

	if (!ni) {
		errno = EINVAL;
		return NULL;
	}

	mft = ni->mrec;

	ctx = ntfs_attr_get_search_ctx(ni, mft);
	if (!ctx) {
		ntfs_log_error("Couldn't create a search context.\n");
		return NULL;
	}

	rec = find_attribute(type, ctx);
	ntfs_attr_put_search_ctx(ctx);
	if (rec)
		ntfs_log_debug("find_first_attribute: found attr of type 0x%02x.\n", le32_to_cpu(type));
	else
		ntfs_log_debug("find_first_attribute: didn't find attr of type 0x%02x.\n", le32_to_cpu(type));
	return rec;

}

/**
 * find_first_attribute - Find the first attribute of a given type
 * @type:  An attribute type, e.g. AT_FILE_NAME
 * @mft:   A buffer containing a raw MFT record
 *
 * Search through a raw MFT record for an attribute of a given type.
 * The return value is a pointer into the MFT record that was supplied.
 *
 * N.B.  This will return a pointer into @mft.  The pointer won't stray outside
 *       the buffer, since we created the search context without an inode.
 *
 * Return:  Pointer  Success, an attribute was found
 *	    NULL     Error, no matching attributes were found
 */
ATTR_RECORD *find_first_attribute(const ATTR_TYPES type, MFT_RECORD *mft)
{
	ntfs_attr_search_ctx *ctx;
	ATTR_RECORD *rec;

	if (!mft) {
		errno = EINVAL;
		return NULL;
	}

	ctx = ntfs_attr_get_search_ctx(NULL, mft);
	if (!ctx) {
		ntfs_log_error("Couldn't create a search context.\n");
		return NULL;
	}

	rec = find_attribute(type, ctx);
	ntfs_attr_put_search_ctx(ctx);
	if (rec)
		ntfs_log_debug("find_first_attribute: found attr of type 0x%02x.\n", le32_to_cpu(type));
	else
		ntfs_log_debug("find_first_attribute: didn't find attr of type 0x%02x.\n", le32_to_cpu(type));
	return rec;
}

/**
 * __metadata
 */
static int __metadata(ntfs_volume *vol, u64 num)
{
	if (num <= FILE_UpCase)
		return 1;
	if (!vol)
		return -1;
	if ((vol->major_ver == 3) && (num == FILE_Extend))
		return 1;

	return 0;
}

/**
 * utils_is_metadata - Determine if an inode represents a metadata file
 * @inode:  An ntfs inode to be tested
 *
 * A handful of files in the volume contain filesystem data - metadata.
 * They can be identified by their inode number (offset in MFT/$DATA) or by
 * their parent.
 *
 * Return:  1  inode is a metadata file
 *	    0  inode is not a metadata file
 *	   -1  Error occurred
 */
int utils_is_metadata(ntfs_inode *inode)
{
	ntfs_volume *vol;
	ATTR_RECORD *rec;
	FILE_NAME_ATTR *attr;
	MFT_RECORD *file;
	u64 num;

	if (!inode) {
		errno = EINVAL;
		return -1;
	}

	vol = inode->vol;
	if (!vol)
		return -1;

	num = inode->mft_no;
	if (__metadata(vol, num) == 1)
		return 1;

	file = inode->mrec;
	if (file && (file->base_mft_record != 0)) {
		num = MREF_LE(file->base_mft_record);
		if (__metadata(vol, num) == 1)
			return 1;
	}

	rec = find_first_inode_attribute(AT_FILE_NAME, inode);
	if (!rec)
		return -1;

	/* We know this will always be resident. */
	attr = (FILE_NAME_ATTR *)((char *)rec + le16_to_cpu(rec->value_offset));

	num = MREF_LE(attr->parent_directory);
	if ((num != FILE_root) && (__metadata(vol, num) == 1))
		return 1;

	if ((inode->flags & (FILE_ATTR_SYSTEM | FILE_ATTR_HIDDEN)) ==
			(FILE_ATTR_SYSTEM | FILE_ATTR_HIDDEN))
		return 1;

	return 0;
}
