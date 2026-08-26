/**
 * xattrs.c : common functions to deal with system extended attributes
 *
 * Copyright (c) 2010-2014 Jean-Pierre Andre
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

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "types.h"
#include "param.h"
#include "layout.h"
#include "attrib.h"
#include "index.h"
#include "dir.h"
#include "security.h"
#include "acls.h"
#include "efs.h"
#include "reparse.h"
#include "object_id.h"
#include "ea.h"
#include "misc.h"
#include "logging.h"
#include "xattrs.h"


static const char nf_ns_xattr_ntfs_acl[] = "system.ntfs_acl";
static const char nf_ns_xattr_attrib[] = "system.ntfs_attrib";
static const char nf_ns_xattr_attrib_be[] = "system.ntfs_attrib_be";
static const char nf_ns_xattr_efsinfo[] = "system.ntfs_efsinfo";
static const char nf_ns_xattr_reparse[] = "system.ntfs_reparse_data";
static const char nf_ns_xattr_object_id[] = "system.ntfs_object_id";
static const char nf_ns_xattr_dos_name[] = "system.ntfs_dos_name";
static const char nf_ns_xattr_times[] = "system.ntfs_times";
static const char nf_ns_xattr_times_be[] = "system.ntfs_times_be";
static const char nf_ns_xattr_crtime[] = "system.ntfs_crtime";
static const char nf_ns_xattr_crtime_be[] = "system.ntfs_crtime_be";
static const char nf_ns_xattr_ea[] = "system.ntfs_ea";
static const char nf_ns_xattr_posix_access[] = "system.posix_acl_access";
static const char nf_ns_xattr_posix_default[] = "system.posix_acl_default";

static const char nf_ns_alt_xattr_efsinfo[] = "user.ntfs.efsinfo";

struct XATTRNAME {
	enum SYSTEMXATTRS xattr;
	const char *name;
} ;

static struct XATTRNAME nf_ns_xattr_names[] = {
	{ XATTR_NTFS_ACL, nf_ns_xattr_ntfs_acl },
	{ XATTR_NTFS_ATTRIB, nf_ns_xattr_attrib },
	{ XATTR_NTFS_ATTRIB_BE, nf_ns_xattr_attrib_be },
	{ XATTR_NTFS_EFSINFO, nf_ns_xattr_efsinfo },
	{ XATTR_NTFS_REPARSE_DATA, nf_ns_xattr_reparse },
	{ XATTR_NTFS_OBJECT_ID, nf_ns_xattr_object_id },
	{ XATTR_NTFS_DOS_NAME, nf_ns_xattr_dos_name },
	{ XATTR_NTFS_TIMES, nf_ns_xattr_times },
	{ XATTR_NTFS_TIMES_BE, nf_ns_xattr_times_be },
	{ XATTR_NTFS_CRTIME, nf_ns_xattr_crtime },
	{ XATTR_NTFS_CRTIME_BE, nf_ns_xattr_crtime_be },
	{ XATTR_NTFS_EA, nf_ns_xattr_ea },
	{ XATTR_POSIX_ACC, nf_ns_xattr_posix_access },
	{ XATTR_POSIX_DEF, nf_ns_xattr_posix_default },
	{ XATTR_UNMAPPED, (char*)NULL } /* terminator */
};


/*
 *		Determine whether an extended attribute is mapped to
 *	internal data (original name in system namespace, or renamed)
 */

enum SYSTEMXATTRS ntfs_xattr_system_type(const char *name,
		ntfs_volume *vol)
{
	struct XATTRNAME *p;
	enum SYSTEMXATTRS ret;
#ifdef XATTR_MAPPINGS
	const struct XATTRMAPPING *q;
#endif /* XATTR_MAPPINGS */

	p = nf_ns_xattr_names;
	while (p->name && strcmp(p->name,name))
		p++;
	ret = p->xattr;
#ifdef XATTR_MAPPINGS
	if (!p->name && vol && vol->xattr_mapping) {
		q = vol->xattr_mapping;
		while (q && strcmp(q->name,name))
			q = q->next;
		if (q)
			ret = q->xattr;
	}
#else /* XATTR_MAPPINGS */
	if (!p->name
			&& vol
			&& vol->efs_raw
			&& !strcmp(nf_ns_alt_xattr_efsinfo,name))
		ret = XATTR_NTFS_EFSINFO;
#endif /* XATTR_MAPPINGS */
	return (ret);
}

#ifdef XATTR_MAPPINGS

/*
 *		Basic read from a user mapping file on another volume
 */

static int basicread(void *fileid, char *buf, size_t size, off_t offs __attribute__((unused)))
{
	return (read(*(int*)fileid, buf, size));
}


/*
 *		Read from a user mapping file on current NTFS partition
 */

static int localread(void *fileid, char *buf, size_t size, off_t offs)
{
	return (ntfs_attr_data_read((ntfs_inode*)fileid,
				AT_UNNAMED, 0, buf, size, offs));
}

/*
 *		Get a single mapping item from buffer
 *
 *	Always reads a full line, truncating long lines
 *	Refills buffer when exhausted
 *	Returns pointer to item, or NULL when there is no more
 *	Note : errors are logged, but not returned
// TODO partially share with acls.c
*/

static struct XATTRMAPPING *getmappingitem(FILEREADER reader, void *fileid,
		off_t *poffs, char *buf, int *psrc, s64 *psize)
{
	int src;
	int dst;
	char *pe;
	char *ps;
	char *pu;
	enum SYSTEMXATTRS xattr;
	int gotend;
	char maptext[LINESZ];
	struct XATTRMAPPING *item;

	src = *psrc;
	dst = 0;
	do {
		gotend = 0;
		while ((src < *psize)
				&& (buf[src] != '\n')) {
			/* ignore spaces */
			if ((dst < LINESZ)
					&& (buf[src] != '\r')
					&& (buf[src] != '\t')
					&& (buf[src] != ' '))
				maptext[dst++] = buf[src];
			src++;
		}
		if (src >= *psize) {
			*poffs += *psize;
			*psize = reader(fileid, buf, (size_t)BUFSZ, *poffs);
			src = 0;
		} else {
			gotend = 1;
			src++;
			maptext[dst] = '\0';
			dst = 0;
		}
	} while (*psize && ((maptext[0] == '#') || !gotend));
	item = (struct XATTRMAPPING*)NULL;
	if (gotend) {
		/* decompose into system name and user name */
		ps = maptext;
		pu = strchr(maptext,':');
		if (pu) {
			*pu++ = 0;
			pe = strchr(pu,':');
			if (pe)
				*pe = 0;
			/* check name validity */
			if ((strlen(pu) < 6) || strncmp(pu,"user.",5))
				pu = (char*)NULL;
			xattr = ntfs_xattr_system_type(ps,
					(ntfs_volume*)NULL);
			if (xattr == XATTR_UNMAPPED)
				pu = (char*)NULL;
		}
		if (pu) {
			item = (struct XATTRMAPPING*)ntfs_malloc(
					sizeof(struct XATTRMAPPING)
					+ strlen(pu));
			if (item) {
				item->xattr = xattr;
				strcpy(item->name,pu);
				item->next = (struct XATTRMAPPING*)NULL;
			}
		} else {
			ntfs_log_early_error("Bad xattr mapping item, aborting\n");
		}
	}
	*psrc = src;
	return (item);
}

/*
 *		Read xattr mapping file and split into their attribute.
 *	Parameters are kept in a chained list.
 *	Returns the head of list, if any
 *	Errors are logged, but not returned
 *
 *	If an absolute path is provided, the mapping file is assumed
 *	to be located in another mounted file system, and plain read()
 *	are used to get its contents.
 *	If a relative path is provided, the mapping file is assumed
 *	to be located on the current file system, and internal IO
 *	have to be used since we are still mounting and we have not
 *	entered the fuse loop yet.
 */

static struct XATTRMAPPING *ntfs_read_xattr_mapping(FILEREADER reader,
		void *fileid)
{
	char buf[BUFSZ];
	struct XATTRMAPPING *item;
	struct XATTRMAPPING *current;
	struct XATTRMAPPING *firstitem;
	struct XATTRMAPPING *lastitem;
	BOOL duplicated;
	int src;
	off_t offs;
	s64 size;

	firstitem = (struct XATTRMAPPING*)NULL;
	lastitem = (struct XATTRMAPPING*)NULL;
	offs = 0;
	size = reader(fileid, buf, (size_t)BUFSZ, (off_t)0);
	if (size > 0) {
		src = 0;
		do {
			item = getmappingitem(reader, fileid, &offs,
					buf, &src, &size);
			if (item) {
				/* check no double mapping */
				duplicated = FALSE;
				for (current=firstitem; current; current=current->next)
					if ((current->xattr == item->xattr)
							|| !strcmp(current->name,item->name))
						duplicated = TRUE;
				if (duplicated) {
					free(item);
					ntfs_log_early_error("Conflicting xattr mapping ignored\n");
				} else {
					item->next = (struct XATTRMAPPING*)NULL;
					if (lastitem)
						lastitem->next = item;
					else
						firstitem = item;
					lastitem = item;
				}
			}
		} while (item);
	}
	return (firstitem);
}

/*
 *		Build the extended attribute mappings to user namespace
 *
 *	Note : no error is returned. If we refused mounting when there
 *	is an error it would be too difficult to fix the offending file
 */

struct XATTRMAPPING *ntfs_xattr_build_mapping(ntfs_volume *vol,
		const char *xattrmap_path)
{
	struct XATTRMAPPING *firstmapping;
	struct XATTRMAPPING *mapping;
	BOOL user_efs;
	BOOL notfound;
	ntfs_inode *ni;
	int fd;

	firstmapping = (struct XATTRMAPPING*)NULL;
	notfound = FALSE;
	if (!xattrmap_path)
		xattrmap_path = XATTRMAPPINGFILE;
	if (xattrmap_path[0] == '/') {
		fd = open(xattrmap_path,O_RDONLY);
		if (fd > 0) {
			firstmapping = ntfs_read_xattr_mapping(basicread, (void*)&fd);
			close(fd);
		} else
			notfound = TRUE;
	} else {
		ni = ntfs_pathname_to_inode(vol, NULL, xattrmap_path);
		if (ni) {
			firstmapping = ntfs_read_xattr_mapping(localread, ni);
			ntfs_inode_close(ni);
		} else
			notfound = TRUE;
	}
	if (notfound && strcmp(xattrmap_path, XATTRMAPPINGFILE)) {
		ntfs_log_early_error("Could not open \"%s\"\n",xattrmap_path);
	}
	if (vol->efs_raw) {
		user_efs = TRUE;
		for (mapping=firstmapping; mapping; mapping=mapping->next)
			if (mapping->xattr == XATTR_NTFS_EFSINFO)
				user_efs = FALSE;
	} else
		user_efs = FALSE;
	if (user_efs) {
		mapping = (struct XATTRMAPPING*)ntfs_malloc(
				sizeof(struct XATTRMAPPING)
				+ strlen(nf_ns_alt_xattr_efsinfo));
		if (mapping) {
			mapping->next = firstmapping;
			mapping->xattr = XATTR_NTFS_EFSINFO;
			strcpy(mapping->name,nf_ns_alt_xattr_efsinfo);
			firstmapping = mapping;
		}
	}
	return (firstmapping);
}

void ntfs_xattr_free_mapping(struct XATTRMAPPING *mapping)
{
	struct XATTRMAPPING *p, *q;

	p = mapping;
	while (p) {
		q = p->next;
		free(p);
		p = q;
	}
}

#endif /* XATTR_MAPPINGS */
