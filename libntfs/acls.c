/**
 * acls.c - General function to process NTFS ACLs
 *
 *	This module is part of ntfs-3g library, but may also be
 *	integrated in tools running over Linux or Windows
 *
 * Copyright (c) 2007-2017 Jean-Pierre Andre
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

#include "config.h"

#ifdef HAVE_STDIO_H
#include <stdio.h>
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
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "types.h"
#include "layout.h"
#include "security.h"
#include "acls.h"
#include "misc.h"

/*
 *	A few useful constants
 */

/*
 *		SID for world  (S-1-1-0)
 */

static const char worldsidbytes[] = {
	1,			/* revision */
	1,			/* auth count */
	0, 0, 0, 0, 0, 1,	/* base */
	0, 0, 0, 0		/* 1st level */
} ;

const SID *worldsid = (const SID*)worldsidbytes;

/*
 *		SID for administrator
 */

static const char adminsidbytes[] = {
	1,			/* revision */
	2,			/* auth count */
	0, 0, 0, 0, 0, 5,	/* base */
	32, 0, 0, 0,		/* 1st level */
	32, 2, 0, 0		/* 2nd level */
};

const SID *adminsid = (const SID*)adminsidbytes;

/*
 *		Determine the size of a SID
 */

int ntfs_sid_size(const SID * sid)
{
	return (sid->sub_authority_count * 4 + 8);
}

/*
 *		Test whether two SID are equal
 */

BOOL ntfs_same_sid(const SID *first, const SID *second)
{
	int size;

	size = ntfs_sid_size(first);
	return ((ntfs_sid_size(second) == size)
			&& !memcmp(first, second, size));
}


/*
 *		Test whether a SID means "some user (or group)"
 *	Currently we only check for S-1-5-21... but we should
 *	probably test for other configurations
 */

BOOL ntfs_is_user_sid(const SID *usid)
{
	return ((usid->sub_authority_count == 5)
		&& (usid->identifier_authority.high_part ==  const_cpu_to_be16(0))
		&& (usid->identifier_authority.low_part ==  const_cpu_to_be32(5))
		&& (usid->sub_authority[0] ==  const_cpu_to_le32(21)));
}



/**
 * ntfs_valid_sid - determine if a SID is valid
 * @sid:	SID for which to determine if it is valid
 *
 * Determine if the SID pointed to by @sid is valid.
 *
 * Return TRUE if it is valid and FALSE otherwise.
 */
BOOL ntfs_valid_sid(const SID *sid)
{
	return sid && sid->revision == SID_REVISION &&
		sid->sub_authority_count <= SID_MAX_SUB_AUTHORITIES;
}
