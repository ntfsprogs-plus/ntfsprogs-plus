/*
 *
 * Copyright (c) 2007-2008 Jean-Pierre Andre
 *
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the NTFS-3G
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef ACLS_H
#define ACLS_H

#include "endians.h"

/*
 *	Configuration for reading mapping files
 */

#define BUFSZ 1024		/* buffer size to read mapping file */
#define LINESZ 120              /* maximum useful size of a mapping line */

typedef int (*FILEREADER)(void *fileid, char *buf, size_t size, off_t pos);

/*
 *		Constants defined in acls.c
 */

extern const SID *adminsid;
extern const SID *worldsid;

/*
 *		Functions defined in acls.c
 */

BOOL ntfs_valid_sid(const SID *sid);
BOOL ntfs_same_sid(const SID *first, const SID *second);
BOOL ntfs_is_user_sid(const SID *usid);
int ntfs_sid_size(const SID * sid);

#endif /* ACLS_H */
