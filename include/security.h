/*
 * security.h - Exports for handling security/ACLs in NTFS.
 *              Originated from the Linux-NTFS project.
 *
 * Copyright (c) 2004      Anton Altaparmakov
 * Copyright (c) 2005-2006 Szabolcs Szakacsits
 * Copyright (c) 2007-2010 Jean-Pierre Andre
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

#ifndef _NTFS_SECURITY_H
#define _NTFS_SECURITY_H

#include "types.h"
#include "layout.h"
#include "inode.h"
#include "dir.h"
#include "endians.h"


/*
 *          item in the mapping list
 */

struct MAPPING {
	struct MAPPING *next;
	int xid;		/* linux id : uid or gid */
	SID *sid;		/* Windows id : usid or gsid */
	int grcnt;		/* group count (for users only) */
	gid_t *groups;		/* groups which the user is member of */
};

/*
 *		Entry in the permissions cache
 *	Note : this cache is not organized as a generic cache
 */

struct CACHED_PERMISSIONS {
	uid_t uid;
	gid_t gid;
	le32 inh_fileid;
	le32 inh_dirid;
	unsigned int mode:12;
	unsigned int valid:1;
} ;

/*
 *	Entry in the permissions cache for directories with no security_id
 */

struct CACHED_PERMISSIONS_LEGACY {
	struct CACHED_PERMISSIONS_LEGACY *next;
	struct CACHED_PERMISSIONS_LEGACY *previous;
	void *variable;
	size_t varsize;
	union ALIGNMENT payload[0];
	/* above fields must match "struct CACHED_GENERIC" */
	u64 mft_no;
	struct CACHED_PERMISSIONS perm;
} ;

/*
 *	Entry in the securid cache
 */

struct CACHED_SECURID {
	struct CACHED_SECURID *next;
	struct CACHED_SECURID *previous;
	void *variable;
	size_t varsize;
	union ALIGNMENT payload[0];
	/* above fields must match "struct CACHED_GENERIC" */
	uid_t uid;
	gid_t gid;
	unsigned int dmode;
	le32 securid;
} ;

/*
 *	Header of the security cache
 *	(has no cache structure by itself)
 */

struct CACHED_PERMISSIONS_HEADER {
	unsigned int last;
	/* statistics for permissions */
	unsigned long p_writes;
	unsigned long p_reads;
	unsigned long p_hits;
} ;

/*
 *	The whole permissions cache
 */

struct PERMISSIONS_CACHE {
	struct CACHED_PERMISSIONS_HEADER head;
	struct CACHED_PERMISSIONS *cachetable[1]; /* array of variable size */
} ;

/*
 *	Security flags values
 */

enum {
	SECURITY_DEFAULT,	/* rely on fuse for permissions checking */
	SECURITY_RAW,		/* force same ownership/permissions on files */
	SECURITY_ACL,		/* enable Posix ACLs (when compiled in) */
	SECURITY_ADDSECURIDS,	/* upgrade old security descriptors */
	SECURITY_STATICGRPS,	/* use static groups for access control */
	SECURITY_WANTED		/* a security related option was present */
} ;

/*
 *	Security context, needed by most security functions
 */

enum { MAPUSERS, MAPGROUPS, MAPCOUNT } ;

struct SECURITY_CONTEXT {
	ntfs_volume *vol;
	struct MAPPING *mapping[MAPCOUNT];
	struct PERMISSIONS_CACHE **pseccache;
	uid_t uid; /* uid of user requesting (not the mounter) */
	gid_t gid; /* gid of user requesting (not the mounter) */
	pid_t tid; /* thread id of thread requesting */
	mode_t umask; /* umask of requesting thread */
} ;


extern BOOL ntfs_guid_is_zero(const GUID *guid);
extern char *ntfs_guid_to_mbs(const GUID *guid, char *guid_str);

extern int ntfs_sid_to_mbs_size(const SID *sid);
extern char *ntfs_sid_to_mbs(const SID *sid, char *sid_str,
		size_t sid_str_size);
extern void ntfs_generate_guid(GUID *guid);
extern int ntfs_sd_add_everyone(ntfs_inode *ni);

int ntfs_open_secure(ntfs_volume *vol);
int ntfs_close_secure(ntfs_volume *vol);

#endif /* defined _NTFS_SECURITY_H */
