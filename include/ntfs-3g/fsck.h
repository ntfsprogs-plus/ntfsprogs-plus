/* SPDX-License-Identifier : GPL-2.0 */
#ifndef _NTFS_FSCK_H
#define _NTFS_FSCK_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
	/* Do not #include <sys/mount.h> here : conflicts with <linux/fs.h> */
#ifdef HAVE_MNTENT_H
#include <mntent.h>
#endif

#include "volume.h"

#define NTFS_BUF_SIZE_BITS		(13)
#define NTFSCK_BYTE_TO_BITS		(3)
#define NTFSCK_BM_BITS_SIZE	(NTFS_BUF_SIZE << 3)
#define FB_ROUND_UP(x)		(((x) + ((NTFS_BUF_SIZE << 3) - 1)) & ~((NTFS_BUF_SIZE << 3) - 1))
#define FB_ROUND_DOWN(x)	(((x) & ~(NTFS_BUF_SIZE - 1)) >> NTFS_BUF_SIZE_BITS)

int ntfs_fsck_set_mftbmp_value(ntfs_volume *vol, u64 mft_no, int value);
char ntfs_fsck_mftbmp_get(ntfs_volume *vol, const u64 bit);
int ntfs_fsck_mftbmp_clear(ntfs_volume *vol, u64 mft_no);
int ntfs_fsck_mftbmp_set(ntfs_volume *vol, u64 mft_no);
void ntfs_fsck_set_bitmap_range(u8 *bm, s64 pos, s64 length, u8 bit);
u8 *ntfs_fsck_get_lcnbmp_block(ntfs_volume *vol, s64 pos);
int ntfsck_set_lcnbmp_range(ntfs_volume *vol, s64 lcn, s64 length, u8 bit);

ntfs_volume *ntfs_fsck_mount(const char *path __attribute__((unused)),
		ntfs_mount_flags flags __attribute__((unused)));
void ntfs_fsck_umount(ntfs_volume *vol);
#endif /* _NTFS_FSCK_H */
