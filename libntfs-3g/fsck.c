#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STDIO_H
#include <stdio.h>
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
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#if defined(__sun) && defined (__SVR4)
#include <sys/mnttab.h>
#endif

#include "fsck.h"
#include "debug.h"
#include "logging.h"
#include "misc.h"
#include "bitmap.h"

u8 zero_bm[NTFS_BUF_SIZE];

/*
 * function to set fsck mft bitmap value
 */
int ntfs_fsck_set_mftbmp_value(ntfs_volume *vol, u64 mft_no, int value)
{
	u32 bm_i = FB_ROUND_DOWN(mft_no >> NTFSCK_BYTE_TO_BITS);
	s64 bm_pos = (s64)bm_i << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS);
	s64 mft_diff = mft_no - bm_pos;

	if (bm_i >= vol->max_fmb_cnt) {
		ntfs_log_error("bm_i(%u) exceeded max_fmb_cnt(%"PRIu64")\n",
				bm_i, vol->max_fmb_cnt);
		return -EINVAL;
	}

	if (!vol->fsck_mft_bitmap[bm_i]) {
		vol->fsck_mft_bitmap[bm_i] = (u8 *)ntfs_calloc(NTFS_BUF_SIZE);
		if (!vol->fsck_mft_bitmap[bm_i])
			return -ENOMEM;
	}

	ntfs_bit_set(vol->fsck_mft_bitmap[bm_i], mft_diff, value);
	return 0;
}

/* fsck mft bitmap get */
char ntfs_fsck_mftbmp_get(ntfs_volume *vol, const u64 bit)
{
	u32 bm_i = FB_ROUND_DOWN(bit >> NTFSCK_BYTE_TO_BITS);
	s64 bm_pos = (s64)bm_i << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS);

	if (bm_i >= vol->max_fmb_cnt || !vol->fsck_mft_bitmap[bm_i])
		return 0;

	return ntfs_bit_get(vol->fsck_mft_bitmap[bm_i], bit - bm_pos);
}

/* fsck mft bitmap clear */
int ntfs_fsck_mftbmp_clear(ntfs_volume *vol, u64 mft_no)
{
	return ntfs_fsck_set_mftbmp_value(vol, mft_no, 0);
}

/* fsck mft bitmap set */
int ntfs_fsck_mftbmp_set(ntfs_volume *vol, u64 mft_no)
{
	return ntfs_fsck_set_mftbmp_value(vol, mft_no, 1);
}

void ntfs_fsck_set_bitmap_range(u8 *bm, s64 pos, s64 length, u8 bit)
{
	while (length--)
		ntfs_bit_set(bm, pos++, bit);
}

u8 *ntfs_fsck_get_lcnbmp_block(ntfs_volume *vol, s64 pos)
{
	u32 bm_i = FB_ROUND_DOWN(pos);

	if (bm_i >= vol->max_flb_cnt || !vol->fsck_lcn_bitmap[bm_i])
		return zero_bm;

	return vol->fsck_lcn_bitmap[bm_i];
}

ntfs_volume *ntfs_fsck_mount(const char *path __attribute__((unused)),
		ntfs_mount_flags flags __attribute__((unused)))
{
	ntfs_volume *vol;

	vol = ntfs_mount(path, flags);
	if (!vol)
		return NULL;

	/* Initialize fsck lcn bitmap buffer array */
	vol->max_flb_cnt = FB_ROUND_DOWN((vol->nr_clusters + 7)) + 1;
	vol->fsck_lcn_bitmap = (u8 **)ntfs_calloc(sizeof(u8 *) * vol->max_flb_cnt);
	if (!vol->fsck_lcn_bitmap) {
		ntfs_umount(vol, FALSE);
		return NULL;
	}

	/* Initialize fsck mft bitmap buffer array */
	vol->max_fmb_cnt = FB_ROUND_DOWN(vol->mft_na->initialized_size >>
				      vol->mft_record_size_bits) + 1;
	vol->fsck_mft_bitmap = (u8 **)ntfs_calloc(sizeof(u8 *) * vol->max_fmb_cnt);
	if (!vol->fsck_mft_bitmap) {
		free(vol->fsck_lcn_bitmap);
		ntfs_umount(vol, FALSE);
		return NULL;
	}

	return vol;
}

void ntfs_fsck_umount(ntfs_volume *vol)
{
	int bm_i;

	for (bm_i = 0; bm_i < vol->max_flb_cnt; bm_i++)
		if (vol->fsck_lcn_bitmap[bm_i])
			free(vol->fsck_lcn_bitmap[bm_i]);
	free(vol->fsck_lcn_bitmap);

	for (bm_i = 0; bm_i < vol->max_fmb_cnt; bm_i++)
		if (vol->fsck_mft_bitmap[bm_i])
			free(vol->fsck_mft_bitmap[bm_i]);
	free(vol->fsck_mft_bitmap);

	ntfs_umount(vol, FALSE);
}
