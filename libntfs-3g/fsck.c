/* SPDX-License-Identifier : GPL-2.0 */
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
 *
 * vol : ntfs_volume structure
 * mft_no : mft number to set on mft bitmap
 * value : 1 if set, 0 if clear
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

/* get fsck mft bitmap */
char ntfs_fsck_mftbmp_get(ntfs_volume *vol, const u64 bit)
{
	u32 bm_i = FB_ROUND_DOWN(bit >> NTFSCK_BYTE_TO_BITS);
	s64 bm_pos = (s64)bm_i << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS);

	if (bm_i >= vol->max_fmb_cnt || !vol->fsck_mft_bitmap[bm_i])
		return 0;

	return ntfs_bit_get(vol->fsck_mft_bitmap[bm_i], bit - bm_pos);
}

/* clear fsck mft bitmap */
int ntfs_fsck_mftbmp_clear(ntfs_volume *vol, u64 mft_no)
{
	return ntfs_fsck_set_mftbmp_value(vol, mft_no, 0);
}

/* set fsck mft bitmap */
int ntfs_fsck_mftbmp_set(ntfs_volume *vol, u64 mft_no)
{
	return ntfs_fsck_set_mftbmp_value(vol, mft_no, 1);
}

void ntfs_fsck_set_bitmap_range(u8 *bm, s64 pos, s64 length, u8 bit)
{
	while (length--)
		ntfs_bit_set(bm, pos++, bit);
}

u8 *ntfs_fsck_find_lcnbmp_block(ntfs_volume *vol, s64 pos)
{
	u32 bm_i = FB_ROUND_DOWN(pos);

	if (bm_i >= vol->max_flb_cnt || !vol->fsck_lcn_bitmap[bm_i])
		return zero_bm;

	return vol->fsck_lcn_bitmap[bm_i];
}

#define FSCK_CHECK_AND_SET(buf, start_lcn, pos, length, bit, check) \
do { \
	int i = 0; \
	while ((length)--) { \
		if (ntfs_bit_get_and_set((buf), (pos) + i, (bit))) { \
			if ((check) && (bit)) \
				ntfs_log_info("Cluster Duplication #1 " \
						" %"PRIu64"\n", (start_lcn) + i); \
		} \
		i++; \
	} \
} while (0)

int ntfs_fsck_set_lcnbmp_range(ntfs_volume *vol, s64 lcn, s64 length, u8 bit,
		BOOL check)
{
	s64 end = lcn + length - 1;
	s64 bm_i = FB_ROUND_DOWN(lcn >> NTFSCK_BYTE_TO_BITS);
	s64 bm_end = FB_ROUND_DOWN(end >> NTFSCK_BYTE_TO_BITS);
	s64 bm_bit = (s64)bm_i << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS);
	s64 lcn_diff = lcn - bm_bit;
	u8 *buf;

	if (length <= 0)
		return -EINVAL;

	if (!vol->fsck_lcn_bitmap[bm_i]) {
		vol->fsck_lcn_bitmap[bm_i] = (u8 *)ntfs_calloc(NTFS_BUF_SIZE);
		if (!vol->fsck_lcn_bitmap[bm_i])
			return -ENOMEM;
	}

	buf = vol->fsck_lcn_bitmap[bm_i];
	if (bm_end == bm_i) {
		FSCK_CHECK_AND_SET(buf, lcn, lcn_diff, length, bit, check);
	} else {
		s64 loop = NTFSCK_BM_BITS_SIZE - lcn_diff;

		FSCK_CHECK_AND_SET(buf, lcn, lcn_diff, loop, bit, check);

		length -= NTFSCK_BM_BITS_SIZE - lcn_diff;
		bm_i++;

		for (; bm_i <= bm_end; bm_i++) {
			bm_bit = (s64)bm_i << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS);
			if (length < 0) {
				ntfs_log_error("length should not be negative here! : %"PRId64"\n",
						length);
				exit(1);
			}

			if (!vol->fsck_lcn_bitmap[bm_i]) {
				vol->fsck_lcn_bitmap[bm_i] =
					(u8 *)ntfs_calloc(NTFS_BUF_SIZE);
				if (!vol->fsck_lcn_bitmap[bm_i])
					return -ENOMEM;
			}

			if (bm_i == bm_end) {
				if (length > NTFSCK_BM_BITS_SIZE) {
					ntfs_log_error("remain length could not be bigger than bm size:"
							"%"PRId64"\n", length);
					exit(1);
				}
				buf = vol->fsck_lcn_bitmap[bm_i];
				FSCK_CHECK_AND_SET(buf, bm_bit, 0, length, bit, check);
			} else {
				/*
				 * It is useful to use memset rather than setting
				 * each bit using ntfs_fsck_set_bitmap_range().
				 * because this bitmap buffer should be filled as
				 * the same value.
				 */
				if (bit == 0)
					memset(vol->fsck_lcn_bitmap[bm_i], 0, NTFS_BUF_SIZE);
				else {
					u64 *p_bmp;
					int i;

					for (i = 0; i < (NTFS_BUF_SIZE >> 3); i++, p_bmp++) {
						p_bmp = (u64 *)vol->fsck_lcn_bitmap[bm_i];
						if (*p_bmp == 0) {
							continue;
						}

						ntfs_log_info("Cluster Duplication #4 from %"PRIu64" to xxx\n",
								bm_bit + ((i * 8) << 3));

					}
					memset(vol->fsck_lcn_bitmap[bm_i], 0xFF, NTFS_BUF_SIZE);
				}
				length -= NTFSCK_BM_BITS_SIZE;
			}
		}
	}

	return 0;
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
