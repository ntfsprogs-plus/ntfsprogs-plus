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
char ntfs_fsck_mftbmp_get(ntfs_volume *vol, const u64 mft_no)
{
	u32 bm_i = FB_ROUND_DOWN(mft_no >> NTFSCK_BYTE_TO_BITS);
	s64 bm_pos = (s64)bm_i << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS);

	if (bm_i >= vol->max_fmb_cnt || !vol->fsck_mft_bitmap[bm_i])
		return 0;

	return ntfs_bit_get(vol->fsck_mft_bitmap[bm_i], mft_no - bm_pos);
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

u8 *ntfs_fsck_find_mftbmp_block(ntfs_volume *vol, s64 pos)
{
	u32 bm_i = FB_ROUND_DOWN(pos);

	if (bm_i >= vol->max_fmb_cnt || !vol->fsck_mft_bitmap[bm_i])
		return zero_bm;

	return vol->fsck_mft_bitmap[bm_i];
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
	while (i < (length)) { \
		if (ntfs_bit_get_and_set((buf), (pos) + i, (bit))) { \
			if ((check) && (bit)) \
				ntfs_log_info("Cluster Duplication #1 " \
						" %"PRIu64"\n", (start_lcn) + i); \
		} \
		i++; \
	} \
} while (0)

/*
 * for a entry of runlists (lcn, length), set/clear lcn bitmap
 *                          ^^^  ^^^^^^
 * fsck_lcn_bitmap
 *   0-th                 s_idx                             e_idx
 * |------|     |----------------------|          |----------------------|
 * |      | ... |                      | ...      |                      |
 * |      |     |      |<-- rel_len -->|          |<-- rel_len  ->|      |
 * |------|     |------|---------------|          |---------------|------|
 *              |      |<---- remain_len (initially length) ----->|
 *              |      |                          | ^^^^^^
 *              |     lcn                         |    last_lcn = lcn + length - 1
 *              |     ^^^                         |
 *              | rel_slcn in s_idx           idx_slcn = rel_slcn in e_idx
 *          idx_slcn
 */
int ntfs_fsck_set_lcnbmp_range(ntfs_volume *vol, s64 lcn, s64 length, u8 bit, BOOL check)
{
	/* calculate last lcn (bit) */
	s64 last_lcn = lcn + length - 1;
	/* start index of fsck_lcn_bitmap */
	s64 s_idx = FB_ROUND_DOWN(lcn >> NTFSCK_BYTE_TO_BITS);
	/* end index of fsck_lcn_bitmap */
	s64 e_idx = FB_ROUND_DOWN(last_lcn >> NTFSCK_BYTE_TO_BITS);

	s64 idx_slcn;       /* real start lcn of fsck_lcn_bitmap[idx] (bit) */
	s64 rel_slcn = lcn; /* relative start lcn in fsck_lcn_bitmap[idx] (bit) */
	s64 remain_length = 0;
	s64 rel_length;	    /* relative length in fsck_lcn_bitmap[idx] (bit) */

	s64 idx;
	u8 *buf;
	int i;

	if (length <= 0)
		return -EINVAL;

	remain_length = length;
	for (idx = s_idx; idx <= e_idx; idx++) {
		if (!vol->fsck_lcn_bitmap[idx]) {
			vol->fsck_lcn_bitmap[idx] = (u8 *)ntfs_calloc(NTFS_BUF_SIZE);
			if (!vol->fsck_lcn_bitmap[idx])
				return -ENOMEM;
		}

		buf = vol->fsck_lcn_bitmap[idx];

		idx_slcn = idx << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS);
		if (rel_slcn)
			rel_slcn -= idx_slcn;

		rel_length = (1 << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS)) - rel_slcn;
		if (remain_length < rel_length)
			rel_length = remain_length;

		for (i = 0; i < rel_length; i++) {
			if (ntfs_bit_get_and_set(buf, rel_slcn + i, bit)) {
				if (bit)
					ntfs_log_info("Cluster Duplication #1 %"PRIu64"\n",
							(idx_slcn + rel_slcn) + i);
			}
		}

		remain_length -= rel_length;
		if (remain_length <= 0)
			break;
		rel_slcn = 0;
	}
	return 0;
}

/*
 * For resolving cluster duplication.
 * Set fsck cluster bitmap and if it found cluster duplication,
 * then this function will try to resolve it.
 * This function only use for setting bitmap.
 *
 * this function logic looks like same as ntfs_fsck_set_lcnbmp_range()
 * except cluster duplication handling logic.
 *
 * it will check for rl[idx] (rl[idx].lcn, rl[idx].length),
 * if it found duplication, will change whole rl data
 */
int ntfs_fsck_set_and_check_lcnbmp(ntfs_volume *vol, runlist *rl, int item)
{
	s64 lcn;
	s64 length;

	s64 last_lcn;	/* calculate last lcn (bit) */
	s64 s_idx;	/* start index of fsck_lcn_bitmap */
	s64 e_idx;	/* end index of fsck_lcn_bitmap */

	s64 idx_slcn;	/* real start lcn of fsck_lcn_bitmap[idx] (bit) */
	s64 rel_slcn;	/* relative start lcn in fsck_lcn_bitmap[idx] (bit) */
	s64 remain_length = 0;
	s64 rel_length;	/* relative length in fsck_lcn_bitmap[idx] (bit) */

	s64 idx;
	u8 *buf;

	int i;

	if (!rl || item < 0)
		return -EINVAL;

	lcn = rl[item].lcn;
	length = rl[item].length;
	if (length <= 0)
		return -EINVAL;

	rel_slcn = lcn;
	last_lcn = lcn + length - 1;
	s_idx = FB_ROUND_DOWN(lcn >> NTFSCK_BYTE_TO_BITS);
	e_idx = FB_ROUND_DOWN(last_lcn >> NTFSCK_BYTE_TO_BITS);

	remain_length = length;
	for (idx = s_idx; idx <= e_idx; idx++) {
		if (!vol->fsck_lcn_bitmap[idx]) {
			vol->fsck_lcn_bitmap[idx] = (u8 *)ntfs_calloc(NTFS_BUF_SIZE);
			if (!vol->fsck_lcn_bitmap[idx])
				return -ENOMEM;
		}

		buf = vol->fsck_lcn_bitmap[idx];

		idx_slcn = idx << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS);
		if (rel_slcn)
			rel_slcn -= idx_slcn;

		rel_length = (1 << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS)) - rel_slcn;
		if (remain_length < rel_length)
			rel_length = remain_length;

		for (i = 0; i < rel_length; i++) {
			if (ntfs_bit_get_and_set(buf, rel_slcn + i, 1)) {
				/* TODO: call handling cluster duplication function */
				ntfs_log_info("Cluster Duplication #1 %"PRIu64"\n",
						(idx_slcn + rel_slcn) + i);
			}
		}

		remain_length -= rel_length;
		if (remain_length <= 0)
			break;
		rel_slcn = 0;
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
