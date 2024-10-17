/* SPDX-License-Identifier : GPL-2.0 */
/* fsck.c : common functions for fsck.
 * Manages MFT bitmap, cluster bitmap, fsck mount */

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
#include "lcnalloc.h"
#include "runlist.h"
#include "problem.h"

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

	/* mftbmp does not need to consider un-allocated mft bitmap,
	 * cause mft bitmap can be expaned more than initialized_size
	 * of mft_na */
	if (bm_i >= vol->max_fmb_cnt || !vol->fsck_mft_bitmap[bm_i]) {
		memset(zero_bm, 0, NTFS_BUF_SIZE);
		return zero_bm;
	}

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
	u32 last_idx = FB_ROUND_DOWN((vol->nr_clusters - 1) >> NTFSCK_BYTE_TO_BITS);

	if (bm_i >= vol->max_flb_cnt || !vol->fsck_lcn_bitmap[bm_i]) {
		memset(zero_bm, 0, NTFS_BUF_SIZE);

		/* consider last unused bitmap */
		if (bm_i == last_idx)
			ntfs_fsck_fill_unused_lcnbmp(vol, last_idx, zero_bm);

		return zero_bm;
	}

	/* consider last unused bitmap */
	if (bm_i == last_idx)
		ntfs_fsck_fill_unused_lcnbmp(vol, last_idx,
				vol->fsck_lcn_bitmap[bm_i]);

	return vol->fsck_lcn_bitmap[bm_i];
}

/*
 * condition: orig_lcn <= dup_lcn < orig_lcn + orig_len, orig_len > 0
 */
int ntfs_fsck_repair_cluster_dup(ntfs_attr *na, runlist *dup_rl)
{
	ntfs_volume *vol;
	runlist *rl;
	runlist *alloc_rl;
	runlist *punch_rl;
	int rl_size, alloc_size, punch_size;
	int i, j;

	if (!na || !na->ni || !dup_rl)
		return -EINVAL;

	vol = na->ni->vol;
	rl = na->rl;

	for (i = 0; dup_rl[i].length; i++) {
		ntfs_log_debug("### Start dup_rl[%d]\n", i);

		/* calculate original cluster runlist size */
		for (rl_size = 0; rl[rl_size].length; rl_size++)
			;
		rl_size++;

		alloc_rl = ntfs_cluster_alloc(vol, dup_rl[i].vcn, dup_rl[i].length,
				dup_rl[i].lcn + dup_rl[i].length, DATA_ZONE);
		if (!alloc_rl) {
			ntfs_log_error("Can' allocated new cluster\n");
			return -ENOMEM;
		}

		ntfs_log_debug("alloc_rl : allocated new rl\n");
		ntfs_debug_runlist_dump(alloc_rl);

		for (j = 0; alloc_rl[j].length; j++)
			;
		alloc_size = j + 1;

		rl = ntfs_rl_punch_hole(rl, rl_size, dup_rl[i].vcn, dup_rl[i].length, &punch_rl);
		ntfs_log_debug("punch_rl: extracted duplication rl\n");
		ntfs_debug_runlist_dump(punch_rl);

		for (j = 0; punch_rl[j].length; j++)
			;
		punch_size = j + 1;
		ntfs_log_debug("rl: punched original rl\n");
		ntfs_debug_runlist_dump(rl);

		alloc_rl = ntfs_copy_rl_clusters(vol, alloc_rl, alloc_size,
				punch_rl, punch_size);
		ntfs_free(punch_rl);
		punch_rl = NULL;

		rl = ntfs_runlists_merge(rl, alloc_rl);
		ntfs_log_debug("merged rl : merged with allocated rl\n");
		ntfs_debug_runlist_dump(rl);
		ntfs_log_debug("### Done dup_rl[%d]\n", i);
	}

	na->rl = rl;
	NAttrSetRunlistDirty(na);

	return STATUS_OK;
}

/*
 * ntfs_fsck_make_dup_runlist: make duplicated runlist, it return runlists
 * which have duplicated cluster information.
 * if return NULL, there's no duplicated cluster.
 */
runlist *ntfs_fsck_make_dup_runlist(runlist *orig_dup_rl, runlist *new_dup_rl)
{
	runlist *dup_rl;
	int orig_size;
	int i;

	ntfs_log_debug("make dup runlist orig_dup_rl dump\n");
	if (!orig_dup_rl) {
		/*
		 * 4K aligned allocation for preventing small fragmentation
		 * index '1' is for runlist end mark
		 */
		orig_dup_rl = ntfs_calloc((2 + 0xfff) & ~0xfff);
		orig_dup_rl[0].lcn = new_dup_rl->lcn;
		orig_dup_rl[0].vcn = new_dup_rl->vcn;
		orig_dup_rl[0].length = new_dup_rl->length;
		orig_dup_rl[1].lcn = LCN_ENOENT;
		orig_dup_rl[1].vcn = new_dup_rl->vcn + new_dup_rl->length;
		orig_dup_rl[1].length = 0;

		ntfs_log_debug("make new orig_dup_rl %p\n", orig_dup_rl);
		ntfs_debug_runlist_dump(orig_dup_rl);
		return orig_dup_rl;
	}

	for (i = 0; orig_dup_rl[i].length; i++)
		;
	orig_size = i + 1;

	ntfs_log_debug("orig_dup_rl\n");
	ntfs_debug_runlist_dump(orig_dup_rl);
	dup_rl = ntfs_rl_replace(orig_dup_rl, orig_size, new_dup_rl, 1, orig_size - 1);

	ntfs_log_debug("appended dup_rl\n");
	ntfs_debug_runlist_dump(dup_rl);

	return dup_rl;
}

void ntfs_fsck_fill_unused_lcnbmp(ntfs_volume *vol, s64 last_idx, u8 *last_bm)
{
	s64 start_pos;
	s64 last_bit;
	s64 last_bit_offset;
	s64 last_byte_offset;

	start_pos = last_idx * NTFS_BUF_SIZE;
	last_bit_offset = vol->nr_clusters - (start_pos << 3);
	last_byte_offset = last_bit_offset >> 3;

	/* fill all unused lcnbmp bytes by 1 (bytes over the maximum cluster number) */
	if ((last_byte_offset + 1) < NTFS_BUF_SIZE)
		memset(last_bm + last_byte_offset + 1, 0xff,
				NTFS_BUF_SIZE - (last_byte_offset + 1));

	/* fill all unused lcnbmp bit by 1 (bits over the maximu cluster number) */
	last_bit = last_bit_offset - (last_byte_offset << 3);
	last_bm[last_byte_offset] |= (0xff << last_bit);
	ntfs_log_trace("last idx %llu, last_bit_offset %llu, last_byte_offset %llu, "
			"last_bit %llu\n", last_idx, last_bit_offset, last_byte_offset, last_bit);
}

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
int ntfs_fsck_set_lcnbmp_range(ntfs_volume *vol, s64 lcn, s64 length, u8 bit)
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
					ntfs_log_info("Cluster Duplication %"PRIu64" - do not fix\n",
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
 * Check cluster bitmap duplication and set bitmap
 * If found cluster duplication, it makes runlist about duplication
 * return it.
 * If duplication is not found, return NULL
 *
 * it will check for rl[rl_idx] (rl[rl_idx].lcn, rl[rl_idx].length),
 */
runlist *ntfs_fsck_check_and_set_lcnbmp(ntfs_volume *vol, ntfs_attr *na, int rl_idx,
		u8 bit, runlist *dup_rl)
{
	/*
	 * last_lcn : calclate last lcn (bit)i
	 * rel_slcn : relative start lcn in fsck_lcn_bitmap[idx] (bit)
	 * idx_slcn : start(first) lcn of fsck_lcn_bitmap[idx] (bit)
	 */
	LCN lcn, last_lcn, rel_slcn, idx_slcn;
	VCN vcn, checked_vcn;

	/* relative length in fsck_lcn_bitmap[idx] (bit) */
	s64 length, remain_length, rel_length;
	runlist tmp_rl[2] = {0, };
	runlist *rl;

	s64 s_idx;	/* start index of fsck_lcn_bitmap */
	s64 e_idx;	/* end index of fsck_lcn_bitmap */

	s64 idx;
	u8 *buf;

	int i;

	if (!na || !na->rl || rl_idx < 0)
		return NULL;

	rl = na->rl;

	lcn = rl[rl_idx].lcn;
	vcn = rl[rl_idx].vcn;
	length = rl[rl_idx].length;
	if (length <= 0)
		return NULL;

	rel_slcn = lcn;
	last_lcn = lcn + length - 1;
	s_idx = FB_ROUND_DOWN(lcn >> NTFSCK_BYTE_TO_BITS);
	e_idx = FB_ROUND_DOWN(last_lcn >> NTFSCK_BYTE_TO_BITS);

	remain_length = length;
	tmp_rl[0].lcn = -1;
	checked_vcn = 0;
	for (idx = s_idx; idx <= e_idx; idx++) {
		if (!vol->fsck_lcn_bitmap[idx]) {
			vol->fsck_lcn_bitmap[idx] = (u8 *)ntfs_calloc(NTFS_BUF_SIZE);
			if (!vol->fsck_lcn_bitmap[idx]) {
				ntfs_log_error("Can't allocate lcn_bitmap buffer\n");
				return dup_rl;
			}
		}

		buf = vol->fsck_lcn_bitmap[idx];

		/* calculate first lcn of fsck_lcn_bitmap[idx] */
		idx_slcn = idx << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS);
		if (rel_slcn)
			rel_slcn -= idx_slcn;

		rel_length = (1 << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS)) - rel_slcn;
		if (remain_length < rel_length)
			rel_length = remain_length;

		for (i = 0; i < rel_length; i++) {
			if (!ntfs_bit_get_and_set(buf, rel_slcn + i, bit))
				continue;

			if (!bit)
				continue;

			/* duplicated */
			ntfs_log_info("Cluster Duplication %"PRIu64"\n",
					(idx_slcn + rel_slcn) + i);

#ifdef TRUNCATE_DATA
			/* handle duplicated cluster of AT_DATA */
			if (na->type == AT_DATA) {
				/* TODO: truncate data after duplicated cluster */
				continue;
			}
#endif

			/* handle duplicated cluster of all attribute except AT_DATA */
			if (tmp_rl[0].lcn == -1) {
				/* found first duplicated cluster */
				tmp_rl[0].lcn = idx_slcn + rel_slcn + i;
				tmp_rl[0].vcn = vcn + checked_vcn + i;
				tmp_rl[0].length = 1;
			} else if (tmp_rl[0].lcn + tmp_rl[0].length == (idx_slcn + rel_slcn + i)) {
				/* found contiguous duplicated cluster */
				tmp_rl[0].length++;
			} else {
				/* found non-contiguous duplicated cluster */
				dup_rl = ntfs_fsck_make_dup_runlist(dup_rl, tmp_rl);

				/* set this duplicated cluster information */
				tmp_rl[0].lcn = idx_slcn + rel_slcn + i;
				tmp_rl[0].vcn = vcn + checked_vcn + i;
				tmp_rl[0].length = 1;
			}
		}

		remain_length -= rel_length;
		checked_vcn += rel_length;
		if (remain_length <= 0)
			break;
		rel_slcn = 0;
	}

	if (tmp_rl[0].lcn >= 0) {
		dup_rl = ntfs_fsck_make_dup_runlist(dup_rl, tmp_rl);
		ntfs_log_debug("Previous check lcn(%"PRIu64") vcn (%"PRIu64") length(%"PRIu64")\n",
				rl_idx ? rl[rl_idx-1].lcn:0,
				rl_idx ? rl[rl_idx-1].vcn:0,
				rl_idx?rl[rl_idx-1].length:0);
		ntfs_log_debug("Check lcn(%"PRIu64") vcn (%"PRIu64") length(%"PRIu64")\n",
				lcn, vcn, length);
	}

	return dup_rl;
}

ntfs_volume *ntfs_fsck_mount(const char *path __attribute__((unused)),
		ntfs_mount_flags flags __attribute__((unused)))
{
	ntfs_volume *vol;

	vol = ntfs_mount(path, flags);
	if (!vol)
		return NULL;

	/* Initialize fsck lcn bitmap buffer array */
	vol->max_flb_cnt = FB_ROUND_DOWN((vol->nr_clusters - 1) >>
			NTFSCK_BYTE_TO_BITS) + 1;
	vol->fsck_lcn_bitmap = (u8 **)ntfs_calloc(sizeof(u8 *) * vol->max_flb_cnt);
	if (!vol->fsck_lcn_bitmap) {
		ntfs_umount(vol, FALSE);
		return NULL;
	}

	/* Initialize fsck mft bitmap buffer array */
	vol->max_fmb_cnt = FB_ROUND_DOWN((vol->mft_na->initialized_size >>
			      vol->mft_record_size_bits) >> NTFSCK_BYTE_TO_BITS) + 1;
	vol->fsck_mft_bitmap = (u8 **)ntfs_calloc(sizeof(u8 *) * vol->max_fmb_cnt);
	if (!vol->fsck_mft_bitmap) {
		free(vol->fsck_lcn_bitmap);
		ntfs_umount(vol, FALSE);
		return NULL;
	}

	vol->option_flags = flags;

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
