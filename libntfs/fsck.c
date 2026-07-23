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

/*
 * Optional disk-backed cluster shadow bitmap. On Linux the literal (partially
 * filled) blocks can be carried in a memory-mapped, immediately-unlinked
 * scratch file instead of the heap, so the resident set is bounded by the
 * kernel page cache rather than by the number of literal blocks.
 */
#if defined(__linux__)
#include <sys/mman.h>
#define NTFSCK_HAVE_SCRATCH	1
/* Below this projected arena size the RAM backend is used (scratch not worth it). */
#define NTFSCK_SCRATCH_MIN	(64LL << 20)
/* System page size; MADV_DONTNEED is only used when a block spans whole pages. */
static long fsck_scratch_page;
#endif

u8 zero_bm[NTFS_BUF_SIZE];

/*
 * All-ones sentinel for the fsck cluster (lcn) shadow bitmap. A slot in
 * vol->fsck_lcn_bitmap[] can be: NULL - block is entirely free (reads share
 * read-only zero_bm) FB_ONES - block is entirely allocated (reads share
 * read-only ones_bm) other ptr - a private literal NTFS_BUF_SIZE block
 * (partially filled) The two sentinels cost no per-block storage, which
 * collapses the common "large contiguous allocation / mostly-used volume"
 * cases from ~1 bit per cluster down to almost nothing.
 */
static u8 ones_bm[NTFS_BUF_SIZE];
#define FB_ONES		((u8 *)ones_bm)
/* Number of cluster bits represented by one NTFS_BUF_SIZE bitmap block. */
#define FB_BLOCK_BITS	(1 << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS))

/*
 * Ensure fsck_lcn_bitmap[idx] is a private, writable literal block,
 * converting either sentinel (all-free NULL or all-allocated FB_ONES) into
 * real storage. When a scratch arena is active the storage is a fixed slice
 * of the mmap'd file (arena + idx * NTFS_BUF_SIZE) rather than the heap.
 */
static u8 *ntfs_fsck_lcnbmp_materialize(ntfs_volume *vol, s64 idx)
{
	u8 *buf = vol->fsck_lcn_bitmap[idx];

	/* Already a literal block. */
	if (buf && buf != FB_ONES)
		return buf;

	if (vol->fsck_lcn_arena) {
		u8 *slot = vol->fsck_lcn_arena + (size_t)idx * NTFS_BUF_SIZE;

		/* The arena slice may hold stale data from a collapsed block, so
		 * always initialize on the sentinel -> literal transition. */
		memset(slot, (buf == FB_ONES) ? 0xff : 0x00, NTFS_BUF_SIZE);
		vol->fsck_lcn_setcnt[idx] = (buf == FB_ONES) ? FB_BLOCK_BITS : 0;
		vol->fsck_lcn_bitmap[idx] = slot;
		return slot;
	}

	if (buf == FB_ONES) {
		buf = (u8 *)ntfs_malloc(NTFS_BUF_SIZE);
		if (!buf)
			return NULL;
		memset(buf, 0xff, NTFS_BUF_SIZE);
		vol->fsck_lcn_setcnt[idx] = FB_BLOCK_BITS;
	} else {
		buf = (u8 *)ntfs_calloc(NTFS_BUF_SIZE);
		if (!buf)
			return NULL;
		vol->fsck_lcn_setcnt[idx] = 0;
	}
	vol->fsck_lcn_bitmap[idx] = buf;
	return buf;
}

/*
 * Collapse a fully-set literal block into the all-ones sentinel, releasing
 * its NTFS_BUF_SIZE storage. No-op unless every bit in the block is set.
 */
static void ntfs_fsck_lcnbmp_try_collapse(ntfs_volume *vol, s64 idx)
{
	u8 *buf = vol->fsck_lcn_bitmap[idx];

	if (!buf || buf == FB_ONES ||
			vol->fsck_lcn_setcnt[idx] != FB_BLOCK_BITS)
		return;

#ifdef NTFSCK_HAVE_SCRATCH
	if (vol->fsck_lcn_arena) {
		/*
		 * Drop the arena slice's resident pages. Only when a block is a whole
		 * number of pages, so this can never disturb a neighbouring block that
		 * shares a page (large-page systems).
		 */
		if (fsck_scratch_page > 0 && (NTFS_BUF_SIZE % fsck_scratch_page) == 0)
			madvise(buf, NTFS_BUF_SIZE, MADV_DONTNEED);
	} else
#endif
		free(buf);
	vol->fsck_lcn_bitmap[idx] = FB_ONES;
}

/*
 * Set up (or decline) the disk-backed scratch arena for the cluster shadow
 * bitmap. On any failure the RAM backend is left in place (arena == NULL).
 */
static void ntfs_fsck_scratch_init(ntfs_volume *vol, const char *dir)
{
	vol->fsck_lcn_arena = NULL;
	vol->fsck_lcn_arena_size = 0;
	vol->fsck_lcn_arena_fd = -1;

#ifdef NTFSCK_HAVE_SCRATCH
	{
		char tmpl[PATH_MAX];
		s64 size = (s64)vol->max_flb_cnt * NTFS_BUF_SIZE;
		void *arena;
		int fd, ret;

		if (!dir || !*dir)
			return;			/* not requested */
		if (size < NTFSCK_SCRATCH_MIN)
			return;			/* too small to be worth it */

		fsck_scratch_page = sysconf(_SC_PAGESIZE);

		snprintf(tmpl, sizeof(tmpl), "%s/ntfsck-lcnbmp-XXXXXX", dir);
		fd = mkstemp(tmpl);
		if (fd < 0) {
			ntfs_log_perror("fsck scratch: mkstemp(%s) failed, "
					"using RAM cluster bitmap", dir);
			return;
		}
		/* Unlink immediately: nothing is left behind on a crash or an
		 * unplug, and the space is reclaimed when the fd is closed. */
		unlink(tmpl);

		/* Reserve the whole arena up front. A later page fault can then
		 * never hit ENOSPC, which on an mmap would raise SIGBUS and abort
		 * the repair mid-flight. */
		ret = posix_fallocate(fd, 0, size);
		if (ret) {
			errno = ret;
			ntfs_log_perror("fsck scratch: cannot reserve %lld bytes "
					"in %s, using RAM cluster bitmap",
					(long long)size, dir);
			close(fd);
			return;
		}

		arena = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (arena == MAP_FAILED) {
			ntfs_log_perror("fsck scratch: mmap failed, "
					"using RAM cluster bitmap");
			close(fd);
			return;
		}

		vol->fsck_lcn_arena = (u8 *)arena;
		vol->fsck_lcn_arena_size = size;
		vol->fsck_lcn_arena_fd = fd;
		ntfs_log_info("fsck: using %lld MiB disk-backed cluster bitmap "
				"under %s\n", (long long)(size >> 20), dir);
	}
#else
	(void)dir;
#endif
}

static void ntfs_fsck_scratch_free(ntfs_volume *vol)
{
#ifdef NTFSCK_HAVE_SCRATCH
	if (vol->fsck_lcn_arena)
		munmap(vol->fsck_lcn_arena, vol->fsck_lcn_arena_size);
#endif
	if (vol->fsck_lcn_arena_fd >= 0)
		close(vol->fsck_lcn_arena_fd);
	vol->fsck_lcn_arena = NULL;
	vol->fsck_lcn_arena_size = 0;
	vol->fsck_lcn_arena_fd = -1;
}

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

u8 *ntfs_fsck_find_lcnbmp_block(ntfs_volume *vol, s64 pos)
{
	u32 bm_i = FB_ROUND_DOWN(pos);
	u32 last_idx = FB_ROUND_DOWN((vol->nr_clusters - 1) >> NTFSCK_BYTE_TO_BITS);

	/*
	 * Fully-allocated block: return the shared read-only all-ones buffer.
	 * The trailing-pad fill-up (fill_unused) only sets bits to 1, so it is
	 * redundant here and is skipped.
	 */
	if (bm_i < vol->max_flb_cnt && vol->fsck_lcn_bitmap[bm_i] == FB_ONES)
		return ones_bm;

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
 * The occupancy oracle (vol->fsck_alloc_bitmap) is a set-only twin of the
 * cluster shadow bitmap. The pass-1 MFT scan marks every cluster a valid
 * inode references so ntfs_cluster_alloc() can avoid them (see
 * ntfs_fsck_or_alloc_lcnbmp()).
 */
static u8 *ntfs_fsck_alloc_materialize(ntfs_volume *vol, s64 idx)
{
	u8 *buf = vol->fsck_alloc_bitmap[idx];

	if (buf && buf != FB_ONES)
		return buf;

	if (buf == FB_ONES) {
		buf = (u8 *)ntfs_malloc(NTFS_BUF_SIZE);
		if (!buf)
			return NULL;
		memset(buf, 0xff, NTFS_BUF_SIZE);
		vol->fsck_alloc_setcnt[idx] = FB_BLOCK_BITS;
	} else {
		buf = (u8 *)ntfs_calloc(NTFS_BUF_SIZE);
		if (!buf)
			return NULL;
		vol->fsck_alloc_setcnt[idx] = 0;
	}
	vol->fsck_alloc_bitmap[idx] = buf;
	return buf;
}

/* Collapse a fully-set literal oracle block back into the FB_ONES sentinel. */
static void ntfs_fsck_alloc_try_collapse(ntfs_volume *vol, s64 idx)
{
	u8 *buf = vol->fsck_alloc_bitmap[idx];

	if (!buf || buf == FB_ONES || vol->fsck_alloc_setcnt[idx] != FB_BLOCK_BITS)
		return;
	free(buf);
	vol->fsck_alloc_bitmap[idx] = FB_ONES;
}

/*
 * Mark [lcn, lcn+length) occupied in the oracle. Set-only: a bit that is
 * already set is simply left set (two inodes overlapping is a real
 * duplication, but it is detected against the shadow bitmap elsewhere; here
 * over-marking is exactly the safe direction for an allocator barrier).
 */
int ntfs_fsck_set_alloc_lcnbmp_range(ntfs_volume *vol, s64 lcn, s64 length)
{
	s64 last_lcn = lcn + length - 1;
	s64 s_idx = FB_ROUND_DOWN(lcn >> NTFSCK_BYTE_TO_BITS);
	s64 e_idx = FB_ROUND_DOWN(last_lcn >> NTFSCK_BYTE_TO_BITS);
	s64 idx_slcn;
	s64 rel_slcn = lcn;
	s64 remain_length;
	s64 rel_length;
	s64 idx;
	u8 *buf;
	u8 *cur;
	BOOL full_cover;
	int i;

	if (length <= 0)
		return -EINVAL;

	remain_length = length;
	for (idx = s_idx; idx <= e_idx; idx++) {
		cur = vol->fsck_alloc_bitmap[idx];

		idx_slcn = idx << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS);
		if (rel_slcn)
			rel_slcn -= idx_slcn;

		rel_length = (1 << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS)) - rel_slcn;
		if (remain_length < rel_length)
			rel_length = remain_length;

		full_cover = (rel_slcn == 0 && rel_length == FB_BLOCK_BITS);

		if (cur == FB_ONES)
			goto next_block;		/* already all-ones */

		if (!cur && full_cover) {
			vol->fsck_alloc_bitmap[idx] = FB_ONES;
			goto next_block;
		}

		buf = ntfs_fsck_alloc_materialize(vol, idx);
		if (!buf)
			return -ENOMEM;

		for (i = 0; i < rel_length; i++) {
			if (!ntfs_bit_get_and_set(buf, rel_slcn + i, 1))
				vol->fsck_alloc_setcnt[idx]++;
		}
		ntfs_fsck_alloc_try_collapse(vol, idx);

next_block:
		remain_length -= rel_length;
		if (remain_length <= 0)
			break;
		rel_slcn = 0;
	}
	return 0;
}

/*
 * Return the NTFS_BUF_SIZE oracle block covering byte offset @byte_pos of the
 * cluster bitmap. Unlike ntfs_fsck_find_lcnbmp_block() there is no trailing
 * fill_unused: the allocator already bounds its search by nr_clusters.
 */
static u8 *ntfs_fsck_find_alloc_lcnbmp_block(ntfs_volume *vol, s64 byte_pos)
{
	u32 bm_i = FB_ROUND_DOWN(byte_pos);

	if (bm_i >= vol->max_flb_cnt || !vol->fsck_alloc_bitmap[bm_i]) {
		memset(zero_bm, 0, NTFS_BUF_SIZE);
		return zero_bm;
	}
	if (vol->fsck_alloc_bitmap[bm_i] == FB_ONES)
		return ones_bm;

	return vol->fsck_alloc_bitmap[bm_i];
}

/*
 * OR the oracle's occupancy bits for byte range [byte_pos, byte_pos+nbytes)
 * of the cluster bitmap into @dst. The range can straddle two oracle blocks,
 * so walk it a block at a time.
 */
void ntfs_fsck_or_alloc_lcnbmp(ntfs_volume *vol, s64 byte_pos, s64 nbytes, u8 *dst)
{
	s64 done = 0;

	while (done < nbytes) {
		s64 cur = byte_pos + done;
		s64 blk_start = (cur >> NTFS_BUF_SIZE_BITS) << NTFS_BUF_SIZE_BITS;
		s64 off = cur - blk_start;
		s64 chunk = NTFS_BUF_SIZE - off;
		u8 *src;
		s64 i;

		if (chunk > nbytes - done)
			chunk = nbytes - done;

		src = ntfs_fsck_find_alloc_lcnbmp_block(vol, cur);
		for (i = 0; i < chunk; i++)
			dst[done + i] |= src[off + i];

		done += chunk;
	}
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
	u8 *cur;
	BOOL full_cover;
	int i;

	if (length <= 0)
		return -EINVAL;

	remain_length = length;
	for (idx = s_idx; idx <= e_idx; idx++) {
		cur = vol->fsck_lcn_bitmap[idx];

		idx_slcn = idx << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS);
		if (rel_slcn)
			rel_slcn -= idx_slcn;

		rel_length = (1 << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS)) - rel_slcn;
		if (remain_length < rel_length)
			rel_length = remain_length;

		full_cover = (rel_slcn == 0 && rel_length == FB_BLOCK_BITS);

		if (bit) {
			if (!cur && full_cover) {
				/* whole empty block becomes all-ones: no storage */
				vol->fsck_lcn_bitmap[idx] = FB_ONES;
				goto next_block;
			}

			buf = ntfs_fsck_lcnbmp_materialize(vol, idx);
			if (!buf)
				return -ENOMEM;

			for (i = 0; i < rel_length; i++) {
				if (!ntfs_bit_get_and_set(buf, rel_slcn + i, bit))
					vol->fsck_lcn_setcnt[idx]++;
				else
					vol->fsck_lcn_range_dup_count++;
			}
			ntfs_fsck_lcnbmp_try_collapse(vol, idx);
		} else if (cur) {
			/* clear: an already-free (NULL) block needs no work */
			buf = ntfs_fsck_lcnbmp_materialize(vol, idx);
			if (!buf)
				return -ENOMEM;

			for (i = 0; i < rel_length; i++) {
				if (ntfs_bit_get_and_set(buf, rel_slcn + i, bit))
					vol->fsck_lcn_setcnt[idx]--;
			}
		}

next_block:
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
		BOOL full_cover;

		/* calculate first lcn of fsck_lcn_bitmap[idx] */
		idx_slcn = idx << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS);
		if (rel_slcn)
			rel_slcn -= idx_slcn;

		rel_length = (1 << (NTFS_BUF_SIZE_BITS + NTFSCK_BYTE_TO_BITS)) - rel_slcn;
		if (remain_length < rel_length)
			rel_length = remain_length;

		full_cover = (rel_slcn == 0 && rel_length == FB_BLOCK_BITS);

		/*
		 * Fast path: marking a wholly-unset block as fully allocated.
		 * No prior bits were set, so no duplicates are possible and no
		 * literal storage is needed.
		 */
		if (bit && !vol->fsck_lcn_bitmap[idx] && full_cover) {
			vol->fsck_lcn_bitmap[idx] = FB_ONES;
			goto next_block;
		}

		/* clearing an already-free block is a no-op */
		if (!bit && !vol->fsck_lcn_bitmap[idx])
			goto next_block;

		buf = ntfs_fsck_lcnbmp_materialize(vol, idx);
		if (!buf) {
			ntfs_log_error("Can't allocate lcn_bitmap buffer\n");
			return dup_rl;
		}

		for (i = 0; i < rel_length; i++) {
			if (!ntfs_bit_get_and_set(buf, rel_slcn + i, bit)) {
				if (bit)
					vol->fsck_lcn_setcnt[idx]++;
				continue;
			}

			if (!bit) {
				vol->fsck_lcn_setcnt[idx]--;
				continue;
			}

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

		ntfs_fsck_lcnbmp_try_collapse(vol, idx);

next_block:
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

	/* Read-only all-ones payload shared by every FB_ONES sentinel block. */
	memset(ones_bm, 0xff, NTFS_BUF_SIZE);

	/* Initialize fsck lcn bitmap buffer array */
	vol->max_flb_cnt = FB_ROUND_DOWN((vol->nr_clusters - 1) >>
			NTFSCK_BYTE_TO_BITS) + 1;
	vol->fsck_lcn_bitmap = (u8 **)ntfs_calloc(sizeof(u8 *) * vol->max_flb_cnt);
	if (!vol->fsck_lcn_bitmap) {
		ntfs_umount(vol, FALSE);
		return NULL;
	}

	/* Per-block set-bit counts, used to collapse full blocks to FB_ONES. */
	vol->fsck_lcn_setcnt = (u32 *)ntfs_calloc(sizeof(u32) * vol->max_flb_cnt);
	if (!vol->fsck_lcn_setcnt) {
		free(vol->fsck_lcn_bitmap);
		ntfs_umount(vol, FALSE);
		return NULL;
	}

	/*
	 * Set-only occupancy oracle, same geometry as the cluster shadow bitmap.
	 * Fed by the pass-1 MFT scan, read by the allocator barrier.
	 */
	vol->fsck_alloc_bitmap = (u8 **)ntfs_calloc(sizeof(u8 *) * vol->max_flb_cnt);
	if (!vol->fsck_alloc_bitmap) {
		free(vol->fsck_lcn_setcnt);
		free(vol->fsck_lcn_bitmap);
		ntfs_umount(vol, FALSE);
		return NULL;
	}
	vol->fsck_alloc_setcnt = (u32 *)ntfs_calloc(sizeof(u32) * vol->max_flb_cnt);
	if (!vol->fsck_alloc_setcnt) {
		free(vol->fsck_alloc_bitmap);
		free(vol->fsck_lcn_setcnt);
		free(vol->fsck_lcn_bitmap);
		ntfs_umount(vol, FALSE);
		return NULL;
	}

	/* Optionally back literal blocks with a disk scratch file (opt-in). */
	ntfs_fsck_scratch_init(vol, getenv("NTFSCK_SCRATCH_DIR"));

	/*
	 * Initialize fsck mft bitmap buffer array. Size it from allocated_size, not
	 * initialized_size: ntfsck grows a truncated $MFT/$DATA back over the
	 * records it hides, and the array must already cover them.
	 */
	vol->max_fmb_cnt = FB_ROUND_DOWN((vol->mft_na->allocated_size >>
				vol->mft_record_size_bits) >> NTFSCK_BYTE_TO_BITS) + 1;
	vol->fsck_mft_bitmap = (u8 **)ntfs_calloc(sizeof(u8 *) * vol->max_fmb_cnt);
	if (!vol->fsck_mft_bitmap) {
		ntfs_fsck_scratch_free(vol);
		free(vol->fsck_alloc_setcnt);
		free(vol->fsck_alloc_bitmap);
		free(vol->fsck_lcn_setcnt);
		free(vol->fsck_lcn_bitmap);
		ntfs_umount(vol, FALSE);
		return NULL;
	}

	vol->option_flags = flags;
	vol->lost_found = 0;

	return vol;
}

void ntfs_fsck_umount(ntfs_volume *vol)
{
	int bm_i;

	/*
	 * Arena-backed literal blocks are slices of the mmap and are released
	 * by ntfs_fsck_scratch_free(); only heap blocks are freed individually.
	 */
	if (!vol->fsck_lcn_arena)
		for (bm_i = 0; bm_i < vol->max_flb_cnt; bm_i++)
			if (vol->fsck_lcn_bitmap[bm_i] &&
					vol->fsck_lcn_bitmap[bm_i] != FB_ONES)
				free(vol->fsck_lcn_bitmap[bm_i]);
	ntfs_fsck_scratch_free(vol);
	free(vol->fsck_lcn_bitmap);
	free(vol->fsck_lcn_setcnt);

	/* Oracle blocks are always heap-backed (no arena). */
	for (bm_i = 0; bm_i < vol->max_flb_cnt; bm_i++)
		if (vol->fsck_alloc_bitmap[bm_i] &&
				vol->fsck_alloc_bitmap[bm_i] != FB_ONES)
			free(vol->fsck_alloc_bitmap[bm_i]);
	free(vol->fsck_alloc_bitmap);
	free(vol->fsck_alloc_setcnt);

	for (bm_i = 0; bm_i < vol->max_fmb_cnt; bm_i++)
		if (vol->fsck_mft_bitmap[bm_i])
			free(vol->fsck_mft_bitmap[bm_i]);
	free(vol->fsck_mft_bitmap);

	ntfs_umount(vol, FALSE);
}
