/* SPDX-License-Identifier : GPL-2.0 */

/**
 * ntfsck - tools for linux-ntfs read/write filesystem.
 *
 * Copyright (c) 2023 LG Electronics Inc.
 * Author(s): Namjae Jeon, JaeHoon Sim
 *
 * This utility will check and fix errors on an NTFS volume.
 *
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
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <layout.h>
#include <bitmap.h>
#include <endians.h>
#include <bootsect.h>
#include <misc.h>
#include <getopt.h>

#include "cluster.h"
#include "utils.h"
#include "list.h"
#include "dir.h"
#include "lcnalloc.h"
#include "fsck.h"

#define RETURN_FS_NO_ERRORS (0)
#define RETURN_FS_ERRORS_CORRECTED (1)
#define RETURN_SYSTEM_NEEDS_REBOOT (2)
#define RETURN_FS_ERRORS_LEFT_UNCORRECTED (4)
#define RETURN_OPERATIONAL_ERROR (8)
#define RETURN_USAGE_OR_SYNTAX_ERROR (16)
#define RETURN_CANCELLED_BY_USER (32)
#define RETURN_FS_NOT_SUPPORT (64)	/* Not defined in fsck man page */
#define RETURN_SHARED_LIBRARY_ERROR (128)

#define FILENAME_LOST_FOUND "lost+found"
#define FILENAME_PREFIX_LOST_FOUND "FSCK_#"
/* 'FSCK_#'(6) + u64 max string(20) + 1(for NULL) */
#define MAX_FILENAME_LEN_LOST_FOUND	(26)

/* todo: command line: (everything is optional)
 *  fsck-frontend options:
 *	-C [fd]	: display progress bar (send it to the file descriptor if specified)
 *	-T	: don't show the title on startup
 *  fsck-checker options:
 *	-a	: auto-repair. no questions. (optional: if marked clean and -f not specified, just check if mounable)
 *	-p	: auto-repair safe. no questions (optional: same)
 *	-n	: only check. no repair.
 *	-r	: interactively repair.
 *	-y	: always yes.
 *	-v	: verbose.
 *	-V	: version.
 *  taken from fsck.ext2
 *	-b sb	: use the superblock from sb. For corrupted volumes. (do we want separete boot/mft options?)
 *	-c	: use badblocks(8) to find bad blocks (R/O mode) and add the findings to $Bad.
 *	-C fd	: write competion info to fd. If 0, print a completion bar.
 *	-d	: debugging output.
 *	-D	: rebalance indices.
 *	-f	: force checking even if marked clean.
 *	-F	: flush buffers before beginning. (for time-benchmarking)
 *	-k	: When used with -c, don't erase previous $Bad items.
 *	-n	: Open fs as readonly. assume always no. (why is it needed if -r is not specified?)
 *	-t	: Print time statistics.
 *  taken from fsck.reiserfs
 *	--rebuild-sb	: try to find $MFT start and rebuild the boot sector.
 *	--rebuild-tree	: scan for items and rebuild the indices that point to them (0x30, $SDS, etc.)
 *	--clean-reserved: zero rezerved fields. (use with care!)
 *	--adjust-size -z: insert a sparse hole if the data_size is larger than the size marked in the runlist.
 *	--logfile file	: report corruptions (unlike other errors) to a file instead of stderr.
 *	--nolog		: don't report corruptions at all.
 *	--quiet -q	: no progress bar.
 *  taken from fsck.msdos
 *	-w	: flush after every write.
 *	- do n passes. (only 2 in fsck.msdos. second should not report errors. Bonus: stop when error list does not change)
 *  taken from fsck.jfs
 *	--omit-journal-reply: self-descriptive (why would someone do that?)
 *	--replay-journal-only: self-descriptive. don't check otherwise.
 *  taken from fsck.xfs
 *	-s	: only serious errors should be reported.
 *	-i ino	: verbose behaviour only for inode ino.
 *	-b bno	: verbose behaviour only for cluster bno.
 *	-L	: zero log.
 *  inspired by others
 *	- don't do cluster accounting.
 *	- don't do mft record accounting.
 *	- don't do file names accounting.
 *	- don't do security_id accounting.
 *	- don't check acl inheritance problems.
 *	- undelete unused mft records. (bonus: different options for 100% salvagable and less)
 *	- error-level-report n: only report errors above this error level
 *	- error-level-repair n: only repair errors below this error level
 *	- don't fail on ntfsclone metadata pruning.
 *  signals:
 *	SIGUSR1	: start displaying progress bar
 *	SIGUSR2	: stop displaying progress bar.
 */

static struct {
	int verbose;
	ntfs_mount_flags flags;
} option;

struct dir {
	struct ntfs_list_head list;
	u64 mft_no;
};

struct ntfsls_dirent {
	ntfs_volume *vol;
};

/* runlist allocated size */
struct rl_size {
	s64 alloc_size;		/* allocated size (include hole length) */
	s64 real_size;		/* data size (real allocated size) */
};

NTFS_LIST_HEAD(ntfs_dirs_list);
NTFS_LIST_HEAD(oc_list_head); /* Orphaned mft records Candidate list */

struct orphan_mft {
	u64 mft_no;
	struct ntfs_list_head oc_list;	/* Orphan Candidate list */
	struct ntfs_list_head ot_list;	/* Orphan Tree list */
} orphan_mft_t;

int parse_count = 1;
s64 clear_mft_cnt;
s64 total_valid_mft;

struct progress_bar prog;
int pb_flags;
u64 total_cnt;
u64 checked_cnt;
u64 orphan_cnt;

#define NTFS_PROGS	"ntfsck"
/**
 * usage
 */
__attribute__((noreturn))
static void usage(int error)
{
	ntfs_log_info("%s v%s\n\n"
		      "Usage: %s [options] device\n"
		      "-a, --repair-auto	auto-repair. no questions\n"
		      "-p,			auto-repair. no questions\n"
		      "-C,			just check volume dirty\n"
		      "-n, --repair-no		just check the consistency and no fix\n"
		      "-q, --quiet		No progress bar\n"
		      "-r, --repair		Repair interactively\n"
		      "-y, --repair-yes		all yes about all question\n"
		      "-v, --verbose		verbose\n"
		      "-V, --version		version\n\n"
		      "NOTE: -a/-p, -C, -n, -r, -y options are mutually exclusive with each other options\n\n"
		      "For example: %s /dev/sda1\n"
		      "For example: %s -C /dev/sda1\n"
		      "For example: %s -a /dev/sda1\n\n",
		      NTFS_PROGS, VERSION, NTFS_PROGS, NTFS_PROGS, NTFS_PROGS, NTFS_PROGS);
	exit(error ? RETURN_USAGE_OR_SYNTAX_ERROR : 0);
}

/**
 * version
 */
__attribute__((noreturn))
static void version(void)
{
	ntfs_log_info("%s v%s\n\n", NTFS_PROGS, VERSION);
	exit(0);
}

static const struct option opts[] = {
	{"repair-auto",		no_argument,		NULL,	'a' },
	{"repair-no",		no_argument,		NULL,	'n' },
	{"repair",		no_argument,		NULL,	'r' },
	{"repair-yes",		no_argument,		NULL,	'y' },
	{"quiet",		no_argument,		NULL,	'q' },
	{"verbose",		no_argument,		NULL,	'v' },
	{"version",		no_argument,		NULL,	'V' },
	{NULL,			0,			NULL,	 0  }
};

static FILE_NAME_ATTR *ntfsck_find_file_name_attr(ntfs_inode *ni,
		FILE_NAME_ATTR *ie_fn, ntfs_attr_search_ctx *actx);
static int ntfsck_check_directory(ntfs_inode *ni);
static int ntfsck_check_file(ntfs_inode *ni);
static int ntfsck_check_runlist(ntfs_attr *na, u8 set_bit, struct rl_size *rls, BOOL *need_fix);
static int ntfsck_check_inode(ntfs_inode *ni, INDEX_ENTRY *ie,
		ntfs_index_context *ictx);
static int ntfsck_check_file_name_attr(ntfs_inode *ni, FILE_NAME_ATTR *ie_fn,
		ntfs_index_context *ictx);
static int32_t ntfsck_check_file_type(ntfs_inode *ni, ntfs_index_context *ictx,
		FILE_NAME_ATTR *ie_fn);
static int ntfsck_initialize_index_attr(ntfs_inode *ni);
static int ntfsck_set_mft_record_bitmap(ntfs_inode *ni, BOOL ondisk_mft_bmp_set);
static int ntfsck_check_attr_list(ntfs_inode *ni);
static inline BOOL ntfsck_opened_ni_vol(s64 mft_num);
static ntfs_inode *ntfsck_get_opened_ni_vol(ntfs_volume *vol, s64 mft_num);
static int ntfsck_check_inode_non_resident(ntfs_inode *ni, int set_bit);
static void ntfsck_check_mft_records(ntfs_volume *vol);
static void ntfsck_free_mft_records(ntfs_volume *vol, ntfs_inode *ni);
static void ntfsck_check_mft_record_unused(ntfs_volume *vol, s64 mft_num);
static void ntfsck_delete_orphaned_mft(ntfs_volume *vol, u64 mft_no);
static int ntfsck_update_runlist(ntfs_attr *na, s64 new_size, ntfs_attr_search_ctx *actx);

#define ntfsck_delete_mft	ntfsck_delete_orphaned_mft

static ntfs_inode *ntfsck_open_inode(ntfs_volume *vol, u64 mft_no)
{
	ntfs_inode *ni;

	ni = ntfsck_get_opened_ni_vol(vol, mft_no);
	if (!ni)
		ni = ntfs_inode_open(vol, mft_no);
	return ni;
}

static int ntfsck_close_inode(ntfs_inode *ni)
{
	u64 mft_no;

	mft_no = ni->mft_no;

	if (ntfsck_opened_ni_vol(mft_no) == TRUE)
		return STATUS_OK;

	if (ntfs_inode_close(ni)) {
		ntfs_log_perror("Failed to close inode(%"PRIu64")\n", mft_no);
		return STATUS_ERROR;
	}

	return STATUS_OK;
}

static int ntfsck_close_inode_in_dir(ntfs_inode *ni, ntfs_inode *dir_ni)
{
	int res = 0;

	res = ntfs_inode_sync_in_dir(ni, dir_ni);
	if (res) {
		ntfs_log_perror("%s failed\n", __func__);
		if (errno != EIO)
			errno = EBUSY;
	} else
		res = ntfsck_close_inode(ni);
	return res;
}

/* update lcn bitmap to disk, not set in fsck lcn bitmap */
static int ntfsck_update_lcn_bitmap(ntfs_inode *ni)
{
	ntfs_attr_search_ctx *actx;

	actx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!actx)
		return -ENOMEM;

	while (!ntfs_attrs_walk(actx)) {
		runlist *rl;
		runlist *part_rl;
		int i = 0;

		if (!actx->attr->non_resident)
			continue;

		rl = ntfs_decompress_cluster_run(ni->vol, actx->attr, NULL, &part_rl);
		if (!rl) {
			ntfs_log_error("Failed to decompress runlist(mft_no:%"PRIu64", type:0x%x). "
					"Leaving inconsistent metadata.\n",
					ni->mft_no, actx->attr->type);
			continue;
		}

		while (rl[i].length) {
			/*
			 * it's need to set bitmap temporarily,
			 * before check and alloc cluster to avoid
			 * cluster duplication in ntfsck
			 */
			if (rl[i].lcn > (LCN)LCN_HOLE)
				ntfs_bitmap_set_run(ni->vol->lcnbmp_na, rl[i].lcn, rl[i].length);
			++i;
		}

		free(rl);
	}

	ntfs_attr_put_search_ctx(actx);

	return 0;
}

static void ntfsck_clear_attr_lcnbmp(ntfs_attr *na)
{
	ntfs_attr_map_whole_runlist(na);
	ntfsck_check_runlist(na, 0, NULL, NULL);
}

/*
 * check runlist size and set/clear bitmap of runlist.
 * Set or clear bit until encountering lcn whose value is less than LCN_HOLE,
 * Clear bit for invalid lcn.
 *
 * @ni : MFT entry inode
 * @rl : runlist to check
 * @set_bit : bit value for set/clear
 * @rls : structure for runlist length, it contains allocated size and
 *	  real allocated size. it may be NULL, don't return calculated size.
 */
static int ntfsck_check_runlist(ntfs_attr *na, u8 set_bit, struct rl_size *rls, BOOL *need_fix)
{
	ntfs_volume *vol;
	ntfs_inode *ni;
	runlist *rl;
	runlist *dup_rl = NULL;
	s64 rl_alloc_size = 0;	/* rl allocated size (including HOLE length) */
	s64 rl_data_size = 0;	/* rl data size (real allocated size) */
	s64 rsize;		/* a cluster run size */
	int i = 0;
	problem_context_t pctx = {0, };

	if (!na || !na->ni || !na->rl)
		return STATUS_ERROR;

	ni = na->ni;
	rl = na->rl;

	vol = ni->vol;

	ntfs_init_problem_ctx(&pctx, ni, na, NULL, NULL, ni->mrec, NULL, NULL);

	while (rl && rl[i].length) {
		if (rl[i].lcn > LCN_HOLE) {
			ntfs_log_trace("%s cluster run of mft entry(%"PRIu64") in memory : "
					"vcn(%"PRId64"), lcn(%"PRId64"), length(%"PRId64")\n",
					set_bit ? "Set" : "Clear",
					ni->mft_no, rl[i].vcn, rl[i].lcn,
					rl[i].length);

			dup_rl = ntfs_fsck_check_and_set_lcnbmp(vol, na, i, set_bit, dup_rl);

			/* Do not clear bitmap on disk, it may trigger cluster duplication */

			rsize = rl[i].length << vol->cluster_size_bits;
			rl_data_size += rsize;
			rl_alloc_size += rsize;
		} else if (rl[i].lcn == LCN_HOLE) {
			rsize = rl[i].length << vol->cluster_size_bits;
			rl_alloc_size += rsize;
		} else {
			rl[i].lcn = LCN_ENOENT;
			rl[i].length = 0;
			break;
		}

		i++;
	}

	if (rls) {
		rls->alloc_size = rl_alloc_size;
		rls->real_size = rl_data_size;
	}

	if (dup_rl) {
		/* Found cluster duplication */
		if (ntfs_fix_problem(vol, PR_CLUSTER_DUPLICATION_FOUND, &pctx)) {
			/*
			 * fix cluster duplication in ntfs_fsck_repair_cluster_dup(),
			 * but it is applied to disk in caller side.
			 */
			ntfs_log_debug("dup_rl: duplicated runlists\n");
			ntfs_debug_runlist_dump(dup_rl);
			ntfs_fsck_repair_cluster_dup(na, dup_rl);

#ifdef DEBUG
			ntfs_log_info("Resolve cluster duplication of inode(%"
					PRIu64":%d)\n",
					ni->mft_no, na->type);
			ntfs_log_info("   cluster no : length \n");
			for (i = 0; dup_rl[i].length; i++) {
				ntfs_log_info("   (%"PRIu64": %"PRIu64")\n",
						dup_rl[i].lcn, dup_rl[i].length);
			}
#endif
		}

		if (need_fix)
			*need_fix = TRUE;
		ntfs_free(dup_rl);
	}

	return STATUS_OK;
}

/*
 * do not call ntfs_inode_close() after this function called,
 * because ntfs_inode_close() is called in ntfs_mft_record_free().
 * */
static void ntfsck_free_mft_records(ntfs_volume *vol, ntfs_inode *ni)
{
	ntfs_inode *free_inode;
	u64 free_mftno;

	if (utils_is_metadata(ni) == 1) {
		ntfs_log_info("Try to free system file(%"PRIu64")\n",
				ni->mft_no);
		return;
	}

	ntfs_inode_attach_all_extents(ni);
	while (ni->nr_extents) {
		free_inode = *(ni->extent_nis);
		free_mftno = free_inode->mft_no;

		if (ntfs_mft_record_free(vol, free_inode))
			ntfs_log_error("Failed to free extent MFT record(%"PRIu64":%"PRIu64"). "
					"Leaving inconsistent metadata.\n",
					free_mftno, ni->mft_no);
		else
			ntfs_fsck_mftbmp_clear(vol, free_mftno);
	}

	free_mftno = ni->mft_no;
	if (ntfs_mft_record_free(vol, ni))
		ntfs_log_error("Failed to free MFT record(%"PRIu64"). "
				"Leaving inconsistent metadata. Run chkdsk.\n",
				ni->mft_no);
	else
		ntfs_fsck_mftbmp_clear(vol, free_mftno);
}

/* only called from repairing orphaned file in auto fsck mode */
static int ntfsck_find_and_check_index(ntfs_inode *parent_ni, ntfs_inode *ni,
		FILE_NAME_ATTR *fn, BOOL check_flag)
{
	ntfs_volume *vol;
	ntfs_index_context *ictx;

	if (!parent_ni || !ni || !fn)
		return STATUS_ERROR;

	ictx = ntfs_index_ctx_get(parent_ni, NTFS_INDEX_I30, 4);
	if (!ictx) {
		ntfs_log_perror("Failed to get index ctx, inode(%"PRIu64") "
				"for repairing orphan inode", parent_ni->mft_no);
		return STATUS_ERROR;
	}

	/*
	 * ntfs_index_lookup() just compare file name,
	 * not whole $FILE_NAME_ATTR
	 */
	if (!ntfs_index_lookup(fn, sizeof(FILE_NAME_ATTR), ictx)) {
		u64 mft_no = 0;

		mft_no = le64_to_cpu(ictx->entry->indexed_file);
		if ((MSEQNO_LE(ictx->entry->indexed_file) !=
					le16_to_cpu(ni->mrec->sequence_number)) ||
				(MREF(mft_no) != ni->mft_no)) {
			/* found index and orphaned inode is different */
			ntfs_log_error("mft number of inode(%"PRIu64") and parent index(%"PRIu64") "
					"are different\n", MREF(mft_no), ni->mft_no);
			ntfs_index_ctx_put(ictx);
			return STATUS_ERROR;
		}

		/* If check_flag set FALSE, when found $FN in parent index, return error */
		if (check_flag == FALSE) {
			ntfs_log_error("Index already exist in parent(%"PRIu64"), "
					"inode(%"PRIu64")\n",
					parent_ni->mft_no, ni->mft_no);
			errno = EEXIST;
			ntfs_index_ctx_put(ictx);
			return STATUS_ERROR;
		}

		/* If check_flags set TRUE, check inode of founded index */
		vol = ni->vol;
		if (ntfs_fsck_mftbmp_get(vol, ni->mft_no)) {
			/* Check file type */
			if (ntfsck_check_file_type(ni, ictx, fn) < 0) {
				ntfs_log_debug("failed to check file type(%"PRIu64")\n",
						ni->mft_no);
				ntfs_index_ctx_put(ictx);
				return STATUS_ERROR;
			}

			/* check $FILE_NAME */
			if (ntfsck_check_file_name_attr(ni, fn, ictx) < 0) {
				ntfs_log_debug("failed to check file name attribute(%"PRIu64")\n",
						ni->mft_no);
				ntfs_index_ctx_put(ictx);
				return STATUS_ERROR;
			}
		} else {
			if (ntfsck_check_inode(ni, ictx->entry, ictx)) {
				/* Inode check failed, remove index and inode */
				ntfs_log_error("Failed to check inode(%"PRId64") "
						"for repairing orphan inode\n", ni->mft_no);

				if (ntfs_index_rm(ictx)) {
					ntfs_log_error("Failed to remove index entry of inode(%"PRId64")\n",
							ni->mft_no);
					ntfs_index_ctx_put(ictx);
					return STATUS_ERROR;
				}
				ntfs_inode_mark_dirty(ictx->ni);
				ntfs_index_ctx_put(ictx);
				return STATUS_ERROR;
			}
		}
	} else {
		ntfs_index_ctx_put(ictx);
		return STATUS_NOT_FOUND;
	}

	ntfs_index_ctx_put(ictx);
	return STATUS_OK;
}

static int ntfsck_add_inode_to_parent(ntfs_volume *vol, ntfs_inode *parent_ni,
		ntfs_inode *ni, FILE_NAME_ATTR *fn, ntfs_attr_search_ctx *ctx)
{
	int err = STATUS_OK;
	int ret = STATUS_ERROR;
	FILE_NAME_ATTR *tfn;
	int tfn_len;

	ret = ntfsck_find_and_check_index(parent_ni, ni, fn, FALSE);
	if (ret == STATUS_OK) { /* index already exist in parent inode */
		return STATUS_OK;
	} else if (ret == STATUS_ERROR) {
		err = -EIO;
		return STATUS_ERROR;
	}

	tfn_len = sizeof(FILE_NAME_ATTR) + fn->file_name_length * sizeof(ntfschar);
	tfn = ntfs_calloc(tfn_len);
	if (!tfn) {
		err = errno;
		return STATUS_ERROR;
	}

	/* Not found index for $FN */

	memcpy(tfn, fn, tfn_len);
	if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
		ntfsck_initialize_index_attr(ni);

		tfn->allocated_size = 0;
		tfn->data_size = 0;
		ni->allocated_size = 0;
		ni->data_size = 0;
	}

	tfn->parent_directory = MK_LE_MREF(parent_ni->mft_no,
			le16_to_cpu(parent_ni->mrec->sequence_number));

	/* Add index for orphaned inode */
	err = ntfs_index_add_filename(parent_ni, tfn, MK_MREF(ni->mft_no,
				le16_to_cpu(ni->mrec->sequence_number)));
	if (err) {
		ntfs_log_error("Failed to add index(%"PRIu64") to parent(%"PRIu64") "
				"err(%d)\n", ni->mft_no, parent_ni->mft_no, err);
		err = -EIO;
		free(tfn);
		/* if parent_ni != lost+found, then add inode to lostfound */
		return STATUS_ERROR;
	}

	/*
	 * ntfs_index_add_filename() may allocate mft record internally.
	 * So, check all mft record related with parent inode,
	 * and set mft bitmap of ntfsck.
	 */
	if (parent_ni->attr_list) {
		if (ntfsck_check_attr_list(parent_ni)) {
			free(tfn);
			return STATUS_ERROR;
		}

		if (ntfs_inode_attach_all_extents(parent_ni)) {
			free(tfn);
			return STATUS_ERROR;
		}
	}

	if (!ntfs_fsck_mftbmp_get(vol, parent_ni->mft_no)) {
		ntfs_log_debug("parent(%"PRIu64") of orphaned inode(%"PRIu64") mft bitmap not set\n",
				parent_ni->mft_no, ni->mft_no);
	}

	ntfsck_set_mft_record_bitmap(parent_ni, TRUE);
	ntfs_inode_mark_dirty(parent_ni);

	/* check again after adding $FN to index */
	ret = ntfsck_find_and_check_index(parent_ni, ni, tfn, TRUE);
	if (ret != STATUS_OK) {
		err = -EIO;
		free(tfn);
		return STATUS_ERROR;
	}
	free(tfn);

	NInoFileNameSetDirty(ctx->ntfs_ino);
	ntfs_inode_mark_dirty(ctx->ntfs_ino);
	ntfs_inode_mark_dirty(ni);

	ntfsck_set_mft_record_bitmap(ni, TRUE);

	return STATUS_OK;
}

static int ntfsck_add_inode_to_lostfound(ntfs_inode *ni, FILE_NAME_ATTR *fn,
		ntfs_attr_search_ctx *ctx)
{
	FILE_NAME_ATTR *new_fn = NULL;
	ntfs_volume *vol;
	ntfs_inode *lost_found = NULL;
	ntfschar *ucs_name = (ntfschar *)NULL;
	int ucs_namelen;
	int fn_len;
	int ret = STATUS_ERROR;
	char filename[MAX_FILENAME_LEN_LOST_FOUND] = {0, };

	if (!ni) {
		ntfs_log_error("inode point is NULL\n");
		return ret;
	}

	vol = ni->vol;
	lost_found = ntfsck_open_inode(vol, vol->lost_found);
	if (!lost_found) {
		ntfs_log_error("Can't open lost+found directory\n");
		return ret;
	}

	/* check before rename orphaned file */
	ret = ntfsck_find_and_check_index(lost_found, ni, fn, FALSE);
	if (ret == STATUS_ERROR) {
		if (errno == EEXIST) {
			goto rename_fn;
		} else {
			ntfs_log_error("Failed to check inode(%"PRIu64")"
					"to add to lost+found\n", ni->mft_no);
			goto err_out;
		}
	} else if (ret != STATUS_NOT_FOUND) {
		ntfs_log_error("error find_and_check_inode():%"PRIu64"\n", ni->mft_no);
		goto err_out;
	}

	fn->parent_directory = MK_LE_MREF(lost_found->mft_no,
			le16_to_cpu(lost_found->mrec->sequence_number));
add_to_parent:
	ret = ntfsck_add_inode_to_parent(vol, lost_found, ni, fn, ctx);

err_out:
	if (ucs_name)
		free(ucs_name);
	if (new_fn)
		ntfs_free(new_fn);
	if (lost_found)
		ntfsck_close_inode(lost_found);
	return ret;

rename_fn:
	/* rename 'FSCK_#' + 'mft_no' */
	snprintf(filename, MAX_FILENAME_LEN_LOST_FOUND, "%s%"PRIu64"",
			FILENAME_PREFIX_LOST_FOUND, ni->mft_no);
	ucs_namelen = ntfs_mbstoucs(filename, &ucs_name);
	if (ucs_namelen <= 0) {
		ntfs_log_error("ntfs_mbstoucs failed, ucs_namelen : %d\n",
				ucs_namelen);
		goto err_out;
	}

	fn_len = sizeof(FILE_NAME_ATTR) + ucs_namelen * sizeof(ntfschar);
	new_fn = ntfs_calloc(fn_len);
	if (!new_fn)
		goto err_out;

	/* parent_directory over-write in ntfsck_add_inode_to_parent() */
	memcpy(new_fn, fn, sizeof(FILE_NAME_ATTR));
	memcpy(new_fn->file_name, ucs_name, ucs_namelen * sizeof(ntfschar));
	new_fn->file_name_length = ucs_namelen;
	new_fn->parent_directory = MK_LE_MREF(lost_found->mft_no,
			le16_to_cpu(lost_found->mrec->sequence_number));

	ntfs_attr_reinit_search_ctx(ctx);
	fn = ntfsck_find_file_name_attr(ni, fn, ctx);

	if (ntfs_attr_record_rm(ctx)) {
		ntfs_log_error("Failed to remove $FN(%"PRIu64")\n", ni->mft_no);
		goto err_out;
	}

	ntfs_attr_reinit_search_ctx(ctx);

	/* Add FILE_NAME attribute to inode. */
	if (ntfs_attr_add(ni, AT_FILE_NAME, AT_UNNAMED, 0, (u8 *)new_fn, fn_len)) {
		ntfs_log_error("Failed to add $FN(%"PRIu64")\n", ni->mft_no);
		goto err_out;
	}

	ntfs_attr_reinit_search_ctx(ctx);
	fn = ntfsck_find_file_name_attr(ni, new_fn, ctx);
	if (!fn) {
		/* $FILE_NAME lookup failed */
		ntfs_log_error("Failed to lookup $FILE_NAME, Remove $FN of inode(%"PRIu64")\n",
				ni->mft_no);
		goto err_out;
	}

	goto add_to_parent;
}

MFT_RECORD *mrec_temp_buf;
/* delete orphaned mft, call this when inode open failed. */
static void ntfsck_delete_orphaned_mft(ntfs_volume *vol, u64 mft_no)
{
	/* Do not delete system file */
	if (mft_no < FILE_first_user)
		return;

	/*
	 * should be called this function only in
	 * ntfsck_check_mft_record_unused().
	 * So, if mrec_temp_buf memory is NULL, return.
	 */
	if (!mrec_temp_buf)
		return;

	ntfsck_check_mft_record_unused(vol, mft_no);
	ntfs_bitmap_clear_bit(vol->mftbmp_na, mft_no);
	ntfs_fsck_mftbmp_clear(vol, mft_no);
}

/*
 * compare parent mft sequence number and sequence number of inode's $FN
 */
static int ntfsck_cmp_parent_mft_sequence(ntfs_inode *parent_ni, FILE_NAME_ATTR *fn)
{
	u16 mft_pdir_seq;	/* MFT/$FN's parent MFT sequence no */
	u16 pdir_seq;		/* parent's MFT sequence no */

	mft_pdir_seq = MSEQNO_LE(fn->parent_directory);
	pdir_seq = le16_to_cpu(parent_ni->mrec->sequence_number);
	if (mft_pdir_seq > pdir_seq)
		return 1;
	else if (mft_pdir_seq < pdir_seq)
		return -1;

	return 0;
}

static int ntfsck_cmp_parent_mft_number(ntfs_inode *parent_ni, FILE_NAME_ATTR *fn)
{
	u64 parent_mftno;	/* IDX/$FN's parent MFT no */
	u64 mft_pdir;		/* MFT/$FN's parent MFT no */

	parent_mftno = parent_ni->mft_no;
	mft_pdir = MREF_LE(fn->parent_directory);

	if (mft_pdir != parent_mftno)
		return STATUS_ERROR;

	return STATUS_OK;
}

static int ntfsck_check_parent_mft_record(ntfs_inode *parent_ni,
		ntfs_inode *ni, INDEX_ENTRY *ie)
{
	FILE_NAME_ATTR *fn;
	FILE_NAME_ATTR *ie_fn;
	ntfs_attr_search_ctx *ctx;

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		return STATUS_ERROR;

	ie_fn = (FILE_NAME_ATTR *)&ie->key;

	fn = ntfsck_find_file_name_attr(ni, ie_fn, ctx);
	if (!fn) {
		ntfs_log_error("Failed to find filename in inode(%"PRIu64")\n",
				ni->mft_no);
		ntfs_attr_put_search_ctx(ctx);
		return STATUS_ERROR;
	}

	if (ntfsck_cmp_parent_mft_number(parent_ni, fn)) {
		ntfs_log_error("MFT number of parent(%"PRIu64")"
				"and $FN of inode(%"PRIu64") is not same\n",
				parent_ni->mft_no, MREF_LE(fn->parent_directory));
		ntfs_attr_put_search_ctx(ctx);
		return STATUS_ERROR;
	}

	if (ntfsck_cmp_parent_mft_sequence(parent_ni, fn)) {
		ntfs_log_error("Seuqnece number of parent(%"PRIu64")"
				"and parent directory in $FN of inode(%"PRIu64") is not same\n",
				parent_ni->mft_no, MREF_LE(fn->parent_directory));
		ntfs_attr_put_search_ctx(ctx);
		return STATUS_ERROR;
	}

	ntfs_attr_put_search_ctx(ctx);
	return STATUS_OK;
}

/*
 * check indexed_file of index entry and mft number and sequence of inode
 * and also check parent mft number and sequence in $FN
 */
static int ntfsck_check_inode_fields(ntfs_inode *parent_ni,
		ntfs_inode *ni, INDEX_ENTRY *ie)
{
	u16 ni_seq;		/* ni's MFT sequence no */
	u16 idx_seq;		/* index entry's MFT sequence no */

	if (!ni || !parent_ni || !ie)
		return STATUS_ERROR;

	if (le16_to_cpu(ni->mrec->link_count) == 0) {
		ntfs_log_error("Link count of inode(%"PRIu64") is zero\n",
				ni->mft_no);
		return STATUS_ERROR;
	}

	if (MREF_LE(ni->mrec->base_mft_record) != 0) {
		ntfs_log_error("Inode(%"PRIu64") is not base inode\n",
				ni->mft_no);
		return STATUS_ERROR;
	}

	/* check indexed_file of index entry and inode mft record and sequence */
	idx_seq = MSEQNO_LE(ie->indexed_file);
	ni_seq = le16_to_cpu(ni->mrec->sequence_number);
	if (ni_seq != idx_seq) {
		ntfs_log_error("Mismatch sequence number of index and inode(%"PRIu64")\n",
				ni->mft_no);
		return STATUS_ERROR;
	}

	/* check parent mft record of $FN and parent mft record and sequence */
	if (ntfsck_check_parent_mft_record(parent_ni, ni, ie))
		return STATUS_ERROR;

	return STATUS_OK;
}

static int ntfsck_remove_filename(ntfs_inode *ni, FILE_NAME_ATTR *fn)
{
	int ret = STATUS_OK;
	int nlink = 0;

	ret = ntfs_attr_remove(ni, AT_FILE_NAME, fn->file_name, fn->file_name_length);
	if (ret)
		return STATUS_ERROR;

	nlink = le16_to_cpu(ni->mrec->link_count);

	ni->mrec->link_count = cpu_to_le16(--nlink);
	ntfs_inode_mark_dirty(ni);

	return STATUS_OK;
}

/* get entry of orphan mft candidate list */
static struct orphan_mft *ntfsck_get_oc_list_entry(struct ntfs_list_head *head, u64 mft_no)
{
	struct orphan_mft *entry = NULL;
	struct ntfs_list_head *pos;

	ntfs_list_for_each(pos, head) {
		entry = ntfs_list_entry(pos, struct orphan_mft, oc_list);
		if (entry->mft_no == mft_no)
			return entry;
	}
	return NULL;
}

static int ntfsck_add_index_entry_orphaned_file(ntfs_volume *vol, struct orphan_mft *e)
{
	ntfs_attr_search_ctx *ctx = NULL;
	FILE_NAME_ATTR *fn;
	ntfs_inode *parent_ni = NULL;
	ntfs_inode *ni = NULL;
	u64 parent_no;
	int ret = STATUS_OK;
	int nlink = 0;
	struct orphan_mft *entry;

	NTFS_LIST_HEAD(ot_list_head);

	if (!e)
		return -EINVAL;

	entry = e;
stack_of:
	ntfs_list_del(&entry->oc_list);
	ntfs_list_add(&entry->ot_list, &ot_list_head);

	while (!ntfs_list_empty(&ot_list_head)) {
		entry = ntfs_list_entry(ot_list_head.next, struct orphan_mft, ot_list);

		ni = ntfsck_open_inode(vol, entry->mft_no);
		if (!ni) {
			ntfs_log_error("Failed to open orphaned inode(%"PRIu64"), check next\n",
					entry->mft_no);
			ntfsck_delete_orphaned_mft(vol, entry->mft_no);
			ret = STATUS_OK;
			goto next_inode;
		}
		nlink = 0;

		ctx = ntfs_attr_get_search_ctx(ni, NULL);
		if (!ctx) {
			ntfs_log_error("Failed to allocate attribute context\n");
			ret = STATUS_OK;
			goto next_inode;
		}

		while (!ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0,
						CASE_SENSITIVE, 0, NULL, 0, ctx)) {
			fn = (FILE_NAME_ATTR *)((u8 *)ctx->attr +
					le16_to_cpu(ctx->attr->value_offset));

			parent_no = le64_to_cpu(fn->parent_directory);

			/*
			 * when root index is initialized
			 * in ntfsck_validate_index_blocks(),
			 * root inode can be a orphaned inode
			 */
			if (ni->mft_no == FILE_root) {
				ntfs_fsck_mftbmp_set(vol, FILE_root);
				goto next_inode;
			}

			/*
			 * Consider that the parent could be orphaned.
			 */

			if (!ntfs_fsck_mftbmp_get(vol, MREF(parent_no))) {
				struct orphan_mft *p_entry;

				p_entry = ntfsck_get_oc_list_entry(&oc_list_head, MREF(parent_no));
				if (p_entry) {
					/*
					 * Parent is also orphaned file!
					 */

					/* Do not delete ni on orphan list and check parent */
					ntfs_attr_put_search_ctx(ctx);
					ctx = NULL;
					ntfsck_close_inode(ni);
					entry = p_entry;
					goto stack_of;
				}

				ntfs_log_debug("Not found parent inode(%"PRIu64")"
						"of inode(%"PRIu64") in orphaned list\n",
						MREF(parent_no), ni->mft_no);
				goto add_to_lostfound;
			}

			/*
			 * Add orphan inode to parent
			 */
			if (!parent_ni && parent_no != (u64)-1) {
				parent_ni = ntfsck_open_inode(vol, MREF(parent_no));
				if (!parent_ni) {
					ntfs_log_error("Failed to open parent inode(%"PRIu64")\n",
							parent_no);
					/* TODO: make parent inode unused ?? */
					goto add_to_lostfound;
				}

				if (ntfsck_cmp_parent_mft_sequence(parent_ni, fn)) {
					/* do not add inode to parent */
					ntfs_log_debug("Different sequence number of parent(%"PRIu64
							") and inode(%"PRIu64")\n",
							parent_ni->mft_no, ni->mft_no);
					ntfs_attr_record_rm(ctx);
					NInoClearDirty(parent_ni);
					NInoFileNameClearDirty(parent_ni);
					NInoAttrListClearDirty(parent_ni);
					ntfsck_close_inode(parent_ni);
					parent_ni = NULL;
					continue;
				}
			}

			if (parent_ni) {
				ret = ntfsck_add_inode_to_parent(vol, parent_ni, ni, fn, ctx);
				if (!ret) {
					nlink++;
					ntfsck_close_inode(parent_ni);
					parent_ni = NULL;
					continue; /* success adding to parent, go to next $FN */
				}

				ntfs_log_error("Failed to add inode(%"PRIu64") to parent(%"PRIu64")\n",
						ni->mft_no, parent_ni->mft_no);
				NInoClearDirty(parent_ni);
				NInoFileNameClearDirty(parent_ni);
				NInoAttrListClearDirty(parent_ni);
				ntfsck_close_inode(parent_ni);
				parent_ni = NULL;
			}
			/* failed to add inode to parent */
add_to_lostfound:
			/*
			 * Try to add orphaned inode to lostfound,
			 * if failed, delete $FILE_NAME and
			 * zero if nlink is zero.
			 */
			ntfs_log_debug("Try to add inode(%"PRIu64") to %s\n",
					ni->mft_no, FILENAME_LOST_FOUND);
			ret = ntfsck_add_inode_to_lostfound(ni, fn, ctx);
			if (ret) {
				ntfs_log_error("Failed to add inode(%"PRIu64") to %s\n",
						ni->mft_no, FILENAME_LOST_FOUND);
				ntfsck_remove_filename(ni, fn);
				ret = STATUS_OK;
			} else {
				ret = STATUS_OK;
				nlink++;
			}
		} /* while (!ntfs_attr_lookup(AT_FILE_NAME, ... */

		if (nlink == 0) {
			ntfsck_close_inode(ni);
			ni = NULL;
			ntfsck_check_mft_record_unused(vol, entry->mft_no);
			ntfs_fsck_mftbmp_clear(vol, entry->mft_no);
			check_mftrec_in_use(vol, entry->mft_no, 1);
		} else {
			ntfsck_set_mft_record_bitmap(ni, TRUE);  // FALSE is also ok?
			check_mftrec_in_use(vol, ni->mft_no, 1);

			if (nlink != le16_to_cpu(ni->mrec->link_count)) {
				ni->mrec->link_count = cpu_to_le16(nlink);
				ntfs_inode_mark_dirty(ni);
			}
		}

next_inode:
		if (ctx) {
			ntfs_attr_put_search_ctx(ctx);
			ctx = NULL;
		}

		if (ni)
			ntfs_inode_sync_in_dir(ni, parent_ni);

		if (parent_ni) {
			ntfsck_close_inode(parent_ni);
			parent_ni = NULL;
		}

		if (ni) {
			ntfsck_close_inode(ni);
			ni = NULL;
		}
		ntfs_list_del(&entry->ot_list);
		free(entry);
	} /* while (!ntfs_list_empty(&ot_list_head)) */

	return ret;
}

/* return STATUS_OK, mft is extend mft record, else return STATUS_ERROR */
static int ntfsck_check_if_extent_mft_record(ntfs_volume *vol, s64 mft_num)
{
	s64 pos = mft_num * vol->mft_record_size;
	s64 count = vol->sector_size;
	u64 base_mft;

	if (ntfs_attr_pread(vol->mft_na, pos, count, mrec_temp_buf) != count) {
		ntfs_log_perror("Couldn't read $MFT record %lld",
				(long long)mft_num);
		return STATUS_ERROR;
	}

	base_mft = MREF_LE(mrec_temp_buf->base_mft_record);
	if (base_mft == 0)
		return STATUS_ERROR;	/* base mft */

	return STATUS_OK;	/* extent mft */
}

static void ntfsck_check_mft_record_unused(ntfs_volume *vol, s64 mft_num)
{
	u16 seq_no;
	s64 pos = mft_num * vol->mft_record_size;
	s64 count = vol->sector_size;

	if (ntfs_attr_pread(vol->mft_na, pos, count, mrec_temp_buf) != count) {
		ntfs_log_perror("Couldn't read $MFT record %lld",
				(long long)mft_num);
		return;
	}

	if (!ntfs_is_file_record(mrec_temp_buf->magic) ||
	    !(mrec_temp_buf->flags & MFT_RECORD_IN_USE)) {
		ntfs_log_verbose("Record(%"PRId64") unused. Skipping.\n",
				mft_num);
		return;
	}

	ntfs_log_error("Record(%"PRId64") used. "
		       "Mark the mft record as not in use.\n",
		       mft_num);
	mrec_temp_buf->flags &= ~MFT_RECORD_IN_USE;
	seq_no = le16_to_cpu(mrec_temp_buf->sequence_number);
	if (seq_no == 0xffff)
		seq_no = 1;
	else if (seq_no)
		seq_no++;
	mrec_temp_buf->sequence_number = cpu_to_le16(seq_no);
	if (ntfs_attr_pwrite(vol->mft_na, pos, count, mrec_temp_buf) != count) {
		ntfs_log_error("Failed to write mft record(%"PRId64")\n",
				mft_num);
	}
}

static void ntfsck_verify_mft_record(ntfs_volume *vol, s64 mft_num)
{
	ntfs_inode *ni = NULL;
	ntfs_inode *parent_ni = NULL;
	struct orphan_mft *of;
	int is_used;
	ntfs_attr_search_ctx *ctx = NULL;
	FILE_NAME_ATTR *fn;
	u64 parent_no;
	int nlink;
	problem_context_t pctx = {0, };

	pctx.inum = mft_num;

	is_used = check_mftrec_in_use(vol, mft_num, 0);
	if (is_used < 0) {
		ntfs_log_error("Error getting bit value for record %"PRId64".\n",
			mft_num);
		return;
	} else if (!is_used) {
		if (mft_num < FILE_Extend) {
			ntfs_log_error("Record(%"PRId64") unused. Fixing or fail about system files.\n",
					mft_num);
			return;
		}
		return;
	}

	ni = ntfsck_open_inode(vol, mft_num);
	if (!ni) {
		/* check this mft is extend mft or not */
		if (!ntfsck_check_if_extent_mft_record(vol, mft_num)) {
			/* extent mft */
			return;
		}

		if (ntfs_fix_problem(vol, PR_ORPHANED_MFT_OPEN_FAILURE, &pctx)) {
			if (ntfs_bitmap_clear_bit(vol->mftbmp_na, mft_num)) {
				ntfs_log_error("ntfs_bitmap_clear_bit failed, errno : %d\n",
						errno);
				return;
			}
			ntfsck_check_mft_record_unused(vol, mft_num);
			ntfs_fsck_mftbmp_clear(vol, mft_num);
			check_mftrec_in_use(vol, mft_num, 1);
			clear_mft_cnt++;
		}
		return;
	}

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		ntfs_log_error("Failed to allocate attribute context\n");
		ntfsck_close_inode(ni);
		return;
	}

	nlink = 0;
	while (!ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0,
				CASE_SENSITIVE, 0, NULL, 0, ctx)) {
		fn = (FILE_NAME_ATTR *)((u8 *)ctx->attr +
				le16_to_cpu(ctx->attr->value_offset));

		parent_no = le64_to_cpu(fn->parent_directory);
		if (parent_no != (u64)-1) {
			parent_ni = ntfsck_open_inode(vol, MREF(parent_no));
			if (!parent_ni) {
				ntfs_log_error("Failed to open parent inode(%"PRIu64")\n",
						MREF(parent_no));
				continue;
			}

			if (ntfsck_cmp_parent_mft_sequence(parent_ni, fn) < 0) {
				/* do not add inode to parent */
				ntfs_log_debug("Different sequence number of parent(%"PRIu64
						") and inode(%"PRIu64")\n",
						parent_ni->mft_no, ni->mft_no);
				/* FIXME: is it need to call ntfs_fix_problem()? */
				ntfsck_remove_filename(ni, fn);
				ntfsck_close_inode(parent_ni);
				continue;
			}
			ntfsck_close_inode(parent_ni);
		}
		nlink++;
	} /* while (!ntfs_attr_lookup(AT_FILE_NAME, ... */

	if (nlink == 0)
		goto err_check_inode;

	if (ni->attr_list) {
		if (ntfsck_check_attr_list(ni))
			goto err_check_inode;

		if (ntfs_inode_attach_all_extents(ni))
			goto err_check_inode;
	}

	if (ctx) {
		ntfs_attr_put_search_ctx(ctx);
		ctx = NULL;
	}

	/* orphaned inode */
	if (utils_is_metadata(ni) == 1) {
		ntfs_log_info("Metadata %"PRIu64" is found as orphaned file\n",
				ni->mft_no);
		/* system files can be orphaned inode,
		 * because root inode can be initialized in
		 * ntfsck_validate_index_blocks(vol, ictx).
		 * so, also check system files.
		 */
	}

	of = (struct orphan_mft *)calloc(1, sizeof(struct orphan_mft));
	if (!of) {
		ntfs_log_error("orphan_mft malloc failed");
		return;
	}

	of->mft_no = mft_num;
	ntfs_list_add_tail(&of->oc_list, &oc_list_head);
	orphan_cnt++;

	ntfs_log_debug("close inode (%"PRIu64")\n", ni->mft_no);
	ntfsck_close_inode(ni);
	return;

err_check_inode:
	ntfs_attr_put_search_ctx(ctx);
	ntfsck_close_inode(ni);

	if (ntfs_fix_problem(vol, PR_ORPHANED_MFT_CHECK_FAILURE, &pctx))
		ntfsck_check_mft_record_unused(vol, mft_num);

	ntfs_fsck_mftbmp_clear(vol, mft_num);
	check_mftrec_in_use(vol, mft_num, 1);
	clear_mft_cnt++;
	return;
}

#if DEBUG
void ntfsck_debug_print_fn_attr(ntfs_attr_search_ctx *actx,
		FILE_NAME_ATTR *idx_fn, FILE_NAME_ATTR *mft_fn)
{
	STANDARD_INFORMATION *std_info;
	ntfs_time si_ctime;
	ntfs_time si_mtime;
	ntfs_time si_mtime_mft;
	ntfs_time si_atime;
	ntfs_inode *ni;
	BOOL diff = FALSE;

	if (!actx)
		return;

	if (ntfs_attr_lookup(AT_STANDARD_INFORMATION, AT_UNNAMED,
				0, CASE_SENSITIVE, 0, NULL, 0, actx)) {
		/* it's not possible here, because $STD_INFO's already checked
		 * in ntfs_inode_open() */
		return;
	}

	ni = actx->ntfs_ino;

	std_info = (STANDARD_INFORMATION *)((u8 *)actx->attr +
			le16_to_cpu(actx->attr->value_offset));
	si_ctime = std_info->creation_time;
	si_mtime = std_info->last_data_change_time;
	si_mtime_mft = std_info->last_mft_change_time;
	si_atime = std_info->last_access_time;

	if (si_mtime != mft_fn->last_data_change_time ||
			si_mtime_mft != mft_fn->last_mft_change_time) {
		ntfs_log_info("STD TIME != MFT/$FN\n");
		diff = TRUE;
	}

	if (si_mtime != ni->last_data_change_time ||
			si_mtime_mft != ni->last_mft_change_time) {
		ntfs_log_info("STD TIME != INODE\n");
		diff = TRUE;
	}

	if (si_mtime != idx_fn->last_data_change_time ||
			si_mtime_mft != idx_fn->last_mft_change_time) {
		ntfs_log_info("STD TIME != IDX/$FN\n");
		diff = TRUE;
	}

	if (idx_fn->parent_directory != mft_fn->parent_directory) {
		ntfs_log_info("different parent_directory IDX/$FN, MFT/$FN\n");
		diff = TRUE;
	}
	if (idx_fn->allocated_size != mft_fn->allocated_size) {
		ntfs_log_info("different allocated_size IDX/$FN, MFT/$FN\n");
		diff = TRUE;
	}
	if (idx_fn->allocated_size != mft_fn->allocated_size) {
		ntfs_log_info("different allocated_size IDX/$FN, MFT/$FN\n");
		diff = TRUE;
	}
	if (idx_fn->data_size != mft_fn->data_size) {
		ntfs_log_info("different data_size IDX/$FN, MFT/$FN\n");
		diff = TRUE;
	}

	if (idx_fn->reparse_point_tag != mft_fn->reparse_point_tag) {
		ntfs_log_info("different reparse_point IDX/$FN:%x, MFT/$FN:%x\n",
				idx_fn->reparse_point_tag,
				mft_fn->reparse_point_tag);
		diff = TRUE;
	}

	if (diff == FALSE)
		return;

	ntfs_log_info("======== START %"PRIu64"================\n", ni->mft_no);
	ntfs_log_info("inode ctime:%"PRIx64", mtime:%"PRIx64", "
			"mftime:%"PRIx64", atime:%"PRIx64"\n",
			ni->creation_time, ni->last_data_change_time,
			ni->last_mft_change_time, ni->last_access_time);
	ntfs_log_info("std_info ctime:%"PRIx64", mtime:%"PRIx64", "
			"mftime:%"PRIx64", atime:%"PRIx64"\n",
			si_ctime, si_mtime, si_mtime_mft, si_atime);
	ntfs_log_info("mft_fn ctime:%"PRIx64", mtime:%"PRIx64", "
			"mftime:%"PRIx64", atime:%"PRIx64"\n",
			mft_fn->creation_time, mft_fn->last_data_change_time,
			mft_fn->last_mft_change_time, mft_fn->last_access_time);
	ntfs_log_info("idx_fn ctime:%"PRIx64", mtime:%"PRIx64", "
			"mftime:%"PRIx64", atime:%"PRIx64"\n",
			idx_fn->creation_time, idx_fn->last_data_change_time,
			idx_fn->last_mft_change_time, idx_fn->last_access_time);
	ntfs_log_info("======== END =======================\n");

	return;
}
#endif

/*
 * check $FILE_NAME attribute in directory index and same one in MFT entry
 * @ni : MFT entry inode
 * @ie : index entry of file (parent's index)
 * @ictx : index context for lookup, not for ni. It's context of ni's parent
 */
static int ntfsck_check_file_name_attr(ntfs_inode *ni, FILE_NAME_ATTR *ie_fn,
		ntfs_index_context *ictx)
{
	ntfs_volume *vol = ni->vol;
	char *filename = NULL;
	int ret = STATUS_OK;
	BOOL need_fix = FALSE;
	FILE_NAME_ATTR *fn;
	ntfs_attr_search_ctx *actx;
	problem_context_t pctx = {0, };

	u64 idx_pdir;		/* IDX/$FN's parent MFT no */
	u64 mft_pdir;		/* MFT/$FN's parent MFT no */
	u16 idx_pdir_seq;	/* IDX/$FN's parent MFT sequence no */
	u16 mft_pdir_seq;	/* MFT/$FN's parent MFT sequence no */

	actx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!actx)
		return STATUS_ERROR;

	fn = ntfsck_find_file_name_attr(ni, ie_fn, actx);
	if (!fn) {
		/* NOT FOUND MFT/$FN */
		filename = ntfs_attr_name_get(ie_fn->file_name,
					      ie_fn->file_name_length);
		ntfs_log_error("Filename(%s) in index entry of parent(%"PRIu64") "
				"was not found in inode(%"PRIu64")\n",
				filename, ictx->ni->mft_no, ni->mft_no);
		ret = STATUS_ERROR;
		goto out;
	}

	ntfs_init_problem_ctx(&pctx, ni, NULL, actx, NULL, NULL, NULL, ie_fn);

	idx_pdir = MREF_LE(ie_fn->parent_directory);
	mft_pdir = MREF_LE(fn->parent_directory);
	idx_pdir_seq = MSEQNO_LE(ie_fn->parent_directory);
	mft_pdir_seq = MSEQNO_LE(fn->parent_directory);

#if DEBUG
	ntfsck_debug_print_fn_attr(actx, ie_fn, fn);
#endif

	/* check parent MFT reference */
	if (idx_pdir != mft_pdir ||
		idx_pdir_seq != mft_pdir_seq ||
		mft_pdir != ictx->ni->mft_no) {
			filename = ntfs_attr_name_get(ie_fn->file_name,
						      ie_fn->file_name_length);
			ntfs_log_error("Parent MFT reference is differnt "
					"(IDX/$FN:%"PRIu64"-%u MFT/$FN:%"PRIu64"-%u) "
					"on inode(%"PRIu64", %s), parent(%"PRIu64")\n",
					idx_pdir, idx_pdir_seq, mft_pdir, mft_pdir_seq,
					ni->mft_no, filename, ictx->ni->mft_no);
			ret = STATUS_ERROR;
			goto out;
	}

	/*
	 * Windows chkdsk seems to fix reparse tag of index entry silently.
	 * And don't touch reparse tags of MFT/$FN and $Reparse attribute.
	 */
#ifdef UNUSED
	/* check reparse point */
	if (ni->flags & FILE_ATTR_REPARSE_POINT) {
		ntfs_attr_search_ctx *_ctx = NULL;
		REPARSE_POINT *rpp = NULL;

		_ctx = ntfs_attr_get_search_ctx(ni, NULL);

		if (ntfs_attr_lookup(AT_REPARSE_POINT, AT_UNNAMED, 0,
					CASE_SENSITIVE, 0, NULL, 0, _ctx)) {
			filename = ntfs_attr_name_get(ie_fn->file_name,
						      ie_fn->file_name_length);
			ntfs_log_error("MFT flag set as reparse file, but there's no "
					"MFT/$REPARSE_POINT attribute on inode(%"PRIu64":%s)",
					ni->mft_no, filename);
			ntfs_attr_put_search_ctx(_ctx);
			ret = STATUS_ERROR;
			goto out;
		}

		rpp = (REPARSE_POINT *)((u8 *)_ctx->attr +
				le16_to_cpu(_ctx->attr->value_offset));

		/* Is it worth to modify fn field? */
		if (!(fn->file_attributes & FILE_ATTR_REPARSE_POINT))
			fn->file_attributes |= FILE_ATTR_REPARSE_POINT;

		if (ie_fn->reparse_point_tag != rpp->reparse_tag) {
			filename = ntfs_attr_name_get(ie_fn->file_name,
						      ie_fn->file_name_length);
			pctx->filename = filename;
			fsck_err_found();
			ntfs_print_problem(vol, PR_MFT_REPARSE_TAG_MISMATCH, &pctx);

			ie_fn->reparse_point_tag = rpp->reparse_tag;
			need_fix = TRUE;
			ntfs_attr_put_search_ctx(_ctx);
			goto fix_index;
		}
		ntfs_attr_put_search_ctx(_ctx);
	}
#endif

	/* Does it need to check? */

	/*
	 * mft record flags for directory is already checked
	 * in ntfsck_check_file_type()
	 */
	if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
		if (!(ie_fn->file_attributes & FILE_ATTR_I30_INDEX_PRESENT)) {
			filename = ntfs_attr_name_get(ie_fn->file_name,
						      ie_fn->file_name_length);
			pctx.filename = filename;
			fsck_err_found();
			if (ntfs_fix_problem(vol, PR_MFT_FLAG_MISMATCH, &pctx)) {
				ie_fn->file_attributes |= FILE_ATTR_I30_INDEX_PRESENT;
				fn->file_attributes = ie_fn->file_attributes;
				ntfs_index_entry_mark_dirty(ictx);
				ntfs_inode_mark_dirty(ni);
				NInoFileNameSetDirty(ni);
				fsck_err_fixed();
			}
		}

		if (ie_fn->allocated_size != 0 || ie_fn->data_size != 0 ||
				ni->allocated_size != 0 || ni->data_size != 0) {
			if (!filename)
				filename = ntfs_attr_name_get(ie_fn->file_name,
							      ie_fn->file_name_length);
			pctx.filename = filename;
			fsck_err_found();
			if (ntfs_fix_problem(vol, PR_DIR_NONZERO_SIZE, &pctx)) {
				ni->allocated_size = 0;
				ni->data_size = 0;
				ie_fn->allocated_size = cpu_to_sle64(0);
				fn->allocated_size = ie_fn->allocated_size;
				ie_fn->data_size = cpu_to_sle64(0);
				fn->data_size = ie_fn->data_size;
				ntfs_index_entry_mark_dirty(ictx);
				ntfs_inode_mark_dirty(ni);
				NInoFileNameSetDirty(ni);
				fsck_err_fixed();
			}
		}

		/* if inode is directory, then skip size fields check */
		goto out;
	}

	/*
	 * Already applied proepr value to inode field.
	 * ni->allocated_size : $DATA->allocated_size or $DATA->compressed_size
	 */

	/* check $FN size fields */
	if (ni->allocated_size != sle64_to_cpu(ie_fn->allocated_size)) {
		filename = ntfs_attr_name_get(ie_fn->file_name,
					      ie_fn->file_name_length);
		pctx.filename = filename;
		fsck_err_found();
		ntfs_print_problem(vol, PR_MFT_ALLOCATED_SIZE_MISMATCH, &pctx);

		need_fix = TRUE;
		goto fix_index;
	}
	/*
	 * Is it need to check MFT/$FN's data size?
	 * It looks like that Windows does not check MFT/$FN's data size.
	 */
	if (ni->data_size != sle64_to_cpu(ie_fn->data_size)) {
		filename = ntfs_attr_name_get(ie_fn->file_name,
					      ie_fn->file_name_length);
		pctx.filename = filename;
		fsck_err_found();
		ntfs_print_problem(vol, PR_MFT_DATA_SIZE_MISMATCH, &pctx);

		need_fix = TRUE;
		goto fix_index;
	}

	/* set NI_FileNameDirty in ni->state to sync
	 * $FILE_NAME attrib when ntfs_inode_close() is called */
fix_index:
	if (need_fix) {
		if (ntfs_ask_repair(vol)) {
			ntfs_inode_mark_dirty(ni);
			NInoFileNameSetDirty(ni);

			ie_fn->allocated_size = cpu_to_sle64(ni->allocated_size);
			ie_fn->data_size = cpu_to_sle64(ni->data_size);

			ntfs_index_entry_mark_dirty(ictx);
			fsck_err_fixed();
		}
	}

#if DEBUG
	ntfsck_debug_print_fn_attr(actx, ie_fn, fn);
#endif

out:
	if (filename)
		ntfs_attr_name_free(&filename);
	ntfs_attr_put_search_ctx(actx);
	return ret;

}

/*
 * Find MFT/$FILE_NAME attribute that matches index entry's key.
 * Return 'fn' if found, else return NULL.
 *
 * 'fn' points somewhere in 'actx->attr', so 'fn' is only valid
 * during 'actx' variable is valid. (ie. before calling
 * ntfs_attr_put_search_ctx() * or ntfs_attr_reinit_search_ctx()
 * outside of this function)
 */
static FILE_NAME_ATTR *ntfsck_find_file_name_attr(ntfs_inode *ni,
		FILE_NAME_ATTR *ie_fn, ntfs_attr_search_ctx *actx)
{
	FILE_NAME_ATTR *fn = NULL;
	ATTR_RECORD *attr;
	ntfs_volume *vol = ni->vol;
	int ret;

#ifdef DEBUG
	char *filename;
	char *idx_filename;

	idx_filename = ntfs_attr_name_get(ie_fn->file_name, ie_fn->file_name_length);
	ntfs_log_trace("Find '%s' matched $FILE_NAME attribute\n", idx_filename);
	ntfs_attr_name_free(&idx_filename);
#endif

	while ((ret = ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, CASE_SENSITIVE,
					0, NULL, 0, actx)) == 0) {
		IGNORE_CASE_BOOL case_sensitive = IGNORE_CASE;

		attr = actx->attr;
		fn = (FILE_NAME_ATTR *)((u8 *)attr +
				le16_to_cpu(attr->value_offset));
#ifdef DEBUG
		filename = ntfs_attr_name_get(fn->file_name, fn->file_name_length);
		ntfs_log_trace("  name:'%s' type:%d\n", filename, fn->file_name_type);
		ntfs_attr_name_free(&filename);
#endif

		/* Ignore hard links from other directories */
		if (fn->parent_directory != ie_fn->parent_directory) {
			ntfs_log_debug("MFT record numbers don't match "
					"(%llu != %llu)\n",
					(unsigned long long)MREF_LE(ie_fn->parent_directory),
					(unsigned long long)MREF_LE(fn->parent_directory));
			continue;
		}

		if (fn->file_name_type == FILE_NAME_POSIX)
			case_sensitive = CASE_SENSITIVE;

		if (!ntfs_names_are_equal(fn->file_name, fn->file_name_length,
					ie_fn->file_name, ie_fn->file_name_length,
					case_sensitive, vol->upcase,
					vol->upcase_len)) {
			continue;
		}

		/* Found $FILE_NAME */
		return fn;
	}

	return NULL;
}

/*
 * check file is normal file or directory.
 * and check flags related it.
 *
 * return index entry's flag if checked normally.
 * else return STATUS_ERROR.
 *
 */
static int32_t ntfsck_check_file_type(ntfs_inode *ni, ntfs_index_context *ictx,
		FILE_NAME_ATTR *ie_fn)
{
	FILE_ATTR_FLAGS ie_flags; /* index key $FILE_NAME flags */
	ntfs_volume *vol = ni->vol;
	BOOL check_ir = FALSE;	/* flag about checking index root */
	problem_context_t pctx = {0, };

	ntfs_init_problem_ctx(&pctx, ni, NULL, NULL, ictx, NULL, NULL, ie_fn);
	ie_flags = ie_fn->file_attributes;

	if (ie_flags & FILE_ATTR_VIEW_INDEX_PRESENT)
		return ie_flags;

	if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
		/* mft record flags is set to directory */
		if (ntfs_attr_exist(ni, AT_INDEX_ROOT, NTFS_INDEX_I30, 4)) {
			if (!(ie_flags & FILE_ATTR_I30_INDEX_PRESENT)) {
				ie_flags |= FILE_ATTR_I30_INDEX_PRESENT;
				ie_fn->file_attributes |= FILE_ATTR_I30_INDEX_PRESENT;

				fsck_err_found();
				if (ntfs_fix_problem(vol, PR_DIR_FLAG_MISMATCH_IDX_FN, &pctx)) {
					ntfs_index_entry_mark_dirty(ictx);
					fsck_err_fixed();
				}
			}
		} else {
#ifndef UNUSED
			/* return if flags set directory, but not exist $IR */
			return STATUS_ERROR;
#else
			if (errno != ENOENT)
				return STATUS_ERROR;

			/* not found $INDEX_ROOT, check failed */
			ie_flags &= ~FILE_ATTR_I30_INDEX_PRESENT;
			ni->mrec->flags &= ~MFT_RECORD_IS_DIRECTORY;

			fsck_err_found();
			if (ntfs_fix_problem(vol, PR_DIR_FLAG_MISMATCH_MFT_FN, &pctx)) {
				ntfs_inode_mark_dirty(ni);
				fsck_err_fixed();
			}

			if (ie_flags & FILE_ATTR_I30_INDEX_PRESENT) {
				ie_flags &= ~FILE_ATTR_I30_INDEX_PRESENT;
				ie_fn->file_attributes &= ~FILE_ATTR_I30_INDEX_PRESENT;

				fsck_err_found();
				if (ntfs_fix_problem(vol, PR_DIR_IR_NOT_EXIST, &pctx)) {
					ntfs_index_entry_mark_dirty(ictx);
					fsck_err_fixed();
				}
			}
#endif
		}
		check_ir = TRUE;
	}

	if (!(ni->mrec->flags & MFT_RECORD_IS_DIRECTORY)) {
		/* mft record flags is not set to directory */
		if (ntfs_attr_exist(ni, AT_DATA, AT_UNNAMED, 0)) {
			if (ie_flags & FILE_ATTR_I30_INDEX_PRESENT) {
				ie_flags &= ~FILE_ATTR_I30_INDEX_PRESENT;
				ie_fn->file_attributes &= ~FILE_ATTR_I30_INDEX_PRESENT;

				fsck_err_found();
				if (ntfs_fix_problem(vol, PR_MFT_FLAG_MISMATCH_IDX_FN, &pctx)) {
					ntfs_index_entry_mark_dirty(ictx);
					fsck_err_fixed();
				}
			}
		} else {
			if (check_ir == TRUE) {
				/*
				 * Already checked index root attr.
				 * It means there are no $INDEX_ROOT and
				 * $DATA in inode.
				 */
				return STATUS_ERROR;
			}
			if (!ntfs_attr_exist(ni, AT_INDEX_ROOT, NTFS_INDEX_I30, 4)) {
				/* there are no $DATA and $INDEX_ROOT in MFT */
				return STATUS_ERROR;
			}

			/* found $INDEX_ROOT */
			ie_flags |= FILE_ATTR_I30_INDEX_PRESENT;
			ie_fn->file_attributes |= FILE_ATTR_I30_INDEX_PRESENT;

			fsck_err_found();
			if (ntfs_fix_problem(vol, PR_FILE_HAVE_IR, &pctx)) {
				ntfs_index_entry_mark_dirty(ictx);
				fsck_err_fixed();
			}
		}
	}
	return (int32_t)ie_flags;
}

/*
 * Decompose non-resident cluster runlist and make into runlist structure.
 *
 * If cluster run should be repaired, need_fix will be set to TRUE.
 * Even if cluster runs is corrupted, runlist array will preserve
 * healthy state data before encounter corruption.
 *
 * If error occur during decompose cluster run, next attributes
 * will be deleted.(In case there are multiple identical attribute exist)
 * Before deleting attribute, rl will have deleleted attribute's cluster run
 * information.(lcn field of rl which error occurred, may be LCN_ENOENT
 * or LCN_RL_NOT_MAPPED)
 *
 * If attribute is resident, it will be deleted. So caller should check
 * that only non-resident attribute will be passed to this function.
 *
 * rl may have normal cluster run information or deleted cluster run information.
 * Return runlist array(rl) if success.
 * If caller need to apply modified runlist at here, then *need_fix is set to TRUE
 * to notify it to caller.
 *
 * Return NULL if it failed to make runlist noramlly.
 * need_fix value is valid only when return success.
 *
 * this function refer to ntfs_attr_map_whole_runlist()
 */
static runlist *ntfsck_decompose_runlist(ntfs_attr *na, BOOL *need_fix)
{
	ntfs_volume *vol;
	ntfs_inode *ni;
	ntfs_attr_search_ctx *actx;
	VCN next_vcn, last_vcn, highest_vcn;
	ATTR_RECORD *attr = NULL;
	runlist *rl = NULL;
	int not_mapped;
	int err;
	problem_context_t pctx = {0, };

	if (!na || !na->ni)
		return NULL;

	ni = na->ni;
	vol = ni->vol;

	actx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!actx)
		return NULL;

	ntfs_init_problem_ctx(&pctx, ni, na, NULL, NULL, NULL, NULL, NULL);

	next_vcn = last_vcn = highest_vcn = 0;
	/* There can be multiple attributes in a inode */
	while (1) {
		runlist *temp_rl = NULL;
		if (ntfs_attr_lookup(na->type, na->name, na->name_len, CASE_SENSITIVE,
					next_vcn, NULL, 0, actx)) {
			err = ENOENT;
			if (errno == EIO) {
				if (rl) {
					free(rl);
					rl = NULL;
				}
				na->rl = NULL;
				*need_fix = TRUE;
				goto out;
			}
			break;
		}

		attr = actx->attr;

		if (!attr->non_resident) {
			ntfs_log_error("attribute should be non-resident.\n");
			continue;
		}

		not_mapped = 0;
		if (ntfs_rl_vcn_to_lcn(na->rl, next_vcn) == LCN_RL_NOT_MAPPED)
			not_mapped = 1;

		temp_rl = rl;

		if (not_mapped) {
			runlist *part_rl = NULL;

			rl = ntfs_decompress_cluster_run(vol, attr, temp_rl, &part_rl);
			if (!rl)
				return NULL;

			if (rl == part_rl) {
				*need_fix = TRUE;
				/*
				 * In case of decompress mp failure, fsck will
				 * truncate it to zero size.
				 * That is same as Windows repairing tool.
				 */
			}
			na->rl = rl;
		}

		if (!next_vcn) {
			if (attr->lowest_vcn) {
				err = EIO;
				/* should fix attribute's lowest_vcn */

				pctx.ctx = actx;
				pctx.vcn = attr->lowest_vcn;
				fsck_err_found();
				if (ntfs_fix_problem(vol, PR_ATTR_LOWEST_VCN_IS_NOT_ZERO, &pctx)) {
					attr->lowest_vcn = 0;
					NInoSetDirty(ni);
					fsck_err_fixed();
				}
				break;
			}

			/* TODO: last_vcn value should be recalculated */
			/* Get the last vcn in the attribute. */
			last_vcn = sle64_to_cpu(attr->allocated_size) >>
					vol->cluster_size_bits;
		}

		highest_vcn = sle64_to_cpu(attr->highest_vcn);
		next_vcn = highest_vcn + 1;

		if (next_vcn <= 0) {
			err = ENOENT;
			break;
		}

		/* Avoid endless loops due to corruption */
		if (next_vcn < sle64_to_cpu(attr->lowest_vcn)) {
			ntfs_log_error("Inode %"PRIu64"has corrupt attribute list\n",
					ni->mft_no);
			/* TODO: how attribute list repair ?? */
			err = EIO;
			break;
		}
	}

	if (err == ENOENT)
		NAttrSetFullyMapped(na);

	if (highest_vcn != last_vcn - 1) {
		ntfs_log_error("highest_vcn and last_vcn of attr(%x) "
				"of inode(%"PRIu64") : highest_vcn(0x%"PRIx64") "
				"last_vcn(0x%"PRIx64")\n",
				na->type, na->ni->mft_no, highest_vcn, last_vcn);
		*need_fix = TRUE;
	}

	na->rl = rl;

out:
	ntfs_attr_put_search_ctx(actx);
	return rl;
}

static int ntfsck_init_root(ntfs_volume *vol, ntfs_inode *ni, ntfs_index_context *ictx)
{
	ntfs_attr_search_ctx *ctx = NULL;
	ntfs_attr *bm_na = NULL;
	ntfs_attr *ia_na = NULL;
	INDEX_ROOT *ir = NULL;
	INDEX_ENTRY *ie = NULL;
	INDEX_BLOCK *ib = NULL;
	int ret = STATUS_ERROR;
	int index_len;
	int ir_init_size;
	u32 block_size;
	s64 r_size;
	u8 *bm = NULL;

	block_size = ictx->block_size;

	ia_na = ictx->ia_na;
	if (!ia_na)
		goto out;

	/* remain one index block not to allocate when add index for meta files in fsck */
	if (ntfs_attr_truncate(ia_na, block_size))
		goto out;

	/* initialized $INDEX_ROOT of root */
	ir = ntfs_ir_lookup(ni, NTFS_INDEX_I30, 4, &ctx);
	if (!ir)
		return STATUS_ERROR;

	index_len = sizeof(INDEX_HEADER) + sizeof(INDEX_ENTRY_HEADER) + sizeof(VCN);

	ir->index.allocated_size = cpu_to_le32(index_len);
	ir->index.index_length = cpu_to_le32(index_len);
	ir->index.entries_offset = const_cpu_to_le32(sizeof(INDEX_HEADER));
	ir->index.ih_flags = LARGE_INDEX;
	ie = (INDEX_ENTRY *)((u8 *)ir + sizeof(INDEX_ROOT));

	ie->length = cpu_to_le16(sizeof(INDEX_ENTRY_HEADER) + sizeof(VCN));
	ie->key_length = 0;
	ie->ie_flags = INDEX_ENTRY_END | INDEX_ENTRY_NODE;

	ir_init_size = sizeof(INDEX_ROOT) - sizeof(INDEX_HEADER) +
		le32_to_cpu(ir->index.allocated_size);
	ntfs_resident_attr_value_resize(ctx->mrec, ctx->attr, ir_init_size);

	/* ntfs_ie_set_vcn(ie, 0) */
	*(leVCN *)((u8 *)ie + le16_to_cpu(ie->length) - sizeof(leVCN)) = cpu_to_sle64(0);

	block_size = le32_to_cpu(ir->index_block_size);

	ib = ntfs_malloc(block_size);
	if (!ib)
		goto out;

	if (ntfs_ib_read(ictx, 0, ib)) {
		ntfs_log_perror("Failed to read $INDEX_ALLOCATION of root\n");
		goto out;
	}
	index_len = le32_to_cpu(ib->index.entries_offset) + sizeof(INDEX_ENTRY_HEADER);
	ib->index_block_vcn = cpu_to_sle64(0);
	ib->index.index_length = cpu_to_le32(index_len);
	ib->index.allocated_size = cpu_to_le32(block_size - offsetof(INDEX_BLOCK, index));
	ib->index.ih_flags = LEAF_NODE;
	ie = (INDEX_ENTRY *)((u8 *)&ib->index + le32_to_cpu(ib->index.entries_offset));
	ie->length = cpu_to_le16(sizeof(INDEX_ENTRY_HEADER));
	ie->key_length = 0;
	ie->ie_flags = INDEX_ENTRY_END;

	ntfs_ib_write(ictx, ib);

	bm_na = ntfs_attr_open(ni, AT_BITMAP, NTFS_INDEX_I30, 4);
	if (!bm_na)
		goto out;

	bm = ntfs_malloc(bm_na->data_size);
	if (!bm)
		goto out;

	r_size = ntfs_attr_pread(bm_na, 0, bm_na->data_size, bm);
	if (r_size != bm_na->data_size) {
		ntfs_log_perror("Failed to read $BITMAP of root\n");
		goto out;
	}

	memset(bm, 0, r_size);
	memset(ni->fsck_ibm, 0, ni->fsck_ibm_size);
	ntfs_inode_sync(ni);
	ntfs_attr_pwrite(bm_na, 0, bm_na->data_size, bm);
	ntfs_ibm_modify(ictx, 0, 1);

	ret = STATUS_OK;

out:
	if (ir)
		ntfs_attr_put_search_ctx(ctx);
	if (bm)
		ntfs_free(bm);
	if (bm_na)
		ntfs_attr_close(bm_na);

	return ret;
}

static int ntfsck_add_index_fn(ntfs_inode *parent_ni, ntfs_inode *ni)
{
	ntfs_attr_search_ctx *ctx = NULL;
	FILE_NAME_ATTR *fn = NULL;
	int ret = STATUS_ERROR;

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		goto out;

	if (ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, CASE_SENSITIVE,
				0, NULL, 0, ctx)) {
		ntfs_log_perror("No $FILE_NAME in %"PRIu64" inode\n",
				ni->mft_no);
		goto out;
	}
	fn = (FILE_NAME_ATTR *)((u8 *)ctx->attr +
			le16_to_cpu(ctx->attr->value_offset));

	ret = ntfs_index_add_filename(parent_ni, fn, MK_MREF(ni->mft_no,
				le16_to_cpu(ni->mrec->sequence_number)));
	if (ret) {
		goto out;
	}
	ntfs_attr_put_search_ctx(ctx);
	ctx = NULL;
	ret = STATUS_OK;
out:
	return ret;
}

static int ntfsck_initiaiize_root_index(ntfs_inode *ni, ntfs_index_context *ictx)
{
	ntfs_volume *vol;
	ntfs_inode *meta_ni;
	u64 mft_no = FILE_MFT;
	int ret = STATUS_ERROR;

	if (!ni)
		return STATUS_ERROR;

	vol = ni->vol;

	if (ni->mft_no != FILE_root)
		return STATUS_ERROR;

	ntfsck_init_root(vol, ni, ictx);

	for (mft_no = FILE_MFT; mft_no <= FILE_Extend; mft_no++) {
		meta_ni = ntfsck_open_inode(vol, mft_no);
		if (!meta_ni) {
			goto out;
		}
		ntfsck_add_index_fn(ni, meta_ni);
		ntfsck_close_inode(meta_ni);
	}

	if (vol->lost_found) {
		meta_ni = ntfsck_open_inode(vol, vol->lost_found);
		if (!meta_ni) {
			goto out;
		}
		ntfsck_add_index_fn(ni, meta_ni);
		ntfsck_close_inode(meta_ni);
	}
	ret = STATUS_OK;

out:
	return ret;
}

/*
 * Remove $IA/$BITMAP, and initialize $IR attribute for repairing.
 * This function should be called $IA or $BITMAP attribute is corrupted.
 */
static int ntfsck_initialize_index_attr(ntfs_inode *ni)
{
	ntfs_attr *bm_na = NULL;
	ntfs_attr *ia_na = NULL;
	ntfs_attr *ir_na = NULL;
	int ret = STATUS_ERROR;

	/*
	 * Remove both ia attr and bitmap attr and recreate them.
	 */
	ia_na = ntfs_attr_open(ni, AT_INDEX_ALLOCATION, NTFS_INDEX_I30, 4);
	if (ia_na) {
		/* clear fsck cluster(lcn) bitmap */
		ntfsck_clear_attr_lcnbmp(ia_na);

		if (ntfs_attr_rm(ia_na)) {
			ntfs_log_error("Failed to remove $IA attr. of inode(%"PRId64")\n",
					ni->mft_no);
			goto out;
		}
		ntfs_attr_close(ia_na);
		ia_na = NULL;
	}

	bm_na = ntfs_attr_open(ni, AT_BITMAP, NTFS_INDEX_I30, 4);
	if (bm_na) {
		if (ntfs_attr_rm(bm_na)) {
			ntfs_log_error("Failed to remove $BITMAP attr. of "
					" inode(%"PRIu64")\n", ni->mft_no);
			goto out;
		}
		ntfs_attr_close(bm_na);
		bm_na = NULL;
	}

	ir_na = ntfs_attr_open(ni, AT_INDEX_ROOT, NTFS_INDEX_I30, 4);
	if (!ir_na) {
		ntfs_log_verbose("Can't open $IR attribute from mft(%"PRIu64") entry\n",
				ni->mft_no);
		goto out;
	}

	ret = ntfs_attr_truncate(ir_na,
			sizeof(INDEX_ROOT) + sizeof(INDEX_ENTRY_HEADER));
	if (ret == STATUS_OK) {
		INDEX_ROOT *ir;
		INDEX_ENTRY *ie;
		int index_len =
			sizeof(INDEX_HEADER) + sizeof(INDEX_ENTRY_HEADER);

		ir = ntfs_ir_lookup2(ni, NTFS_INDEX_I30, 4);
		if (!ir)
			goto out;

		ir->index.allocated_size = cpu_to_le32(index_len);
		ir->index.index_length = cpu_to_le32(index_len);
		ir->index.entries_offset = const_cpu_to_le32(sizeof(INDEX_HEADER));
		ir->index.ih_flags = SMALL_INDEX;
		ie = (INDEX_ENTRY *)((u8 *)ir + sizeof(INDEX_ROOT));
		ie->length = cpu_to_le16(sizeof(INDEX_ENTRY_HEADER));
		ie->key_length = 0;
		ie->ie_flags = INDEX_ENTRY_END;
	} else if (ret == STATUS_ERROR) {
		ntfs_log_perror("Failed to truncate INDEX_ROOT");
		goto out;
	}

	ntfs_attr_close(ir_na);
	ir_na = NULL;

	ntfs_inode_mark_dirty(ni);

	ret = STATUS_OK;
out:
	if (ir_na)
		ntfs_attr_close(ir_na);
	if (ia_na)
		ntfs_attr_close(ia_na);
	if (bm_na)
		ntfs_attr_close(bm_na);
	return ret;
}

/*
 * Read non-resident attribute's cluster run from disk,
 * and make rl structure. Even if error occurred during decomposing
 * runlist, rl will include only valid cluster run of attribute.
 *
 * And rl also has another valid cluster run of next attribute.
 * (multiple same name attribute may exist)
 *
 * If error occurred during decomposing runlist, lcn field of rl may
 * have LCN_RL_NOT_MAPPED or not.
 *
 * (TODO) more documentation.
 *
 */
static int ntfsck_check_attr_runlist(ntfs_attr *na, struct rl_size *rls,
		BOOL *need_fix, int set_bit)
{
	runlist *rl = NULL;
	int ret = STATUS_OK;

	if (!na || !na->ni)
		return STATUS_ERROR;

	rl = ntfsck_decompose_runlist(na, need_fix);
	if (!rl) {
		ntfs_log_error("Failed to get cluster run in directory(%"PRId64")",
				na->ni->mft_no);
		return STATUS_ERROR;
	}

	if (*need_fix == TRUE) {
		ntfs_log_error("Non-resident cluster run of inode(%"PRId64")(%02x:%"PRIu64") "
				"corrupted. rl_size(%"PRIx64":%"PRIx64"). Truncate it",
				na->ni->mft_no, na->type, na->data_size, rls->alloc_size, rls->real_size);
	}

#if UNUSED
	ntfs_log_debug("Before (%"PRId64") =========================\n",
			na->ni->mft_no);
	ntfs_debug_runlist_dump(rl);
#endif

	ret = ntfsck_check_runlist(na, set_bit, rls, need_fix);
	if (ret)
		return STATUS_ERROR;

#if UNUSED
	ntfs_log_debug("After (%"PRId64") =========================\n",
			na->ni->mft_no);
	ntfs_debug_runlist_dump(na->rl);
#endif

	return 0;
}

static int ntfsck_update_runlist(ntfs_attr *na, s64 new_size, ntfs_attr_search_ctx *actx)
{
	ntfs_inode *ni;
	u32 backup_attr_list_size;

	if (!na->ni)
		return STATUS_ERROR;

	ni = na->ni;
	if (NInoAttrList(ni))
		backup_attr_list_size = ni->attr_list_size;

	/* apply rl to disk */
	na->allocated_size = new_size;
	if (ntfs_attr_update_mapping_pairs(na, 0)) {
		ntfs_log_error("Failed to update mapping pairs of "
				"inode(%"PRIu64")\n", ni->mft_no);
		return STATUS_ERROR;
	}

	/*
	 * new allocated attr_list of inode in ntfs_attr_update_mapping_pairs()
	 * so, SHOULD change field related with attr_list
	 */
	if (actx && ni->attr_list_size != backup_attr_list_size) {
		ntfs_attr_reinit_search_ctx(actx);
		if (ntfs_attr_lookup(na->type, na->name, na->name_len, 0, 0, NULL, 0, actx)) {
			ntfs_log_error("Failed to lookup type(%d) of inode(%"PRIu64")\n",
					na->type, ni->mft_no);
			return STATUS_ERROR;
		}
	}

	/* Update data size in the index. */
	if (na->ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
		if (na->type == AT_INDEX_ROOT && na->name == NTFS_INDEX_I30) {
			na->ni->data_size = na->data_size;
			na->ni->allocated_size = na->allocated_size;
			set_nino_flag(na->ni, KnownSize);
		}
	} else {
		if (na->type == AT_DATA && na->name == AT_UNNAMED) {
			na->ni->data_size = na->data_size;
			NInoFileNameSetDirty(na->ni);
		}
	}

	return STATUS_OK;
}

static int ntfsck_check_non_resident_attr(ntfs_attr *na,
		ntfs_attr_search_ctx *actx, struct rl_size *out_rls, int set_bit)
{
	BOOL need_fix = FALSE;
	ntfs_volume *vol;
	ntfs_inode *ni;
	ATTR_RECORD *a;

	s64 data_size;
	s64 alloc_size;
	s64 new_size;
	s64 aligned_data_size;
	s64 lowest_vcn;
	struct rl_size rls = {0, };
	problem_context_t pctx = {0, };

	if (!na || !na->ni || !na->ni->vol)
		return STATUS_ERROR;

	if (!actx || !actx->attr || !actx->attr->non_resident)
		return STATUS_ERROR;

	ni = na->ni;
	vol = na->ni->vol;
	a =  actx->attr;

	ntfs_init_problem_ctx(&pctx, ni, na, actx, NULL, NULL, a, NULL);

	/* check whole cluster runlist and set cluster bitmap of fsck */
	if (ntfsck_check_attr_runlist(na, &rls, &need_fix, set_bit)) {
		ntfs_log_error("Failed to get non-resident attribute(%d) "
				"in directory(%"PRId64")", na->type, ni->mft_no);
		return STATUS_ERROR;
	}

	/* if need_fix is set to TRUE, apply modified runlist to cluster runs */
	if (need_fix == TRUE) {
		fsck_err_found();
		if (ntfs_fix_problem(vol, PR_LOG_APPLY_RUNLIST_TO_DISK, &pctx)) {
			/*
			 * keep a valid runlist as long as possible.
			 * if truncate zero, call with second parameter to 0
			 */
			if (ntfsck_update_runlist(na, rls.alloc_size, actx)) {
				/* FIXME: why ntfsck_update_runlist failed? and
				 * what should it do? */
				fsck_err_fixed();
				return STATUS_ERROR;
			}
			fsck_err_fixed();
		}
	}

	/*
	 * Skip size check of metadata files
	 */
	if (utils_is_metadata(ni))
		goto out;

	/*
	 * Check size only atrr->lowest_vcn is zero.
	 */
	lowest_vcn = sle64_to_cpu(a->lowest_vcn);
	if (lowest_vcn)
		goto out;

	data_size = le64_to_cpu(a->data_size);
	alloc_size = le64_to_cpu(a->allocated_size);
	aligned_data_size = (data_size + vol->cluster_size - 1) & ~(vol->cluster_size - 1);

	/*
	 * Reset non-residnet if sizes are invalid,
	 * And then make it resident attribute.
	 */

	/* TODO: check more detail */

	if (alloc_size != rls.alloc_size || data_size > alloc_size) {
		new_size = 0;
	} else {
		if (aligned_data_size <= alloc_size)
			goto out;
		new_size = alloc_size;
	}

	/*
	 * ntfsck_update_runlist will set appropriate flag
	 * and fields of attribute structure at ntfs_attr_update_meta(),
	 * that is also including compressed_size and flags.
	 */

	fsck_err_found();
	if (!ntfs_fix_problem(vol, PR_ATTR_NON_RESIDENT_SIZES_MISMATCH, &pctx))
		goto out;

	if (na->type == AT_INDEX_ALLOCATION)
		ntfsck_initialize_index_attr(ni);
	else
		ntfs_non_resident_attr_shrink(na, new_size);

	fsck_err_fixed();

out:
	if (out_rls)
		memcpy(out_rls, &rls, sizeof(struct rl_size));

	return STATUS_OK;
}

static int ntfsck_check_directory(ntfs_inode *ni)
{
	ntfs_attr *ia_na = NULL;
	ntfs_attr *bm_na = NULL;
	int ret = STATUS_OK;
	problem_context_t pctx = {0, };

	if (!ni)
		return -EINVAL;

	/*
	 * header size and overflow is already checked in opening inode
	 * (ntfs_attr_inconsistent()). just check existence of $INDEX_ROOT.
	 */
	if (!ntfs_attr_exist(ni, AT_INDEX_ROOT, NTFS_INDEX_I30, 4)) {
		ntfs_log_perror("$IR is missing in inode(%"PRId64")", ni->mft_no);
		ret = STATUS_ERROR;
		/* remove mft entry */
		goto out;
	}

	ia_na = ntfs_attr_open(ni, AT_INDEX_ALLOCATION, NTFS_INDEX_I30, 4);
	if (!ia_na) {
		/* directory can have only $INDEX_ROOT. not error */

		/* check $BITMAP if exist */
		bm_na = ntfs_attr_open(ni, AT_BITMAP, NTFS_INDEX_I30, 4);
		if (!bm_na) {
			/* both $IA and $BITMAP do not exist. it's OK. */
			ret = STATUS_OK;
			goto check_next;
		}

		/* only $BITMAP exist, remove it */
		if (ntfs_attr_rm(bm_na)) {
			ntfs_log_error("Failed to remove $BITMAP attr. of "
					" inode(%"PRId64")\n", ni->mft_no);
			ret = STATUS_ERROR;
			goto out;
		}
		ntfs_attr_close(bm_na);
		bm_na = NULL;
		goto check_next;
	}

	/* $INDEX_ALLOCATION is always non-resident */
	if (!NAttrNonResident(ia_na)) {
		/* TODO: check $BITMAP, if exist, remove bitmap and ia */
		ret = STATUS_ERROR;
		goto init_all;
	}

	/*
	 * check $BITMAP's cluster run
	 * TODO: is it possible multiple $BITMAP attrib in inode?
	 */
	bm_na = ntfs_attr_open(ni, AT_BITMAP, NTFS_INDEX_I30, 4);
	if (!bm_na) {
		u8 bmp[8];

		ntfs_log_perror("Failed to open $BITMAP of inode(%"PRIu64")",
				ni->mft_no);

		memset(bmp, 0, sizeof(bmp));
		if (ntfs_attr_add(ni, AT_BITMAP, NTFS_INDEX_I30, 4, bmp,
					sizeof(bmp))) {
			ntfs_log_perror("Failed to add AT_BITMAP");
			ret = STATUS_ERROR;
			goto out;
		}
	}

check_next:
	/* $INDEX_ALLOCATION actual size is zero, remove it with $BITMAP */
	if (ia_na && ia_na->data_size == 0) {
		ntfs_attr_rm(ia_na);
		if (bm_na)
			ntfs_attr_rm(bm_na);
	}

out:
	if (bm_na)
		ntfs_attr_close(bm_na);
	if (ia_na)
		ntfs_attr_close(ia_na);

	return ret;

init_all:
	if (bm_na)
		ntfs_attr_close(bm_na);
	if (ia_na)
		ntfs_attr_close(ia_na);

	ntfs_init_problem_ctx(&pctx, ni, NULL, NULL, NULL, NULL, NULL, NULL);
	fsck_err_found();
	if (ntfs_fix_problem(ni->vol, PR_DIR_HAVE_RESIDENT_IA, &pctx)) {
		ntfsck_initialize_index_attr(ni);
		fsck_err_fixed();
	}

	return ret;
}

static int ntfsck_check_file(ntfs_inode *ni)
{
	ntfs_attr_search_ctx *ctx;
	ntfs_volume *vol;
	ATTR_RECORD *a;
	FILE_ATTR_FLAGS attr_flags = 0;

	if (!ni)
		return STATUS_ERROR;

	vol = ni->vol;

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		return STATUS_ERROR;

	if (ntfs_attr_lookup(AT_DATA, NULL, 0, CASE_SENSITIVE, 0, NULL, 0, ctx)) {
		ntfs_log_error("$DATA attribute of Inode(%"PRIu64") is missing\n",
				ni->mft_no);
		goto err_out;
	}

	a = ctx->attr;
	if (a->flags & (ATTR_COMPRESSION_MASK | ATTR_IS_SPARSE)) {
		if (a->flags & ATTR_COMPRESSION_MASK) {
			attr_flags = FILE_ATTR_COMPRESSED;
			if (vol->cluster_size > 4096) {
				ntfs_log_error("Found compressed data(%"PRIu64" but "
						"compression is disabled due to "
						"cluster size(%i) > 4kiB.\n",
						ni->mft_no, vol->cluster_size);
				goto err_out;
			}

			if ((a->flags & ATTR_COMPRESSION_MASK) != ATTR_IS_COMPRESSED) {
				ntfs_log_error("Found unknown compression method "
						"or corrupt file.(%"PRIu64")\n",
						ni->mft_no);
				goto err_out;
			}
		}
		if (a->flags & ATTR_IS_SPARSE)
			attr_flags |= FILE_ATTR_SPARSE_FILE;
	}

	if (a->flags & ATTR_IS_ENCRYPTED) {
		if (attr_flags & FILE_ATTR_COMPRESSED) {
			ntfs_log_error("Found encrypted and compressed data.(%"PRIu64")\n",
					ni->mft_no);
			goto err_out;
		}
		attr_flags |= FILE_ATTR_ENCRYPTED;
	}

	ntfs_attr_put_search_ctx(ctx);
	return STATUS_OK;

err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);

	return STATUS_ERROR;
}

/* called after ntfs_inode_attatch_all_extents() is called */
static int ntfsck_set_mft_record_bitmap(ntfs_inode *ni, BOOL ondisk_mft_bmp_set)
{
	int ext_idx = 0;
	ntfs_volume *vol;

	if (!ni || !ni->vol)
		return STATUS_ERROR;

	vol = ni->vol;

	if (ntfs_fsck_mftbmp_set(vol, ni->mft_no)) {
		ntfs_log_error("Failed to set MFT bitmap for (%"PRIu64")\n",
				ni->mft_no);
		/* do not return error */
	}

	if (ondisk_mft_bmp_set == TRUE)
		ntfs_bitmap_set_bit(vol->mftbmp_na, ni->mft_no);

	/* set mft record bitmap */
	while (ext_idx < ni->nr_extents) {
		if (ntfs_fsck_mftbmp_set(vol, ni->extent_nis[ext_idx]->mft_no)) {
			/* do not return error */
			break;
		}
		if (ondisk_mft_bmp_set == TRUE)
			ntfs_bitmap_set_bit(vol->mftbmp_na, ni->extent_nis[ext_idx]->mft_no);
		ext_idx++;
	}

	return STATUS_OK;
}

/*
 * check all cluster runlist of non-resident attributes of a inode
 */
static int ntfsck_check_inode_non_resident(ntfs_inode *ni, int set_bit)
{
	ntfs_attr_search_ctx *ctx;
	ntfs_attr *na;
	ATTR_RECORD *a;
	int ret = STATUS_OK;

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		return STATUS_ERROR;

	while (!(ret = ntfs_attrs_walk(ctx))) {
		a = ctx->attr;
		if (!a->non_resident)
			continue;

		/*
		 * skip already checked same attribute type,
		 * because ntfsck_check_non_resident_attr()
		 * check all same attribute type at once
		 */
		if (a->type >= AT_FIRST_USER_DEFINED_ATTRIBUTE) {
			ntfs_log_trace("SKIP: inode %"PRIu64", type(%04x) for user defined\n",
					ni->mft_no, a->type);
			continue;
		}

		/*
		 * To distinguish named attribute like as $DATA:UNNAMED, $DATA:NAMED,
		 * check lowest_vcn. if lowest_vcn of attribute is not zero and attribute
		 * bitmap is already set, then we can skip that attribute
		 * because it has already checked in previous attributes walk.
		 */
		if (le64_to_cpu(a->lowest_vcn) != 0) {
			ntfs_log_trace("SKIP: inode %"PRIu64", type %02x\n",
					ni->mft_no, a->type);
			continue;
		}

		na = ntfs_attr_open(ni, a->type,
				(ntfschar *)((u8 *)a + le16_to_cpu(a->name_offset)),
				a->name_length);
		if (!na) {
			ntfs_log_perror("Can't open attribute(%d) of inode(%"PRIu64")\n",
					a->type, ni->mft_no);
			ntfs_attr_put_search_ctx(ctx);
			return STATUS_ERROR;
		}

		ret = ntfsck_check_non_resident_attr(na, ctx, NULL, set_bit);

		ntfs_attr_close(na);
		if (ret) {
			ntfs_attr_put_search_ctx(ctx);
			return STATUS_ERROR;
		}
	}

	if (ret == -1 && errno == ENOENT)
		ret = STATUS_OK;

	ntfs_attr_put_search_ctx(ctx);
	return ret;
}

static int _ntfsck_check_attr_list_type(ntfs_attr_search_ctx *ctx)
{
	ntfs_inode *ni;

	ATTR_TYPES type;
	ATTR_LIST_ENTRY *al_entry;
	ATTR_LIST_ENTRY *next_al_entry;
	u16 al_length = 0;
	u16 al_real_length = 0;
	u8 *al_start;
	u8 *al_end;
	u8 *next_al_end = 0;
	int ret = STATUS_OK;
	problem_context_t pctx = {0, };

	ni = ctx->ntfs_ino;
	if (ctx->base_ntfs_ino && ni != ctx->base_ntfs_ino)
		return STATUS_ERROR;

	ntfs_init_problem_ctx(&pctx, ni, NULL, ctx, NULL, ctx->mrec, ctx->attr, NULL);
	al_start = ni->attr_list;
	al_end = al_start + ni->attr_list_size;
	al_entry = (ATTR_LIST_ENTRY *)ni->attr_list;

	do {
		type = al_entry->type;

		if (type != AT_STANDARD_INFORMATION &&
			type != AT_FILE_NAME &&
			type != AT_OBJECT_ID &&
			type != AT_SECURITY_DESCRIPTOR &&
			type != AT_VOLUME_NAME &&
			type != AT_VOLUME_INFORMATION &&
			type != AT_DATA &&
			type != AT_INDEX_ROOT &&
			type != AT_INDEX_ALLOCATION &&
			type != AT_BITMAP &&
			type != AT_REPARSE_POINT &&
			type != AT_EA_INFORMATION &&
			type != AT_EA &&
			type != AT_PROPERTY_SET &&
			type != AT_LOGGED_UTILITY_STREAM) {

			/* attrlist is corrupted */
			ret = STATUS_ERROR;
			goto out;
		}

		al_length = le16_to_cpu(al_entry->length);
		if (al_length == 0 || al_length & 7) {
			ret = STATUS_ERROR;
			goto out;
		}

		al_real_length += al_length;
		next_al_entry =
			(ATTR_LIST_ENTRY *)((u8 *)al_entry + al_length);

		if ((u8 *)next_al_entry >= al_end)
			break;

		next_al_end = (u8 *)next_al_entry + le16_to_cpu(next_al_entry->length);
		if (next_al_end > al_end)
			break;

		al_entry = next_al_entry;
	} while (1);

out:
	if (ni->attr_list_size != al_real_length) {
		fsck_err_found();
		if (ntfs_fix_problem(ni->vol, PR_ATTRLIST_LENGTH_CORRUPTED, &pctx)) {
			ntfs_set_attribute_value_length(ctx->attr, al_real_length);
			ni->attr_list_size = al_real_length;
			if (!errno) {
				ntfs_inode_mark_dirty(ni);
				fsck_err_fixed();
			}
		}
	}

	return ret;
}

static int ntfsck_check_attr_list(ntfs_inode *ni)
{
	ntfs_attr_search_ctx *ctx;
	int ret = STATUS_OK;

	if (!ni->attr_list)
		return STATUS_ERROR;

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		return STATUS_ERROR;

	if (ntfs_attr_lookup(AT_ATTRIBUTE_LIST, AT_UNNAMED, 0, CASE_SENSITIVE,
				0, NULL, 0, ctx)) {
		ret = STATUS_ERROR;
		goto out;
	}

	ret = _ntfsck_check_attr_list_type(ctx);

out:
	ntfs_attr_put_search_ctx(ctx);
	return ret;
}

static int ntfsck_check_inode(ntfs_inode *ni, INDEX_ENTRY *ie,
		ntfs_index_context *ictx)
{
	FILE_NAME_ATTR *ie_fn = (FILE_NAME_ATTR *)&ie->key.file_name;
	int32_t flags;
	int ret;

	if (ni->attr_list) {
		if (ntfsck_check_attr_list(ni))
			goto err_out;

		if (ntfs_inode_attach_all_extents(ni))
			goto err_out;
	}

	if (ntfsck_check_inode_fields(ictx->ni, ni, ie))
		goto err_out;

	ret = ntfsck_check_inode_non_resident(ni, 1);
	if (ret)
		goto err_out;

	/* Check file type */
	flags = ntfsck_check_file_type(ni, ictx, ie_fn);
	if (flags < 0)
		goto err_out;

	if (flags & FILE_ATTR_I30_INDEX_PRESENT) {
		ret = ntfsck_check_directory(ni);
		if (ret)
			goto err_out;
	} else if (flags & FILE_ATTR_VIEW_INDEX_PRESENT) {
		/* TODO: check view index */
	} else {
		ret = ntfsck_check_file(ni);
		if (ret)
			goto err_out;
	}

	/* check $FILE_NAME */
	ret = ntfsck_check_file_name_attr(ni, ie_fn, ictx);
	if (ret < 0)
		goto err_out;

	/* FALSE or TRUE? */
	ntfsck_set_mft_record_bitmap(ni, FALSE);
	return STATUS_OK;

err_out:
	ntfsck_check_inode_non_resident(ni, 0);
	return STATUS_ERROR;
}

static int ntfsck_check_system_inode(ntfs_inode *ni, INDEX_ENTRY *ie,
		ntfs_index_context *ictx)
{
	int ret;

	if (ntfsck_check_inode_fields(ictx->ni, ni, ie))
		goto err_out;

	if (ni->attr_list) {
		ntfsck_check_attr_list(ni);
		ntfs_inode_attach_all_extents(ni);
	}

	ret = ntfsck_check_inode_non_resident(ni, 1);
	if (ret)
		goto err_out;

	/*
	 * Directory system file is Root and $Extend only.
	 * Root directory is already checked in ntfsck_check_system_files() */
	if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
		ret = ntfsck_check_directory(ni);
	}

	/* TODO: check index
	if (ni->mrec->flags & MFT_RECORD_IS_VIEW_INDEX) {
		ret = ntfsck_check_index(ni);
	}
	*/

	/* TODO: check system file more detail respectively. */

	ntfsck_set_mft_record_bitmap(ni, FALSE);
	return STATUS_OK;

err_out:
	ntfsck_check_inode_non_resident(ni, 0);
	return STATUS_ERROR;
}

static inline int ntfsck_is_directory(FILE_NAME_ATTR *ie_fn)
{
	if (!(ie_fn->file_attributes & FILE_ATTR_I30_INDEX_PRESENT))
		return 0;

	if (ie_fn->file_name_length == 1) {
		char *filename;

		filename = ntfs_attr_name_get(ie_fn->file_name,
				ie_fn->file_name_length);
		if (!strcmp(filename, ".")) {
			free(filename);
			return 0;
		}
		free(filename);
	}

	return 1;
}

/*
 * Check index and inode which is pointed by index.
 * if pointed inode is directory, then add it to ntfs_dir_list.
 *
 * @vol:	ntfs_volume
 * @ie:		index entry to check
 * @ictx:	index context to handle index entry
 *
 * @return:	return 0, for checking success,
 *		return 1, removal of index due to failure,
 *		return < 0, for other cases
 *
 * After calling ntfs_index_rm(), ictx->entry will point next entry
 * of deleted entry. So caller can distinguish what happened in this
 * function using return value.(if this function return 1, caller do
 * not need to call ntfs_index_next(), cause ictx->entry already point
 * next entry.
 */
static int ntfsck_check_index(ntfs_volume *vol, INDEX_ENTRY *ie,
			       ntfs_index_context *ictx)
{
	ntfs_inode *ni;
	struct dir *dir;
	MFT_REF mref;
	u64 mft_no;
	int ret = STATUS_OK;
	FILE_NAME_ATTR *ie_fn = &ie->key.file_name;
	problem_context_t pctx = {0, };

	if (!ie)
		return STATUS_ERROR;

	mref = le64_to_cpu(ie->indexed_file);
	mft_no = MREF(mref);
	if ((ntfsck_opened_ni_vol(MREF(mref)) == TRUE) || mft_no == FILE_root)
		return STATUS_OK;

	ntfs_init_problem_ctx(&pctx, NULL, NULL, NULL, ictx, NULL, NULL, ie_fn);
	pctx.inum = mft_no;
#ifdef DEBUG
	char *filename;
	filename = ntfs_attr_name_get(ie_fn->file_name, ie_fn->file_name_length);
	ntfs_log_info("%s %"PRIu64", %s, ictx->ni %"PRIu64"\n", __func__,
			mft_no, filename, ictx->ni->mft_no);
	free(filename);
#endif

	ni = ntfsck_open_inode(vol, mft_no);
	if (ni) {
		BOOL is_mft_checked = FALSE;

		/*
		 * check if mft record is already checked
		 */
		if (ntfs_fsck_mftbmp_get(vol, ni->mft_no)) {
			is_mft_checked = TRUE;

			/* Check file type */
			if (ntfsck_check_file_type(ni, ictx, ie_fn) < 0) {
				ntfsck_close_inode(ni);
				goto remove_index;
			}

			/* check $FILE_NAME */
			if (ntfsck_check_file_name_attr(ni, ie_fn, ictx) < 0) {
				ntfsck_close_inode(ni);
				goto remove_index;
			}
			ntfsck_close_inode(ni);
			return STATUS_OK;
		}

		/* checking for system files or not */
		if ((utils_is_metadata(ni) == 1) ||
				((utils_is_metadata(ictx->ni) == 1) &&
				 (ictx->ni->mft_no != FILE_root))) {
			/*
			 * Do not check return value because system files can be deleted.
			 * this check may be already done in check system files.
			 */
			ret = ntfsck_check_system_inode(ni, ie, ictx);
		} else {
			ret = ntfsck_check_inode(ni, ie, ictx);
			if (ret) {
				ntfs_log_error("Failed to check inode(%"PRIu64") "
						"in parent(%"PRIu64") index.\n",
						ni->mft_no, ictx->ni->mft_no);

				NInoFileNameClearDirty(ni);
				NInoAttrListClearDirty(ni);
				NInoClearDirty(ni);
				/* TODO: distinguish delete or not, as error type */

				/* Do not clear bitmap on disk */
				ntfsck_close_inode(ni);
				goto remove_index;
			}
		}

		if (ntfsck_is_directory(ie_fn) && is_mft_checked == FALSE) {
			dir = (struct dir *)calloc(1, sizeof(struct dir));
			if (!dir) {
				ntfs_log_error("Failed to allocate for subdir.\n");
				ntfsck_close_inode(ni);
				ret = STATUS_ERROR;
				goto err_out;
			}

			dir->mft_no = ni->mft_no;
			ntfsck_close_inode(ni);
			ntfs_list_add_tail(&dir->list, &ntfs_dirs_list);
		} else {
			ret = ntfsck_close_inode_in_dir(ni, ictx->ni);
			if (ret) {
				ntfs_log_error("Failed to close inode(%"PRIu64")\n",
						ni->mft_no);
				goto remove_index;
			}
		}
	} else {
		char *crtname;

		ntfs_log_error("Failed to open inode(%"PRIu64")\n", mft_no);

remove_index:
		crtname = ntfs_attr_name_get(ie_fn->file_name, ie_fn->file_name_length);
		fsck_err_found();
		pctx.filename = crtname;
		if (ntfs_fix_problem(vol, PR_IDX_ENTRY_CORRUPTED, &pctx)) {
			ictx->entry = ie;
			ret = ntfs_index_rm(ictx);
			if (ret) {
				ntfs_log_error("Failed to remove index entry of inode(%"PRIu64":%s)\n",
						mft_no, crtname);
			} else {
				ntfs_log_verbose("Index entry of inode(%"PRIu64":%s) is deleted\n",
						mft_no, crtname);
				ret = STATUS_FIXED;
				fsck_err_fixed();
				if (ictx->actx)
					ntfs_inode_mark_dirty(ictx->actx->ntfs_ino);
			}
		}
		free(crtname);
	}

err_out:
	return ret;
}

/*
 * set bitmap of current index allocation's all parent vcn.
 */
static int ntfsck_set_index_bitmap(ntfs_inode *ni, ntfs_index_context *ictx,
		ntfs_attr *bm_na)
{
	INDEX_HEADER *ih;
	s64 vcn = -1;
	s64 pos;
	u32 bpos;
	int i;

	if (!ictx->ib)
		return STATUS_ERROR;

	if (ni != ictx->ni)
		ntfs_log_error("inode(%p) and ictx->ni(%p) are different\n",
				ni, ictx->ni);

	ih = &ictx->ib->index;
	if ((ih->ih_flags & NODE_MASK) != LEAF_NODE)
		return STATUS_OK;

	vcn = ictx->parent_vcn[ictx->pindex];
	pos = (vcn << ictx->vcn_size_bits) / ictx->block_size;
	bpos = pos >> NTFSCK_BYTE_TO_BITS;

	if (ictx->ni->fsck_ibm_size < bpos + 1) {
		ictx->ni->fsck_ibm = ntfs_realloc(ictx->ni->fsck_ibm,
				(bm_na->data_size + 8) & ~7);
		if (!ictx->ni->fsck_ibm) {
			ntfs_log_perror("Failed to realloc fsck_ibm(%"PRId64")",
					bm_na->data_size);
			return STATUS_ERROR;
		}

		ictx->ni->fsck_ibm_size = (bm_na->data_size + 8) & ~7;
	}

	for (i = ictx->pindex; i > 0; i--) {
		vcn = ictx->parent_vcn[i];
		pos = (vcn << ictx->vcn_size_bits) / ictx->block_size;
		ntfs_bit_set(ictx->ni->fsck_ibm, pos, 1);
	}

	return STATUS_OK;
}

static int ntfsck_check_index_bitmap(ntfs_inode *ni, ntfs_attr *bm_na)
{
	s64 ibm_size = 0;
	s64 wcnt = 0;
	u8 *ni_ibm = NULL;	/* for index bitmap reading from disk: $BITMAP */
	ntfs_volume *vol;
	problem_context_t pctx = {0, };

	if (!ni || !ni->fsck_ibm)
		return STATUS_ERROR;

	vol = ni->vol;

	ntfs_init_problem_ctx(&pctx, ni, bm_na, NULL, NULL, ni->mrec, NULL, NULL);

	/* read index bitmap from disk */
	ni_ibm = ntfs_attr_readall(ni, AT_BITMAP, NTFS_INDEX_I30, 4, &ibm_size);
	if (!ni_ibm) {
		ntfs_log_error("Failed to read $BITMAP of inode(%"PRIu64")\n",
				ni->mft_no);
		return STATUS_ERROR;
	}

	if (ibm_size != ni->fsck_ibm_size) {
		/* FIXME: if ni->fsck_ibm_size is larger than ibm_size,
		 * it could allocate cluster in ntfs_attr_pwrite() */
		ntfs_log_info("\n\nBitmap changed during check_inodes\n");
		fsck_err_found();
		if (ntfs_fix_problem(vol, PR_IDX_BITMAP_SIZE_MISMATCH, &pctx)) {
			wcnt = ntfs_attr_pwrite(bm_na, 0, ni->fsck_ibm_size, ni->fsck_ibm);
			if (wcnt == ni->fsck_ibm_size)
				fsck_err_fixed();
			else
				ntfs_log_error("Can't write $BITMAP(%"PRId64") "
						"of inode(%"PRIu64")\n", wcnt, ni->mft_no);
		}
		goto out;
	}

	if (memcmp(ni->fsck_ibm, ni_ibm, ibm_size)) {
#ifdef DEBUG
		int pos = 0;
		int remain = 0;

		remain = ibm_size;
		while (remain > 0) {
			ntfs_log_verbose("disk $IA bitmap : %08llx\n",
					*(unsigned long long *)(ni_ibm + pos));
			ntfs_log_verbose("fsck $IA bitmap : %08llx\n",
					*(unsigned long long *)(ni->fsck_ibm + pos));

			remain -= sizeof(unsigned long long);
			pos += sizeof(unsigned long long);
		}
#endif
		fsck_err_found();
		if (ntfs_fix_problem(vol, PR_IDX_BITMAP_MISMATCH, &pctx)) {
			wcnt = ntfs_attr_pwrite(bm_na, 0, ibm_size, ni->fsck_ibm);
			if (wcnt == ibm_size)
				fsck_err_fixed();
			else
				ntfs_log_error("Can't write $BITMAP(%"PRId64") "
						"of inode(%"PRIu64")\n", wcnt, ni->mft_no);
		}
	}

out:
	free(ni_ibm);

	return STATUS_OK;
}

static void ntfsck_validate_index_blocks(ntfs_volume *vol,
					 ntfs_index_context *ictx)
{
	ntfs_attr *bmp_na = NULL;
	INDEX_ALLOCATION *ia;
	INDEX_ENTRY *ie;
	INDEX_ROOT *ir = ictx->ir;
	ntfs_inode *ni = ictx->ni;
	VCN vcn;
	u32 ir_size = le32_to_cpu(ir->index.index_length);
	u8 *ir_buf = NULL, *ia_buf = NULL, *bmp_buf = NULL, *index_end;
	u64 max_vcn_bits;
	u32 vcn_step;
	VCN max_vcn;
	int ret = STATUS_OK;
	problem_context_t pctx = {0, };

	ictx->ia_na = ntfs_attr_open(ni, AT_INDEX_ALLOCATION,
			ictx->name, ictx->name_len);
	if (!ictx->ia_na)
		return;

	bmp_na = ntfs_attr_open(ictx->ni, AT_BITMAP, ictx->name, ictx->name_len);
	if (!bmp_na) {
		ntfs_log_error("Failed to open bitmap\n");
		goto out;
	}

	bmp_buf = malloc(bmp_na->data_size);
	if (!bmp_buf) {
		ntfs_log_error("Failed to allocate bitmap buffer\n");
		goto out;
	}

	if (ntfs_attr_pread(bmp_na, 0, bmp_na->data_size, bmp_buf) != bmp_na->data_size) {
		ntfs_log_perror("Failed to read $BITMAP");
		goto out;
	}

	ir_buf = malloc(le32_to_cpu(ir->index.index_length));
	if (!ir_buf) {
		ntfs_log_error("Failed to allocate ir buffer\n");
		goto out;
	}

	memcpy(ir_buf, (u8 *)&ir->index + le32_to_cpu(ir->index.entries_offset),
		       ir_size);

	/* check entries in INDEX_ROOT */
	index_end = ir_buf + ir_size;
	ie = (INDEX_ENTRY *)ir_buf;
	for (; (u8 *)ie < index_end;
			ie = (INDEX_ENTRY *)((u8 *)ie + le16_to_cpu(ie->length))) {
		/* check length bound */
		if ((u8 *)ie + sizeof(INDEX_ENTRY_HEADER) > index_end ||
		    (u8 *)ie + le16_to_cpu(ie->length) > index_end) {
			ntfs_log_error("Index root entry out of bounds in"
					" inode %"PRId64"\n", ni->mft_no);
			goto initialize_index;
		}

		if (ie->ie_flags & INDEX_ENTRY_NODE) {
			VCN vcn = ntfs_ie_get_vcn(ie);
			u32 sub_bmp_pos;

			/* check bitmap for sub-node */
			sub_bmp_pos = (vcn << ictx->vcn_size_bits) / ictx->block_size;
			if (!ntfs_bit_get(bmp_buf, sub_bmp_pos)) {
				ntfs_log_error("Index allocation subnode of inode(%"PRIu64
						" is in not allocated bitmap cluster\n",
						ni->mft_no);
				goto initialize_index;
			}
		}

		/* The file name must not overflow from the entry */
		if (ntfs_index_entry_inconsistent(vol, ie, COLLATION_FILE_NAME,
				ni->mft_no, NULL) < 0) {
			ntfs_log_error("Index entry(%p) of inode(%"PRIu64
					" is inconsistent\n", ie, ni->mft_no);
			goto initialize_index;
		}

		/* The last entry cannot contain a name. */
		if (ie->ie_flags & INDEX_ENTRY_END)
			break;

		if (!le16_to_cpu(ie->length))
			break;
	}

	ia_buf = ntfs_malloc(ictx->block_size);
	if (!ia_buf) {
		ntfs_log_error("Failed to allocate ia buffer\n");
		goto out;
	}

	max_vcn_bits = bmp_na->data_size << NTFSCK_BYTE_TO_BITS;
	max_vcn = ictx->ia_na->data_size >> ictx->vcn_size_bits;
	vcn_step = ictx->block_size >> ictx->vcn_size_bits;

	/* check index block and entries in INDEX_ALLOCATION */
	for (vcn = 0; vcn < max_vcn; vcn += vcn_step) {
		u32 bmp_pos;

		if (max_vcn_bits <= vcn)
			break;

		bmp_pos = (vcn << ictx->vcn_size_bits) / ictx->block_size;
		if (!ntfs_bit_get(bmp_buf, bmp_pos))
			continue;

		if (ntfs_attr_mst_pread(ictx->ia_na,
					ntfs_ib_vcn_to_pos(ictx, vcn), 1,
					ictx->block_size, ia_buf) != 1) {
			ntfs_log_error("Failed to read index blocks of inode(%"PRIu64"), %d",
					ictx->ni->mft_no, errno);
			goto initialize_index;
		}

		if (ntfs_index_block_inconsistent(vol, ictx->ia_na,
					(INDEX_ALLOCATION *)ia_buf,
					ictx->block_size, ni->mft_no, vcn)) {
			ntfs_log_error("Index block of inode(%"PRIu64" is inconsistent\n",
					ni->mft_no);
			goto initialize_index;
		}

		/* check index entries in a INDEX_ALLOCATION block */
		ia = (INDEX_ALLOCATION *)ia_buf;
		index_end = (u8 *)ia + ictx->block_size;
		ie = (INDEX_ENTRY *)((u8 *)&ia->index +
				le32_to_cpu(ia->index.entries_offset));

		for (;; ie = (INDEX_ENTRY *)((u8 *)ie + le16_to_cpu(ie->length))) {
			/* check bitmap for sub-node */
			if (ie->ie_flags & INDEX_ENTRY_NODE) {
				VCN vcn = ntfs_ie_get_vcn(ie);
				u32 sub_bmp_pos;

				sub_bmp_pos = (vcn << ictx->vcn_size_bits) / ictx->block_size;
				if (max_vcn_bits <= vcn) {
					ntfs_log_error("Subnode of inode(%"PRIu64
							"is larger than max vcn\n",
							ni->mft_no);
					goto initialize_index;
				}

				if (!ntfs_bit_get(bmp_buf, sub_bmp_pos)) {
					ntfs_log_error("Subnode of inode(%"PRIu64
							"is not set on $BITMAP\n",
							ni->mft_no);
					goto initialize_index;
				}
			}

			/* check length bound */
			if (((u8 *)ie < (u8 *)ia) ||
					((u8 *)ie + sizeof(INDEX_ENTRY_HEADER) > index_end) ||
					((u8 *)ie + le16_to_cpu(ie->length) > index_end)) {
				ntfs_log_error("Index entry out of bounds in directory inode "
						"%"PRId64"\n", ni->mft_no);
				goto initialize_index;
			}

			/* The file name must not overflow from the entry */
			if (ntfs_index_entry_inconsistent(vol, ie,
						COLLATION_FILE_NAME, ni->mft_no, NULL)) {
				ntfs_log_error("Index entry(%p) of inode(%"PRIu64
						"is inconsistent\n", ie, ni->mft_no);
				goto initialize_index;
			}

			/* The last entry cannot contain a name. */
			if (ie->ie_flags & INDEX_ENTRY_END)
				break;

			if (!le16_to_cpu(ie->length))
				break;
		}
	}

out:
	if (ir_buf)
		ntfs_free(ir_buf);

	if (bmp_buf)
		ntfs_free(bmp_buf);

	if (ia_buf)
		ntfs_free(ia_buf);

	if (bmp_na)
		ntfs_attr_close(bmp_na);

	if (ictx->ia_na) {
		ntfs_attr_close(ictx->ia_na);
		ictx->ia_na = NULL;
	}

	return;

initialize_index:

	ntfs_init_problem_ctx(&pctx, ni, NULL, NULL, NULL, ni->mrec, NULL, NULL);
	fsck_err_found();
	if (!ntfs_fix_problem(vol, PR_DIR_IDX_INITIALIZE, &pctx))
		goto out;

	if (ni->mft_no == FILE_root)
		ret = ntfsck_initiaiize_root_index(ni, ictx);
	else
		ret = ntfsck_initialize_index_attr(ni);

	if (ret)
		ntfs_log_perror("Failed to initialize index attributes of inode(%"PRIu64")\n",
				ni->mft_no);
	else
		fsck_err_fixed();

	ntfs_log_info("inode(%"PRIu64") index is initialized\n", ni->mft_no);

	goto out;
}

static int ntfsck_remove_index(ntfs_inode *parent_ni, ntfs_inode *ni)
{
	ntfs_attr_search_ctx *actx;
	ntfs_index_context *ictx;
	FILE_NAME_ATTR *fn;

	actx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!actx) {
		ntfs_log_perror("Failed to get search ctx of inode(%"PRIu64") "
				"in removing index.\n", ni->mft_no);
		return STATUS_ERROR;
	}

	if (ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, CASE_SENSITIVE,
			0, NULL, 0, actx)) {
		ntfs_log_perror("Failed to lookup $FN of inode(%"PRIu64") "
				"in removing index.\n", ni->mft_no);
		ntfs_attr_put_search_ctx(actx);
		return STATUS_ERROR;
	}

	fn = (FILE_NAME_ATTR *)((u8 *)actx->attr +
			le16_to_cpu(actx->attr->value_offset));

	ictx = ntfs_index_ctx_get(parent_ni, NTFS_INDEX_I30, 4);
	if (!ictx) {
		ntfs_log_perror("Failed to get index ctx of inode(%"PRIu64") "
				"in removing index.\n", parent_ni->mft_no);
		ntfs_attr_put_search_ctx(actx);
		return STATUS_ERROR;
	}

	if (ntfs_index_lookup(fn, sizeof(FILE_NAME_ATTR), ictx)) {
		ntfs_log_error("Failed to find index entry of inode(%"PRIu64").\n",
				parent_ni->mft_no);
		ntfs_attr_put_search_ctx(actx);
		ntfs_index_ctx_put(ictx);
		return STATUS_ERROR;
	}

	if (ntfs_index_rm(ictx)) {
		ntfs_log_error("Failed to remove index entry of inode(%"PRIu64")\n",
				parent_ni->mft_no);
		ntfs_attr_put_search_ctx(actx);
		ntfs_index_ctx_put(ictx);
		return STATUS_ERROR;
	}
	ntfs_inode_mark_dirty(ictx->ni);

	ntfs_attr_put_search_ctx(actx);
	ntfs_index_ctx_put(ictx);
	return STATUS_OK;
}

static void ntfsck_check_lost_found(ntfs_volume *vol, ntfs_inode *ni)
{
	ntfs_inode *lf_ni = NULL; /* lost+found inode */
	u64 lf_mftno = (u64)-1; /* lost+found mft record number */

	/* find 'lost+found' directory in root directory */
	lf_mftno = ntfs_inode_lookup_by_mbsname(ni, FILENAME_LOST_FOUND);
	if (lf_mftno == (u64)-1) {
		/* create 'lost+found' directory */
create_lf:
		if (!NVolReadOnly(vol)) {
			ntfschar *ucs_name = (ntfschar *)NULL;
			int ucs_namelen;

			ucs_namelen = ntfs_mbstoucs(FILENAME_LOST_FOUND, &ucs_name);
			if (ucs_namelen != -1) {
				lf_ni = ntfs_create(ni, 0, ucs_name, ucs_namelen, S_IFDIR);
				if (!lf_ni) {
					free(ucs_name);
					return;
				}

				ntfs_log_debug("%s(%"PRIu64") created\n", FILENAME_LOST_FOUND,
						lf_ni->mft_no);
			}
			free(ucs_name);
		}
	} else {
		lf_ni = ntfsck_open_inode(vol, lf_mftno);
		if (!lf_ni)
			ntfs_log_verbose("Failed to open %s(%"PRIu64").\n",
					FILENAME_LOST_FOUND, lf_mftno);

		if (lf_ni && !(lf_ni->mrec->flags & MFT_RECORD_IS_DIRECTORY)) {
			int ret = STATUS_OK;

			ntfs_log_error("%s(%"PRIu64") is not a directory, delete it\n",
					FILENAME_LOST_FOUND, lf_ni->mft_no);
			ret = ntfsck_remove_index(ni, lf_ni);
			if (!ret) {
				ntfsck_free_mft_records(vol, lf_ni);
				goto create_lf;
			}

			ntfs_log_error("Failed to remove index of %s(%"PRIu64")\n",
					FILENAME_LOST_FOUND, lf_ni->mft_no);
			ntfsck_close_inode(lf_ni);
			lf_ni = NULL;
		}
	}

	if (!lf_ni) {
		if (!NVolReadOnly(vol))
			ntfs_log_error("Failed to open/check '%s'\n", FILENAME_LOST_FOUND);
	} else {
		vol->lost_found = lf_ni->mft_no;

		/* FIXME: is it need to call ntfs_fix_problem()? */
		ntfsck_set_mft_record_bitmap(lf_ni, TRUE);
		ntfsck_close_inode(lf_ni);
	}
}

static ntfs_inode *ntfsck_check_root_inode(ntfs_volume *vol)
{
	ntfs_inode *ni;

	ni = ntfsck_open_inode(vol, FILE_root);
	if (!ni) {
		ntfs_log_error("Couldn't open the root directory.\n");
		goto err_out;
	}

	if (ni->attr_list) {
		if (ntfsck_check_attr_list(ni))
			goto err_out;

		if (ntfs_inode_attach_all_extents(ni))
			goto err_out;
	}

	if (ntfsck_check_inode_non_resident(ni, 1)) {
		ntfs_log_error("Failed to check non resident attribute of root directory.\n");
		exit(STATUS_ERROR);
	}

	if (ntfsck_check_directory(ni)) {
		ntfs_log_error("Failed to check root directory.\n");
		exit(STATUS_ERROR);
	}

	ntfsck_set_mft_record_bitmap(ni, FALSE);
	return ni;

err_out:
	if (ni)
		ntfsck_close_inode(ni);
	return NULL;
}

static int ntfsck_scan_index_entries_btree(ntfs_volume *vol)
{
	ntfs_inode *dir_ni;
	struct dir *dir;
	INDEX_ROOT *ir;
	INDEX_ENTRY *next;
	ntfs_attr_search_ctx *ctx = NULL;
	ntfs_index_context *ictx = NULL;
	ntfs_attr *bm_na = NULL;
	int ret;

	dir = (struct dir *)calloc(1, sizeof(struct dir));
	if (!dir) {
		ntfs_log_error("Failed to allocate for subdir.\n");
		return -1;
	}

	dir_ni = ntfsck_open_inode(vol, FILE_root);
	if (!dir_ni) {
		free(dir);
		ntfs_log_error("Failed to open root inode\n");
		return -1;
	}

	dir->mft_no = dir_ni->mft_no;
	ntfsck_close_inode(dir_ni);
	ntfs_list_add(&dir->list, &ntfs_dirs_list);

	progress_init(&prog, 0, total_cnt, 1000, pb_flags);

	while (!ntfs_list_empty(&ntfs_dirs_list)) {

		dir = ntfs_list_entry(ntfs_dirs_list.next, struct dir, list);
		dir_ni = ntfsck_open_inode(vol, dir->mft_no);
		if (!dir_ni) {
			ntfs_log_perror("Failed to open inode (%"PRIu64")\n",
					dir->mft_no);
			goto err_continue;
		}

		ctx = ntfs_attr_get_search_ctx(dir_ni, NULL);
		if (!ctx)
			goto err_continue;

		/* Find the index root attribute in the mft record. */
		if (ntfs_attr_lookup(AT_INDEX_ROOT, NTFS_INDEX_I30, 4, CASE_SENSITIVE, 0, NULL,
					0, ctx)) {
			ntfs_log_perror("Index root attribute missing in directory inode "
					"%"PRId64"", dir_ni->mft_no);
			ntfs_attr_put_search_ctx(ctx);
			goto err_continue;
		}

		ictx = ntfs_index_ctx_get(dir_ni, NTFS_INDEX_I30, 4);
		if (!ictx) {
			ntfs_attr_put_search_ctx(ctx);
			goto err_continue;
		}

		/* Get to the index root value. */
		ir = (INDEX_ROOT *)((u8 *)ctx->attr +
				le16_to_cpu(ctx->attr->value_offset));

		ictx->ir = ir;
		ictx->actx = ctx;
		ictx->parent_vcn[ictx->pindex] = VCN_INDEX_ROOT_PARENT;
		ictx->is_in_root = TRUE;
		ictx->parent_pos[ictx->pindex] = 0;

		ictx->block_size = le32_to_cpu(ir->index_block_size);
		if (ictx->block_size < NTFS_BLOCK_SIZE) {
			ntfs_log_perror("Index block size (%d) is smaller than the "
					"sector size (%d)", ictx->block_size, NTFS_BLOCK_SIZE);
			goto err_continue;
		}

		if (vol->cluster_size <= ictx->block_size)
			ictx->vcn_size_bits = vol->cluster_size_bits;
		else
			ictx->vcn_size_bits = NTFS_BLOCK_SIZE_BITS;

		ntfsck_validate_index_blocks(vol, ictx);

		/*
		 * Re-lookup index root attribute.
		 * Index root position can be updated by calling
		 * ntfsck_validate_index_blocks().
		 */
		ntfs_attr_reinit_search_ctx(ctx);
		/* Find the index root attribute in the mft record. */
		if (ntfs_attr_lookup(AT_INDEX_ROOT, NTFS_INDEX_I30, 4,
				     CASE_SENSITIVE, 0, NULL, 0, ctx)) {
			ntfs_log_perror("Index root attribute missing in directory inode "
					"%"PRId64"", dir_ni->mft_no);
			goto err_continue;
		}
		ictx->ir = ir;
		ir = (INDEX_ROOT *)((u8 *)ctx->attr +
				le16_to_cpu(ctx->attr->value_offset));

		/* The first index entry. */
		next = (INDEX_ENTRY*)((u8*)&ir->index +
				le32_to_cpu(ir->index.entries_offset));

		if (next->ie_flags & INDEX_ENTRY_NODE) {
			/* read $IA */
			ictx->ia_na = ntfs_attr_open(dir_ni, AT_INDEX_ALLOCATION,
							ictx->name, ictx->name_len);
			if (!ictx->ia_na) {
				ntfs_log_perror("Failed to open index allocation of inode "
						"%"PRIu64"", dir_ni->mft_no);
				goto err_continue;
			}

			/* read $BITMAP */
			bm_na = ntfs_attr_open(dir_ni, AT_BITMAP, NTFS_INDEX_I30, 4);
			if (!bm_na) {
				ntfs_log_perror("Failed to open bitmap of inode "
						"%"PRIu64"", dir_ni->mft_no);
				goto err_continue;
			}

			/* allocate for $IA bitmap */
			if (!dir_ni->fsck_ibm) {
				dir_ni->fsck_ibm = ntfs_calloc(bm_na->allocated_size);
				if (!dir_ni->fsck_ibm) {
					ntfs_log_perror("Failed to allocate fsck_ibm memory\n");
					goto err_continue;
				}
				dir_ni->fsck_ibm_size = bm_na->allocated_size;
			}
		}

		if (next->ie_flags == INDEX_ENTRY_END) {
			/*
			 * 48 means sizeof(INDEX_ROOT) + sizeof(INDEX_ENTRY_HEADER).
			 * If the flags of first entry is only INDEX_ENTRY_END,
			 * which means directory is empty, The value_length of
			 * resident entry should be 48. If It is bigger than
			 * this value, Try to resize it!.
			 */
			if (ctx->attr->value_length != 48) {
				problem_context_t pctx = {0, };
				pctx.ni = dir_ni;

				fsck_err_found();
				if (ntfs_fix_problem(vol, PR_DIR_EMPTY_IE_LENGTH_CORRUPTED, &pctx)) {
					ntfs_resident_attr_value_resize(ctx->mrec, ctx->attr, 48);
					fsck_err_fixed();
				}
			}
			goto next_dir;
		}

		if (next->ie_flags & INDEX_ENTRY_NODE) {
			next = ntfs_index_walk_down(next, ictx);
			if (!next)
				goto next_dir;
		}

		if (!(next->ie_flags & INDEX_ENTRY_END))
			goto check_index;

		while ((next = ntfs_index_next(next, ictx)) != NULL) {
check_index:
			if (!ntfs_fsck_mftbmp_get(vol,
					MREF(le64_to_cpu(next->indexed_file))))
				progress_update(&prog, ++checked_cnt);

			ret = ntfsck_check_index(vol, next, ictx);
			if (ret) {
				next = ictx->entry;
				if (ret < 0 || !ictx->actx || !next)
					break;
				if (!(next->ie_flags & INDEX_ENTRY_END))
					goto check_index;
			}

			/* check bitmap */
			if (bm_na && ictx->ib)
				ntfsck_set_index_bitmap(dir_ni, ictx, bm_na);
		}

next_dir:
		/* compare index allocation bitmap between disk & fsck */
		if (bm_na) {
			if (ntfsck_check_index_bitmap(dir_ni, bm_na))
				goto err_continue;
		}

err_continue:
		if (bm_na) {
			ntfs_attr_close(bm_na);
			bm_na = NULL;
		}

		if (ictx) {
			ntfs_index_ctx_put(ictx);
			ictx = NULL;
		}

		if (dir_ni && dir_ni->fsck_ibm) {
			free(dir_ni->fsck_ibm);
			dir_ni->fsck_ibm = NULL;
			dir_ni->fsck_ibm_size = 0;
		}

		ntfsck_close_inode(dir_ni);
		ntfs_list_del(&dir->list);
		free(dir);
	}

	progress_update(&prog, total_cnt);

	total_cnt -= checked_cnt;
	if (total_cnt < 0)
		total_cnt = 0;

	return 0;
}

static int ntfsck_scan_index_entries(ntfs_volume *vol)
{
	int ret;

	fsck_start_step("Check index entries in volume...");

	ret = ntfsck_scan_index_entries_btree(vol);

	fsck_end_step();
	return ret;
}

static void ntfsck_check_mft_records(ntfs_volume *vol)
{
	s64 mft_num, nr_mft_records;

	fsck_start_step("Scan orphaned MFTs candidiates...");

	// For each mft record, verify that it contains a valid file record.
	nr_mft_records = vol->mft_na->initialized_size >>
			vol->mft_record_size_bits;
	ntfs_log_verbose("Checking %"PRId64" MFT records.\n", nr_mft_records);

	progress_init(&prog, 0, nr_mft_records, 1000, pb_flags);

	/*
	 * Force to read first bitmap block to invalidate static cache
	 * array buffer.
	 */
	check_mftrec_in_use(vol, FILE_first_user, 1);
	for (mft_num = FILE_MFT; mft_num < nr_mft_records; mft_num++) {
		if (ntfs_fsck_mftbmp_get(vol, mft_num))
			continue;
		ntfsck_verify_mft_record(vol, mft_num);
		progress_update(&prog, mft_num + 1);
	}

	if (clear_mft_cnt)
		ntfs_log_info("Clear MFT bitmap count:%"PRId64"\n", clear_mft_cnt);

	fsck_end_step();
}

static int ntfsck_reset_dirty(ntfs_volume *vol)
{
	le16 flags;

	if (!(vol->flags & VOLUME_IS_DIRTY))
		return STATUS_OK;

	ntfs_log_verbose("Resetting dirty flag.\n");

	flags = vol->flags & ~VOLUME_IS_DIRTY;

	if (ntfs_volume_write_flags(vol, flags)) {
		ntfs_log_error("Error setting volume flags.\n");
		return STATUS_ERROR;
	}
	return 0;
}

static int ntfsck_replay_log(ntfs_volume *vol __attribute__((unused)))
{
	fsck_start_step("Replay logfile...");
	problem_context_t pctx = {0, };

	/*
	 * For now, Just reset logfile.
	 */
	if (ntfs_fix_problem(vol, PR_RESET_LOG_FILE, &pctx)) {
		if (ntfs_logfile_reset(vol)) {
			check_failed("ntfs logfile reset failed, errno : %d\n", errno);
			return STATUS_ERROR;
		}
	}

	fsck_end_step();
	return STATUS_OK;
}

static inline BOOL ntfsck_opened_ni_vol(s64 mft_num)
{
	BOOL is_opened = FALSE;

	switch (mft_num) {
	case FILE_MFT:
	case FILE_MFTMirr:
	case FILE_Volume:
	case FILE_Bitmap:
	case FILE_Secure:
		is_opened = TRUE;
	}

	return is_opened;
}

static ntfs_inode *ntfsck_get_opened_ni_vol(ntfs_volume *vol, s64 mft_num)
{
	ntfs_inode *ni = NULL;

	switch (mft_num) {
	case FILE_MFT:
		ni = vol->mft_ni;
		break;
	case FILE_MFTMirr:
		ni = vol->mftmirr_ni;
		break;
	case FILE_Volume:
		ni = vol->vol_ni;
		break;
	case FILE_Bitmap:
		ni = vol->lcnbmp_ni;
		break;
	case FILE_Secure:
		ni = vol->secure_ni;
	}

	return ni;
}

static int ntfsck_validate_system_file(ntfs_inode *ni)
{
	ntfs_volume *vol = ni->vol;
	problem_context_t pctx = {0, };

	pctx.ni = ni;

	switch (ni->mft_no) {
	case FILE_MFT:
	case FILE_MFTMirr:
	case FILE_LogFile:
	case FILE_Volume:
	case FILE_AttrDef:
	case FILE_Boot:
	case FILE_Secure:
	case FILE_UpCase:
	case FILE_Extend:
		ntfsck_check_inode_non_resident(ni, 1);
		break;
	case FILE_Bitmap: {
		s64 max_lcnbmp_size;

		if (ntfs_attr_map_whole_runlist(vol->lcnbmp_na)) {
			ntfs_log_perror("Failed to map runlist\n");
			return -EIO;
		}

		/* Check cluster run of $DATA attribute */
		if (ntfsck_check_runlist(vol->lcnbmp_na, 1, NULL, NULL)) {
			ntfs_log_error("Failed to check and setbit runlist. "
					"Leaving inconsistent metadata.\n");
			return -EIO;
		}

		/* Check if data size is valid. */
		max_lcnbmp_size = (vol->nr_clusters + 7) >> 3;
		ntfs_log_verbose("max_lcnbmp_size : %"PRId64", "
				"lcnbmp data_size : %"PRId64"\n",
				max_lcnbmp_size, vol->lcnbmp_na->data_size);
		if (max_lcnbmp_size > vol->lcnbmp_na->data_size) {
			u8 *zero_bm;
			s64 written;
			s64 zero_bm_size =
				max_lcnbmp_size - vol->lcnbmp_na->data_size;

			pctx.ni = vol->lcnbmp_na->ni;
			pctx.na = vol->lcnbmp_na;
			pctx.dsize = max_lcnbmp_size;
			fsck_err_found();
			if (ntfs_fix_problem(vol, PR_BITMAP_MFT_SIZE_MISMATCH, &pctx)) {
				zero_bm = ntfs_calloc(max_lcnbmp_size -
						vol->lcnbmp_na->data_size);
				if (!zero_bm) {
					ntfs_log_error("Failed to allocat zero_bm\n");
					return -ENOMEM;
				}

				written = ntfs_attr_pwrite(vol->lcnbmp_na,
						vol->lcnbmp_na->data_size,
						zero_bm_size, zero_bm);
				ntfs_free(zero_bm);
				if (written != zero_bm_size) {
					ntfs_log_error("lcn bitmap write failed, pos:%"PRId64", "
							"count:%"PRId64", written:%"PRId64"\n",
							vol->lcnbmp_na->data_size,
							zero_bm_size, written);
					return -EIO;
				}
				fsck_err_fixed();
			}
		}
		break;
	}
	}

	return 0;
}

static int ntfsck_check_system_files(ntfs_volume *vol)
{
	ntfs_inode *sys_ni, *root_ni;
	ntfs_attr_search_ctx *root_ctx, *sys_ctx;
	ntfs_index_context *ictx;
	FILE_NAME_ATTR *fn;
	s64 mft_num;
	u64 lf_mftno = (u64)-1; /* lost+found mft record number */
	int ret = STATUS_ERROR;
	int is_used;
	BOOL trivial;	/* represent system file is trivial or not */

	fsck_start_step("Check system files...");

	progress_init(&prog, 0, FILE_first_user, 1, pb_flags);

	root_ni = ntfsck_check_root_inode(vol);
	if (!root_ni) {
		ntfs_log_error("Couldn't open the root directory.\n");
		return ret;
	}

	/* find 'lost+found' directory in root directory */
	lf_mftno = ntfs_inode_lookup_by_mbsname(root_ni, FILENAME_LOST_FOUND);
	vol->lost_found = lf_mftno;	/* if not found, lf_mftno = -1 */

	root_ctx = ntfs_attr_get_search_ctx(root_ni, NULL);
	if (!root_ctx)
		goto close_inode;

	ictx = ntfs_index_ctx_get(root_ni, NTFS_INDEX_I30, 4);
	if (!ictx)
		goto put_attr_ctx;

	progress_update(&prog, 1);

	/*
	 * System MFT entries should be verified checked by ntfs_device_mount().
	 * Here just account number of clusters that is used by system MFT
	 * entries.
	 */
	for (mft_num = FILE_MFT; mft_num < FILE_first_user; mft_num++) {
		progress_update(&prog, mft_num + 2);
		if (vol->major_ver < 3 && mft_num == FILE_Extend)
			continue;

		trivial = FALSE;

		sys_ni = ntfsck_get_opened_ni_vol(vol, mft_num);
		if (!sys_ni) {
			if (mft_num == FILE_root)
				continue;

			/* check only already opened inode and reserved inode */
			if (mft_num < FILE_reserved12)
				continue;

			sys_ni = ntfsck_open_inode(vol, mft_num);
			if (!sys_ni) {
				ntfs_log_error("Failed to open system file(%"PRId64")\n",
						mft_num);
				continue;
			}
			trivial = TRUE;
		}

		is_used = utils_mftrec_in_use(vol, mft_num);
		if (is_used < 0) {
			ntfs_log_error("Can't read system file(%"PRIu64") bitmap\n",
					mft_num);
			ntfsck_close_inode(sys_ni);
			goto check_trivial;
		}

		ntfs_inode_attach_all_extents(sys_ni);
		ntfsck_set_mft_record_bitmap(sys_ni, FALSE);

		/* do not check any more about reserved inode */
		if (mft_num >= FILE_reserved12) {
			ntfsck_close_inode(sys_ni);
			continue;
		}

		/* Validate mft entry of system file */
		ret = ntfsck_validate_system_file(sys_ni);
		if (ret)
			goto check_trivial;

		sys_ctx = ntfs_attr_get_search_ctx(sys_ni, NULL);
		if (!sys_ctx) {
			ntfsck_close_inode(sys_ni);
			ret = STATUS_ERROR;
			goto put_index_ctx;
		}

		ret = ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0,
				CASE_SENSITIVE, 0, NULL, 0, sys_ctx);
		if (ret) {
			ntfs_log_error("Failed to lookup file name attribute of %"PRId64" system file\n",
					mft_num);
			ntfs_attr_put_search_ctx(sys_ctx);
			ntfsck_close_inode(sys_ni);
			goto check_trivial;
		}

		fn = (FILE_NAME_ATTR *)((u8 *)sys_ctx->attr +
				le16_to_cpu(sys_ctx->attr->value_offset));

		/*
		 * Index entries of system files must exist. Check whether
		 * the index entries for system files is in the $INDEX_ROOT
		 * of the $Root mft entry using ntfs_index_lookup().
		 */
		ret = ntfs_index_lookup(fn,
				le32_to_cpu(sys_ctx->attr->value_length), ictx);
		if (ret) {
			/* TODO: add index filename to root?? not return error */

			ntfs_log_error("There's no system file entry"
					"(%"PRId64") in root\n", mft_num);
			ntfs_attr_put_search_ctx(sys_ctx);
			ntfsck_close_inode(sys_ni);
			goto check_trivial;
		}
		ntfs_attr_put_search_ctx(sys_ctx);

		/* TODO: Validate index entry of system file */

		ntfs_index_ctx_reinit(ictx);
		if (ntfsck_opened_ni_vol(mft_num) == TRUE)
			continue;

		ntfsck_close_inode(sys_ni);
		continue;

check_trivial:
		if (trivial == FALSE) {
			ret = STATUS_ERROR;
			goto put_index_ctx;
		} else {
			continue;
		}
	}

	ret = STATUS_OK;

put_index_ctx:
	ntfs_index_ctx_put(ictx);
put_attr_ctx:
	ntfs_attr_put_search_ctx(root_ctx);
close_inode:
	ntfsck_close_inode(root_ni);

	fsck_end_step();
	return ret;
}

typedef u8 *(*get_bmp_func)(ntfs_volume *, s64);

static int ntfsck_apply_bitmap(ntfs_volume *vol, ntfs_attr *na, get_bmp_func func, int direction)
{
	s64 count, pos, total, remain;
	s64 rcnt, wcnt;
	u8 *disk_bm;
	u8 *fsck_bm;
	unsigned long i;
	unsigned long *dbml;
	unsigned long *fbml;
	problem_context_t pctx = {0, };

	if (na != vol->lcnbmp_na && na != vol->mftbmp_na)
		return STATUS_ERROR;

	disk_bm = ntfs_calloc(NTFS_BUF_SIZE);
	if (!disk_bm)
		return STATUS_ERROR;

	pos = 0;
	count = NTFS_BUF_SIZE;
	total = na->data_size;
	remain = total;

	if (total < count)
		count = total;

	ntfs_init_problem_ctx(&pctx, na->ni, na, NULL, NULL, na->ni->mrec, NULL, NULL);
	/* apply btimap(fsck OR lcnbmp) to disk */
	while (1) {
		/* read bitmap from disk */
		memset(disk_bm, 0, NTFS_BUF_SIZE);
		rcnt = ntfs_attr_pread(na, pos, count, disk_bm);
		if (rcnt == STATUS_ERROR) {
			ntfs_log_error("Couldn't get $Bitmap $DATA");
			break;
		}

		if (rcnt != count) {
			ntfs_log_error("Couldn't get $Bitmap, read count error\n");
			break;
		}

		fsck_bm = func(vol, pos);

		if (!memcmp(fsck_bm, disk_bm, count))
			goto next;

		/* ondisk lcnbmp OR fsck lcnbmp */
		for (i = 0; i < (count / sizeof(unsigned long)); i++) {
			dbml = (unsigned long *)disk_bm + i;
			fbml = (unsigned long *)fsck_bm + i;
			if (*dbml != *fbml) {
#ifdef DEBUG
				ntfs_log_info("%s bitmap(%d):\n",
						na->type == 0xb0 ? "MFT" : "LCN", direction);
				ntfs_log_info("1:difference pos(%"PRIu64":%lu:%"PRIu64
						"): %0lx:%0lx\n", pos, i,
						(pos + (i * sizeof(unsigned long))) << 3, *dbml, *fbml);
#endif
				*dbml |= *fbml;
#ifdef DEBUG
				ntfs_log_info("2:difference pos(%"PRIu64":%lu:%"PRIu64
						"): %0lx:%0lx\n\n", pos, i,
						(pos + (i * sizeof(unsigned long))) << 3, *dbml, *fbml);
#endif
			}
		}

		if (direction != 1)
			fsck_err_found();

		if (ntfs_fix_problem(vol, PR_CLUSTER_BITMAP_MISMATCH, &pctx)) {
			if (direction == 1)
				wcnt = ntfs_attr_pwrite(na, pos, count, disk_bm);
			else {
				wcnt = ntfs_attr_pwrite(na, pos, count, fsck_bm);
				fsck_err_fixed();
			}

			if (wcnt != count) {
				ntfs_log_error("Cluster bitmap write failed, "
						"pos:%"PRId64 "count:%"PRId64", writtne:%"PRId64"\n",
						pos, count, wcnt);
				free(disk_bm);
				return STATUS_ERROR;
			}
		}

next:
		pos += count;
		remain -= count;
		if (remain && remain < NTFS_BUF_SIZE)
			count = remain;

		if (!remain)
			break;
	}

	free(disk_bm);
	return STATUS_OK;
}

static int ntfsck_check_orphaned_mft(ntfs_volume *vol)
{
	struct orphan_mft *entry = NULL;
	ntfs_inode *root_ni;
	u64 cnt = 1;
	problem_context_t pctx = {0, };

	fsck_start_step("Check orphaned mft...");

	ntfsck_apply_bitmap(vol, vol->lcnbmp_na, ntfs_fsck_find_lcnbmp_block, 1);
	ntfsck_apply_bitmap(vol, vol->mftbmp_na, ntfs_fsck_find_mftbmp_block, 1);

	progress_init(&prog, 0, orphan_cnt + 1, 1000, pb_flags);

	/* check lost found directory */
	if (!vol->lost_found) {
		root_ni = ntfsck_open_inode(vol, FILE_root);
		if (!root_ni) {
			ntfs_log_error("Failed to open root inode\n");
			return STATUS_ERROR;
		}

		ntfsck_check_lost_found(vol, root_ni);
		ntfsck_close_inode(root_ni);
	}
	progress_update(&prog, cnt);

	/* check orphaned mft */
	while (!ntfs_list_empty(&oc_list_head)) {
		entry = ntfs_list_entry(oc_list_head.next, struct orphan_mft, oc_list);

		cnt++;

		pctx.inum = entry->mft_no;
		fsck_err_found();
		if (ntfs_fix_problem(vol, PR_ORPHANED_MFT_REPAIR, &pctx)) {
			if (ntfsck_add_index_entry_orphaned_file(vol, entry)) {
				/*
				 * error returned.
				 * inode is already freed and closed in that function,
				 */
				ntfs_log_error("failed to add entry(%"PRIu64") orphaned file\n",
						entry->mft_no);
				return STATUS_ERROR;
			}
			fsck_err_fixed();
			progress_update(&prog, cnt);
		} else {
			ntfs_list_del(&entry->oc_list);
			free(entry);
		}
	}

	ntfsck_apply_bitmap(vol, vol->lcnbmp_na, ntfs_fsck_find_lcnbmp_block, 0);
	ntfsck_apply_bitmap(vol, vol->mftbmp_na, ntfs_fsck_find_mftbmp_block, 0);

	fsck_end_step();
	return STATUS_OK;
}

static int _ntfsck_check_backup_boot(ntfs_volume *vol, s64 sector, u8 *buf)
{
	s64 backup_boot_pos;
	u8 spc_bits;	/* sector per cluster bits */

	spc_bits = vol->cluster_size_bits - vol->sector_size_bits;
	backup_boot_pos = sector << vol->sector_size_bits;
	if (ntfs_pread(vol->dev, backup_boot_pos, vol->sector_size, buf) !=
			vol->sector_size) {
		ntfs_log_error("Failed to read boot sector.\n");
		return STATUS_ERROR;
	}

	if (ntfs_boot_sector_is_ntfs((NTFS_BOOT_SECTOR *)buf) == FALSE)
		return STATUS_ERROR;

	ntfs_fsck_set_lcnbmp_range(vol, sector >> spc_bits, 1, 1);
	return STATUS_OK;
}

/* check boot sector backup cluster bitmap */
static int ntfsck_check_backup_boot(ntfs_volume *vol)
{
	s64 bb_sector;	/* number of backup boot sector */
	u8 spc_bits;	/* sector per cluster bits */
	u8 *bb_buf;

	spc_bits = vol->cluster_size_bits - vol->sector_size_bits;
	bb_buf = ntfs_malloc(vol->sector_size);
	if (!bb_buf)
		return -ENOMEM;

	/* check backup boot sector located in last sector (normal) */
	bb_sector = vol->nr_sectors;
	if (!_ntfsck_check_backup_boot(vol, bb_sector, bb_buf)) {
		free(bb_buf);
		return STATUS_OK;
	}
	/* check backup boot at last sector failed */

	/* check backup boot sector located in the middle of cluster (some cases) */
	bb_sector = (vol->nr_clusters / 2) << spc_bits;
	if (!_ntfsck_check_backup_boot(vol, bb_sector, bb_buf)) {
		ntfs_log_verbose("Found backup boot sector in the middle of the volume"
				"(cl_pos:%"PRId64").\n", bb_sector >> spc_bits);
		free(bb_buf);
		return STATUS_OK;
	}

	free(bb_buf);
	return STATUS_ERROR;
}

static int ntfsck_scan_mft_record(ntfs_volume *vol, s64 mft_num)
{
	ntfs_inode *ni = NULL;
	int is_used;

	is_used = check_mftrec_in_use(vol, mft_num, 0);
	if (is_used < 0) {
		ntfs_log_error("Error getting bit value for record %"PRId64".\n",
			mft_num);
		return STATUS_ERROR;
	} else if (!is_used) {
		if (mft_num < FILE_Extend) {
			ntfs_log_error("Record(%"PRId64") unused. Fixing or fail about system files.\n",
					mft_num);
		}
		return STATUS_ERROR;
	}

	ni = ntfsck_open_inode(vol, mft_num);
	if (!ni)
		return STATUS_ERROR;

	total_valid_mft++;

	if (ni->attr_list) {
		if (ntfsck_check_attr_list(ni))
			goto err_check_inode;

		if (ntfs_inode_attach_all_extents(ni))
			goto err_check_inode;
	}

	/*
	 * TODO:
	 * now, set cluster bitmap on every runlists of attributes in inode,
	 * it's heavy operation. so it's better to use fsck cluster bitmap
	 * and applying it to disk in this function
	 */
	ntfsck_update_lcn_bitmap(ni);
	ntfsck_close_inode(ni);
	return STATUS_OK;

err_check_inode:
	ntfs_log_trace("Delete orphaned candidate inode(%"PRIu64")\n", ni->mft_no);
	ntfsck_close_inode(ni);

	ntfsck_check_mft_record_unused(vol, mft_num);
	ntfs_fsck_mftbmp_clear(vol, mft_num);
	check_mftrec_in_use(vol, mft_num, 1);
	return STATUS_ERROR;
}

static void ntfsck_scan_mft_records(ntfs_volume *vol)
{
	s64 mft_num, nr_mft_records;
	problem_context_t pctx = {0, };

	fsck_start_step("Scan mft entries in volume...");

	// For each mft record, verify that it contains a valid file record.
	nr_mft_records = vol->mft_na->initialized_size >>
			vol->mft_record_size_bits;
	ntfs_log_verbose("Scanning maximum %"PRId64" MFT records.\n", nr_mft_records);

	if (!ntfs_fix_problem(vol, PR_PRE_SCAN_MFT, &pctx)) {
		total_cnt = nr_mft_records;
		fsck_end_step();
		return;
	}

	progress_init(&prog, 0, nr_mft_records, 1000, pb_flags);

	/*
	 * Force to read first bitmap block to invalidate static cache
	 * array buffer.
	 */
	for (mft_num = FILE_MFT; mft_num < nr_mft_records; mft_num++) {
		if (!ntfsck_scan_mft_record(vol, mft_num))
			total_cnt++;
		progress_update(&prog, mft_num + 1);
	}


	fsck_end_step();
}

/**
 * main - Does just what C99 claim it does.
 *
 * For more details on arguments and results, check the man page.
 */
int main(int argc, char **argv)
{
	ntfs_volume *vol = NULL;
	const char *path = NULL;
	int c, errors = 0, ret;
	unsigned long mnt_flags;
	BOOL check_dirty_only = FALSE;

	ntfs_log_set_handler(ntfs_log_handler_outerr);

	ntfs_log_set_levels(NTFS_LOG_LEVEL_INFO);
	ntfs_log_clear_levels(NTFS_LOG_LEVEL_TRACE|NTFS_LOG_LEVEL_ENTER|NTFS_LOG_LEVEL_LEAVE);
	pb_flags = NTFS_PROGBAR;
	option.verbose = 0;
	opterr = 0;
	option.flags = NTFS_MNT_FSCK | NTFS_MNT_IGNORE_HIBERFILE;

	while ((c = getopt_long(argc, argv, "aCnpqryhvV", opts, NULL)) != EOF) {
		switch (c) {
		case 'a':
		case 'p':
			if (option.flags & (NTFS_MNT_FS_NO_REPAIR |
						NTFS_MNT_FS_ASK_REPAIR |
						NTFS_MNT_FS_YES_REPAIR) ||
					check_dirty_only == TRUE) {
conflict_option:
				ntfs_log_error("\n%s: "
				"Only one of the optinos -a/-p, -C, -n, -r or -y may be specified.\n",
				NTFS_PROGS);

				exit(RETURN_USAGE_OR_SYNTAX_ERROR);
			}

			option.flags |= NTFS_MNT_FS_AUTO_REPAIR;
			break;
		case 'C':	/* exclusive with others */
			if (option.flags & (NTFS_MNT_FS_AUTO_REPAIR |
							NTFS_MNT_FS_ASK_REPAIR |
							NTFS_MNT_FS_YES_REPAIR)) {
				goto conflict_option;
			}

			option.flags &= ~NTFS_MNT_FSCK;
			option.flags |= NTFS_MNT_FS_NO_REPAIR;
			check_dirty_only = TRUE;
			break;
		case 'n':
			if (option.flags & (NTFS_MNT_FS_AUTO_REPAIR |
						NTFS_MNT_FS_ASK_REPAIR |
						NTFS_MNT_FS_YES_REPAIR) ||
					check_dirty_only == TRUE) {
				goto conflict_option;
			}

			option.flags |= NTFS_MNT_FS_NO_REPAIR | NTFS_MNT_RDONLY;
			break;
		case 'q':
			pb_flags |= ~NTFS_PROGBAR;
			break;
		case 'r':
			if (option.flags & (NTFS_MNT_FS_AUTO_REPAIR |
						NTFS_MNT_FS_NO_REPAIR |
						NTFS_MNT_FS_YES_REPAIR) ||
					check_dirty_only == TRUE) {
				goto conflict_option;
			}

			option.flags |= NTFS_MNT_FS_ASK_REPAIR;
			break;
		case 'y':
			if (option.flags & (NTFS_MNT_FS_AUTO_REPAIR |
						NTFS_MNT_FS_NO_REPAIR |
						NTFS_MNT_FS_ASK_REPAIR) ||
					check_dirty_only == TRUE) {
				goto conflict_option;
			}

			option.flags |= NTFS_MNT_FS_YES_REPAIR;
			break;
		case 'h':
			usage(0);
		case '?':
			usage(1);
			break;
		case 'v':
			option.verbose = 1;
                        ntfs_log_set_levels(NTFS_LOG_LEVEL_VERBOSE);
                        break;
		case 'V':
			version();
			break;
		default:
			ntfs_log_info("ERROR: Unknown option '%s'.\n", argv[optind - 1]);
			usage(1);
		}
	}

	/* If not set fsck repair option, set default fsck flags to ASK mode. */
	if (!(option.flags & (NTFS_MNT_FS_AUTO_REPAIR |
				NTFS_MNT_FS_NO_REPAIR |
				NTFS_MNT_FS_ASK_REPAIR |
				NTFS_MNT_FS_YES_REPAIR))) {
		option.flags |= NTFS_MNT_FS_ASK_REPAIR;
	}

	if (optind != argc - 1)
		usage(1);
	path = argv[optind];

	if (!ntfs_check_if_mounted(path, &mnt_flags)) {
		if ((mnt_flags & NTFS_MF_MOUNTED)) {
			if (!(mnt_flags & NTFS_MF_READONLY)) {
				ntfs_log_error("Refusing to operate on read-write mounted device %s.\n",
						path);
				exit(1);
			}

			if (option.flags != (NTFS_MNT_FS_NO_REPAIR | NTFS_MNT_RDONLY)) {
				ntfs_log_error("Refusing to change filesystem on read mounted device %s.\n",
						path);
				exit(1);
			}
		}
	} else
		ntfs_log_perror("Failed to determine whether %s is mounted",
				path);

	vol = ntfs_fsck_mount(path, option.flags);
	if (!vol) {
		/*
		 * Defined the error code RETURN_FS_NOT_SUPPORT(64),
		 * but not use now, just return RETURN_OPERATIONAL_ERROR
		 * like ext4 filesystem.
		 */
		if (errno == EOPNOTSUPP) {
			ntfs_log_error("The superblock does not describe a valid NTFS.\n");
			exit(RETURN_OPERATIONAL_ERROR);
		}

		if (check_dirty_only == TRUE) {
			ntfs_log_info("Check volume: Volume mount failed, Consider volume is dirty.\n");
			exit(RETURN_FS_ERRORS_LEFT_UNCORRECTED);
		} else {
			ntfs_log_error("ntfsck mount failed, errno : %d\n", errno);
			fsck_err_found();
		}

		goto err_out;
	}

	/* Just return the volume dirty flags when '-C' option is specified. */
	if (check_dirty_only == TRUE) {
		if (vol->flags & VOLUME_IS_DIRTY) {
			ntfs_log_info("Check volume: Volume is dirty.\n");
			exit(RETURN_FS_ERRORS_LEFT_UNCORRECTED);
		} else {
			ntfs_log_warning("Check volume: Volume is clean.\n");
			exit(RETURN_FS_NO_ERRORS);
		}
	}

	ntfsck_check_backup_boot(vol);

	/* pass 1 */
	ntfsck_scan_mft_records(vol);

	/* pass 2 */
	if (ntfsck_check_system_files(vol))
		goto err_out;

	if (ntfsck_replay_log(vol))
		goto err_out;

	mrec_temp_buf = ntfs_malloc(vol->sector_size);
	if (!mrec_temp_buf) {
		ntfs_log_perror("Couldn't allocate mrec_temp_buf buffer");
		goto err_out;
	}

	/* pass 3 */
	if (ntfsck_scan_index_entries(vol)) {
		ntfs_log_error("Stop processing fsck due to critical problems\n");
		goto err_out;
	}

	/* pass 4 */
	/* apply mft bitmap & cluster bitmap to disk */
	ntfsck_check_mft_records(vol);

	/* pass 5 */
	ntfsck_check_orphaned_mft(vol);

	free(mrec_temp_buf);

err_out:
	errors = fsck_errors - fsck_fixes;
	if (errors) {
		ntfs_log_info("%d errors left (errors:%d, fixed:%d)\n",
				errors, fsck_errors, fsck_fixes);
		ret = RETURN_FS_ERRORS_LEFT_UNCORRECTED;
	} else {
		ntfs_log_info("Clean, No errors found or left (errors:%d, fixed:%d)\n",
				fsck_errors, fsck_fixes);
		if (fsck_fixes)
			ret = RETURN_FS_ERRORS_CORRECTED;
		else
			ret = RETURN_FS_NO_ERRORS;
	}

	if (!errors && vol)
		ntfsck_reset_dirty(vol);

	if (vol)
		ntfs_fsck_umount(vol);

	return ret;
}
