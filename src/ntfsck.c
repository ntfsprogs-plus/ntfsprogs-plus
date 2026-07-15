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
#include <mft.h>
#include <misc.h>
#include <mst.h>
#include <unistr.h>
#include <getopt.h>

#include "cluster.h"
#include "utils.h"
#include "list.h"
#include "dir.h"
#include "lcnalloc.h"
#include "logfile.h"
#include "reparse.h"
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

/*
 * Salvage-aggressive mode. When set, ntfsck is allowed to take destructive
 * recovery actions that trade unrecoverable data for a mountable volume - for
 * example replacing a compression unit that will not decompress with a sparse
 * hole.
 */
static BOOL opt_salvage;

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
s64 total_inuse_mft;	/* MFT records the bitmap marks in-use */
s64 fsck_scan_eio;	/* MFT records that failed to read/open with EIO */
/* $LogFile was reset this run: stale LSNs must be zeroed (see parse #1) */
static BOOL logfile_was_reset;

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
		"-S, --salvage		aggressive salvage (may discard unrecoverable data)\n"
		"-D, --scratch-dir DIR	back the cluster bitmap with a scratch file under DIR\n"
		"			(use a filesystem other than the volume being checked)\n"
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
	{"salvage",		no_argument,		NULL,	'S' },
	{"scratch-dir",		required_argument,	NULL,	'D' },
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
static int ntfsck_check_orphan_inode(ntfs_inode *parent_ni, ntfs_inode *ni);
static int ntfsck_check_file_name_attr(ntfs_inode *ni, FILE_NAME_ATTR *ie_fn,
		ntfs_index_context *ictx);
static int32_t ntfsck_check_file_type(ntfs_inode *ni, ntfs_index_context *ictx,
		FILE_NAME_ATTR *ie_fn);
static int ntfsck_check_orphan_file_type(ntfs_inode *ni, ntfs_index_context *ictx,
		FILE_NAME_ATTR *ie_fn);
static int ntfsck_check_extend_inode(ntfs_inode *ni);
static int ntfsck_check_view_index(ntfs_inode *ni);
static int ntfsck_check_system_inode_detail(ntfs_inode *ni);
static int ntfsck_validate_named_index(ntfs_inode *ni,
		ntfschar *name, u32 name_len);
static int ntfsck_initialize_named_index_attr(ntfs_inode *ni,
		ntfschar *name, u32 name_len);
static int ntfsck_initialize_index_attr(ntfs_inode *ni);
static int ntfsck_set_mft_record_bitmap(ntfs_inode *ni, BOOL ondisk_mft_bmp_set);
static int ntfsck_check_attr_list(ntfs_inode *ni);
static inline BOOL ntfsck_opened_ni_vol(s64 mft_num);
static ntfs_inode *ntfsck_get_opened_ni_vol(ntfs_volume *vol, s64 mft_num);
static int ntfsck_validate_system_file(ntfs_inode *ni);
static int ntfsck_check_inode_non_resident(ntfs_inode *ni, int set_bit);
static void ntfsck_check_mft_records(ntfs_volume *vol);
static void ntfsck_check_mft_record_unused(ntfs_volume *vol, s64 mft_num);
static void ntfsck_delete_orphaned_mft(ntfs_volume *vol, u64 mft_no);
static int ntfsck_update_runlist(ntfs_attr *na, s64 new_size, ntfs_attr_search_ctx *actx);
static int ntfsck_check_attr_runlist(ntfs_attr *na, struct rl_size *rls,
		BOOL *need_fix, int set_bit);
static int __ntfsck_check_non_resident_attr(ntfs_attr *na,
		ntfs_attr_search_ctx *actx, struct rl_size *rls, int set_bit);
static ntfs_inode *ntfsck_open_inode_after_raw_mft_check(ntfs_volume *vol,
		u64 mft_no, BOOL expect_in_use);

#define ntfsck_delete_mft	ntfsck_delete_orphaned_mft

static ntfs_inode *ntfsck_open_inode(ntfs_volume *vol, u64 mft_no)
{
	ntfs_inode *ni;

	ni = ntfsck_get_opened_ni_vol(vol, mft_no);
	if (!ni)
		ni = ntfs_inode_open(vol, mft_no);
	return ni;
}

static s8 ntfsck_expected_clusters_per_index_block(const ntfs_volume *vol,
		u32 block_size)
{
	if (vol->cluster_size <= block_size)
		return block_size >> vol->cluster_size_bits;
	return block_size >> NTFS_BLOCK_SIZE_BITS;
}

static BOOL ntfsck_get_named_index_defaults(u64 mft_no,
		const ntfschar *name, u32 name_len, ATTR_TYPES *type,
		COLLATION_RULES *collation_rule)
{
	if (!name || !name_len || !type || !collation_rule)
		return FALSE;

	if (name_len == 4 &&
			!memcmp(name, NTFS_INDEX_I30, 4 * sizeof(ntfschar))) {
		*type = AT_FILE_NAME;
		*collation_rule = COLLATION_FILE_NAME;
		return TRUE;
	}
	if (name_len == 4 &&
			!memcmp(name, NTFS_INDEX_SII, 4 * sizeof(ntfschar))) {
		*type = AT_UNUSED;
		*collation_rule = COLLATION_NTOFS_ULONG;
		return TRUE;
	}
	if (name_len == 4 &&
			!memcmp(name, NTFS_INDEX_SDH, 4 * sizeof(ntfschar))) {
		*type = AT_UNUSED;
		*collation_rule = COLLATION_NTOFS_SECURITY_HASH;
		return TRUE;
	}
	if (name_len == 2 &&
			!memcmp(name, NTFS_INDEX_Q, 2 * sizeof(ntfschar))) {
		*type = AT_UNUSED;
		*collation_rule = COLLATION_NTOFS_ULONG;
		return TRUE;
	}
	if (name_len == 2 &&
			!memcmp(name, NTFS_INDEX_R, 2 * sizeof(ntfschar))) {
		*type = AT_UNUSED;
		*collation_rule = COLLATION_NTOFS_ULONGS;
		return TRUE;
	}
	if (name_len == 2 &&
			!memcmp(name, NTFS_INDEX_O, 2 * sizeof(ntfschar))) {
		*type = AT_UNUSED;
		if (mft_no == 24) {
			*collation_rule = COLLATION_NTOFS_SID;
			return TRUE;
		}
		if (mft_no == 25) {
			*collation_rule = COLLATION_NTOFS_ULONGS;
			return TRUE;
		}
	}

	return FALSE;
}

static u32 ntfsck_index_used_length(INDEX_HEADER *ih, const u8 *index_end,
		BOOL *has_subnodes)
{
	u8 *entry;
	BOOL found_subnode = FALSE;

	if (!ih || !index_end)
		return 0;

	entry = (u8 *)ih + le32_to_cpu(ih->entries_offset);
	if (le32_to_cpu(ih->entries_offset) < sizeof(INDEX_HEADER) ||
			(le32_to_cpu(ih->entries_offset) & 7) || entry >= index_end)
		return 0;

	for (;;) {
		INDEX_ENTRY *ie = (INDEX_ENTRY *)entry;
		u16 length;

		if (entry + sizeof(INDEX_ENTRY_HEADER) > index_end)
			return 0;
		length = le16_to_cpu(ie->length);
		if (length < sizeof(INDEX_ENTRY_HEADER) || (length & 7) ||
				entry + length > index_end)
			return 0;
		if (ie->ie_flags & INDEX_ENTRY_NODE)
			found_subnode = TRUE;
		entry += length;
		if (ie->ie_flags & INDEX_ENTRY_END)
			break;
	}

	if (has_subnodes)
		*has_subnodes = found_subnode;
	return entry - (u8 *)ih;
}

static BOOL ntfsck_repair_index_root_fields(ntfs_volume *vol, u64 mft_no,
		ATTR_RECORD *attr)
{
	INDEX_ROOT *ir;
	ATTR_TYPES expected_type = AT_UNUSED;
	COLLATION_RULES expected_collation = COLLATION_BINARY;
	u32 expected_block_size;
	u32 payload_size;
	u32 used_length;
	s8 expected_clusters_per_index_block;
	INDEX_HEADER_FLAGS expected_flags;
	BOOL has_subnodes = FALSE;
	BOOL changed = FALSE;
	BOOL know_defaults;
	const ntfschar *name = NULL;

	if (!vol || !attr || attr->type != AT_INDEX_ROOT || attr->non_resident)
		return FALSE;
	if (le32_to_cpu(attr->value_length) < sizeof(INDEX_ROOT) +
			sizeof(INDEX_ENTRY_HEADER))
		return FALSE;

	ir = (INDEX_ROOT *)((u8 *)attr + le16_to_cpu(attr->value_offset));
	payload_size = le32_to_cpu(attr->value_length) - offsetof(INDEX_ROOT, index);
	payload_size &= ~7U;
	if (payload_size < sizeof(INDEX_HEADER) + sizeof(INDEX_ENTRY_HEADER))
		return FALSE;

	if (attr->name_length)
		name = (const ntfschar *)((const u8 *)attr +
				le16_to_cpu(attr->name_offset));
	know_defaults = ntfsck_get_named_index_defaults(mft_no, name,
			attr->name_length, &expected_type, &expected_collation);
	if (know_defaults && ir->type != expected_type) {
		ir->type = expected_type;
		changed = TRUE;
	}
	if (know_defaults && ir->collation_rule != expected_collation) {
		ir->collation_rule = expected_collation;
		changed = TRUE;
	}

	expected_block_size = vol->indx_record_size;
	if (le32_to_cpu(ir->index_block_size) != expected_block_size) {
		ir->index_block_size = cpu_to_le32(expected_block_size);
		changed = TRUE;
	}
	expected_clusters_per_index_block =
		ntfsck_expected_clusters_per_index_block(vol, expected_block_size);
	if (ir->clusters_per_index_block != expected_clusters_per_index_block) {
		ir->clusters_per_index_block = expected_clusters_per_index_block;
		changed = TRUE;
	}
	if (ir->reserved[0] || ir->reserved[1] || ir->reserved[2]) {
		memset(ir->reserved, 0, sizeof(ir->reserved));
		changed = TRUE;
	}
	/*
	 * An INDEX_ROOT has no update sequence array, so the entries may start right
	 * after the header, but as in an index block a writer is allowed to leave
	 * slack. Only rewrite an offset that cannot be walked -- relocating a valid
	 * one would send the walk into that slack.
	 */
	if (le32_to_cpu(ir->index.entries_offset) < sizeof(INDEX_HEADER) ||
			(le32_to_cpu(ir->index.entries_offset) & 7) ||
			le32_to_cpu(ir->index.entries_offset) >= payload_size) {
		ir->index.entries_offset = const_cpu_to_le32(sizeof(INDEX_HEADER));
		changed = TRUE;
	}

	used_length = ntfsck_index_used_length(&ir->index,
			(u8 *)&ir->index + payload_size, &has_subnodes);
	if (!used_length)
		used_length = payload_size;
	if (le32_to_cpu(ir->index.index_length) != used_length) {
		ir->index.index_length = cpu_to_le32(used_length);
		changed = TRUE;
	}
	if (le32_to_cpu(ir->index.allocated_size) != payload_size) {
		ir->index.allocated_size = cpu_to_le32(payload_size);
		changed = TRUE;
	}
	/*
	 * LARGE_INDEX describes the entries of this very header -- whether they
	 * carry sub-node pointers -- not the attributes of the inode holding it.
	 * The two are not equivalent: ntfs_ir_leafify() clears the flag when the
	 * root's last sub-node pointer goes away, yet leaves the now empty
	 * $INDEX_ALLOCATION in place, and that is how $Extend/$Deleted ships.
	 *
	 * Deriving the flag from the presence of an $INDEX_ALLOCATION therefore
	 * calls every such directory corrupt, and the rewrite is not even benign:
	 * ntfs_ir_reparent() skips ntfs_ia_add() on a root that is not
	 * SMALL_INDEX, so a leaf root left claiming LARGE_INDEX reaches
	 * ntfs_ib_write() with icx->ia_na still NULL -- the lookup only opens it
	 * when it descends through a sub-node.
	 */
	expected_flags = has_subnodes ? LARGE_INDEX : SMALL_INDEX;
	if (ir->index.ih_flags != expected_flags) {
		ir->index.ih_flags = expected_flags;
		changed = TRUE;
	}
	if (ir->index.reserved[0] || ir->index.reserved[1] ||
			ir->index.reserved[2]) {
		memset(ir->index.reserved, 0, sizeof(ir->index.reserved));
		changed = TRUE;
	}

	return changed;
}

/*
 * Whether ntfsck_repair_index_root_fields() would change @attr. When @apply
 * is false it must not: -n has to report the corruption without touching the
 * record, and mutating the in-memory copy would also hide the fields from
 * every later check that reads the same record.
 */
static BOOL ntfsck_index_root_fields_changed(ntfs_volume *vol, u64 mft_no,
		ATTR_RECORD *attr, BOOL apply)
{
	ATTR_RECORD *copy;
	u32 len;
	BOOL changed;

	if (apply)
		return ntfsck_repair_index_root_fields(vol, mft_no, attr);

	if (!attr || attr->type != AT_INDEX_ROOT || attr->non_resident)
		return FALSE;
	len = le32_to_cpu(attr->length);
	copy = ntfs_malloc(len);
	if (!copy)
		return FALSE;
	memcpy(copy, attr, len);
	changed = ntfsck_repair_index_root_fields(vol, mft_no, copy);
	free(copy);
	return changed;
}

static BOOL ntfsck_repair_raw_index_root_fields(ntfs_volume *vol, u64 mft_no,
		MFT_RECORD *mrec)
{
	ATTR_RECORD *attr;
	u8 *record_end;
	BOOL apply;
	BOOL dirty = FALSE;

	if (!vol || !mrec || !NVolFsck(vol))
		return FALSE;
	apply = !NVolFsNoRepair(vol);

	/*
	 * An extent record only carries overflow attributes of its base inode, so
	 * @mft_no names the extent rather than the inode the INDEX_ROOT belongs to.
	 * The per-inode defaults below would then be looked up under the wrong
	 * number.
	 */
	if (MREF_LE(mrec->base_mft_record) != 0)
		return FALSE;

	record_end = (u8 *)mrec + le32_to_cpu(mrec->bytes_in_use);
	attr = (ATTR_RECORD *)((u8 *)mrec + le16_to_cpu(mrec->attrs_offset));
	while ((u8 *)attr + sizeof(ATTR_RECORD) <= record_end &&
			attr->type != AT_END) {
		u32 attr_len = le32_to_cpu(attr->length);

		if (!attr_len || (u8 *)attr + attr_len > record_end)
			break;
		if (attr->type != AT_INDEX_ROOT || attr->non_resident)
			goto next;
		if (ntfsck_index_root_fields_changed(vol, mft_no, attr, apply)) {
			ntfs_log_error("Inode(%llu): INDEX_ROOT header fields are corrupted.%s\n",
					(unsigned long long)mft_no,
					apply ? " Fixed." : "");
			if (apply)
				dirty = TRUE;
			else
				fsck_err_found();
		}
next:
		attr = (ATTR_RECORD *)((u8 *)attr + attr_len);
	}

	return dirty;
}

static int ntfsck_repair_named_index_root(ntfs_inode *ni,
		ntfs_attr_search_ctx *ctx)
{
	ntfs_volume *vol;
	ntfs_inode *hosting;
	BOOL apply;

	if (!ni || !ctx || !ctx->attr)
		return STATUS_ERROR;

	vol = ni->vol;
	if (!NVolFsck(vol))
		return STATUS_OK;
	apply = !NVolFsNoRepair(vol);

	if (!ntfsck_index_root_fields_changed(vol, ni->mft_no, ctx->attr, apply))
		return STATUS_OK;

	fsck_err_found();
	if (!apply) {
		ntfs_log_error("Inode(%llu): INDEX_ROOT header fields are corrupted.\n",
				(unsigned long long)ni->mft_no);
		return STATUS_OK;
	}
	ntfs_log_error("Inode(%llu): INDEX_ROOT header fields are corrupted. Fixed.\n",
			(unsigned long long)ni->mft_no);
	/*
	 * INDEX_ROOT can be relocated into an extent MFT record via the attribute
	 * list, in which case ctx->mrec is that extent record, not the base one.
	 * Persist the record that actually holds the attribute (ctx->ntfs_ino);
	 * writing ctx->mrec back to the base slot would stamp the base record with
	 * the extent's contents and record number.
	 */
	hosting = ctx->ntfs_ino ? ctx->ntfs_ino : ni;
	if (ntfs_mft_record_write(vol, hosting->mft_no, ctx->mrec))
		return STATUS_ERROR;
	fsck_err_fixed();

	return STATUS_OK;
}

static int ntfsck_read_index_block(ntfs_index_context *ictx, VCN vcn,
		INDEX_BLOCK *ib, BOOL *mst_salvaged)
{
	s64 bytes;
	u16 expected_usa_count;

	if (mst_salvaged)
		*mst_salvaged = FALSE;

	if (ntfs_attr_mst_pread(ictx->ia_na, ntfs_ib_vcn_to_pos(ictx, vcn), 1,
				ictx->block_size, (u8 *)ib) == 1)
		return STATUS_OK;
	if (!NVolFsck(ictx->ni->vol) || NVolFsNoRepair(ictx->ni->vol))
		return STATUS_ERROR;

	bytes = ntfs_attr_pread(ictx->ia_na, ntfs_ib_vcn_to_pos(ictx, vcn),
			ictx->block_size, ib);
	if (bytes != ictx->block_size)
		return STATUS_ERROR;

	expected_usa_count = (ictx->block_size >= NTFS_BLOCK_SIZE) ?
		ictx->block_size / NTFS_BLOCK_SIZE + 1 : 1;
	if (le16_to_cpu(ib->usa_ofs) != sizeof(INDEX_BLOCK))
		ib->usa_ofs = const_cpu_to_le16(sizeof(INDEX_BLOCK));
	if (le16_to_cpu(ib->usa_count) != expected_usa_count)
		ib->usa_count = cpu_to_le16(expected_usa_count);
	if (ntfs_mst_post_read_fixup((NTFS_RECORD *)ib, ictx->block_size))
		return STATUS_ERROR;

	if (mst_salvaged)
		*mst_salvaged = TRUE;
	return STATUS_OK;
}

static int ntfsck_repair_index_block(ntfs_index_context *ictx, VCN vcn,
		INDEX_BLOCK *ib, BOOL mst_salvaged)
{
	u16 expected_usa_count;
	u32 min_entries_offset;
	u32 entries_offset;
	u32 expected_allocated_size;
	u32 used_length;
	BOOL has_subnodes = FALSE;
	BOOL changed = mst_salvaged;
	INDEX_HEADER_FLAGS expected_flags;

	if (!ictx || !ib)
		return STATUS_ERROR;
	if (!NVolFsck(ictx->ni->vol) || NVolFsNoRepair(ictx->ni->vol))
		return STATUS_OK;

	expected_usa_count = (ictx->block_size >= NTFS_BLOCK_SIZE) ?
		ictx->block_size / NTFS_BLOCK_SIZE + 1 : 1;
	min_entries_offset = (sizeof(INDEX_HEADER) +
			expected_usa_count * 2 + 7) & ~7;
	expected_allocated_size = ictx->block_size -
		(sizeof(INDEX_BLOCK) - sizeof(INDEX_HEADER));

	if (!ntfs_is_indx_record(ib->magic)) {
		ib->magic = magic_INDX;
		changed = TRUE;
	}
	if (le16_to_cpu(ib->usa_ofs) != sizeof(INDEX_BLOCK)) {
		ib->usa_ofs = const_cpu_to_le16(sizeof(INDEX_BLOCK));
		changed = TRUE;
	}
	if (le16_to_cpu(ib->usa_count) != expected_usa_count) {
		ib->usa_count = cpu_to_le16(expected_usa_count);
		changed = TRUE;
	}
	if (sle64_to_cpu(ib->index_block_vcn) != vcn) {
		ib->index_block_vcn = cpu_to_sle64(vcn);
		changed = TRUE;
	}
	/*
	 * entries_offset is measured from the start of the INDEX_HEADER, and the
	 * update sequence array sits between that header and the first entry. All
	 * the format requires is that the entries begin past the USA, stay 8-byte
	 * aligned and fit inside the block; a writer may leave more slack than the
	 * minimum, and they do -- mkntfs starts the entries right after the USA
	 * where the in-kernel driver pads further out.
	 */
	entries_offset = le32_to_cpu(ib->index.entries_offset);
	if (entries_offset < min_entries_offset || (entries_offset & 7) ||
			entries_offset >= expected_allocated_size) {
		ib->index.entries_offset = cpu_to_le32(min_entries_offset);
		changed = TRUE;
	}
	if (le32_to_cpu(ib->index.allocated_size) != expected_allocated_size) {
		ib->index.allocated_size = cpu_to_le32(expected_allocated_size);
		changed = TRUE;
	}
	if (ib->index.reserved[0] || ib->index.reserved[1] ||
			ib->index.reserved[2]) {
		memset(ib->index.reserved, 0, sizeof(ib->index.reserved));
		changed = TRUE;
	}

	used_length = ntfsck_index_used_length(&ib->index,
			(u8 *)&ib->index + expected_allocated_size, &has_subnodes);
	/*
	 * The entry chain does not tile the block, so nothing here can be repaired
	 * in place. Report the failure instead of returning a header we may have
	 * already rewritten: the caller then rebuilds the index, whereas walking
	 * this block would just rediscover the damage on every repair round without
	 * ever writing a correction back.
	 */
	if (!used_length)
		return STATUS_ERROR;
	if (le32_to_cpu(ib->index.index_length) != used_length) {
		ib->index.index_length = cpu_to_le32(used_length);
		changed = TRUE;
	}
	expected_flags = has_subnodes ? INDEX_NODE : LEAF_NODE;
	if (ib->index.ih_flags != expected_flags) {
		ib->index.ih_flags = expected_flags;
		changed = TRUE;
	}

	if (!changed)
		return STATUS_OK;

	fsck_err_found();
	ntfs_log_error("Inode(%llu): INDEX_ALLOCATION block VCN(%lld) header fields are corrupted. Fixed.\n",
			(unsigned long long)ictx->ni->mft_no, (long long)vcn);
	if (ntfs_ib_write(ictx, ib))
		return STATUS_ERROR;
	fsck_err_fixed();

	return STATUS_OK;
}

/*
 * Last-chance read of an MFT record whose multi sector transfer fixup
 * failed (the reader stamps such a record with the BAAD magic). Two
 * on-disk states are recoverable:
 *
 * A FILE record whose fixup header (usa_ofs/usa_count) is corrupted even
 * though every protected sector survived; ntfsck_read_index_block()
 * already salvages index blocks the same way. Reread the record without
 * deprotection, restore the canonical fixup header from the volume
 * geometry (the values ntfs_mft_record_layout() writes) and retry the
 * fixup: it still verifies every sector tail against the update sequence
 * number, so a genuinely torn write keeps failing, silently, and the
 * record is left to the discard path.
 *
 * A record carrying the BAAD magic on disk, which a Windows driver
 * stamps once it detects a torn multi sector write. The update sequence
 * array in the first sector still holds the bytes every sector tail is
 * supposed to carry, so the intended content can be reassembled by
 * deprotecting without tail verification; sectors the torn write never
 * reached simply keep their older content. Whether the reassembled
 * record is coherent cannot be decided here: it is handed to
 * ntfs_mft_record_check() and the regular inode checks like any other
 * record, and what they cannot repair still ends up discarded. chkdsk
 * deletes such a record outright, so this can only recover more.
 *
 * The problem is only reported once the record is known to be
 * salvageable, which keeps the -n error count equal to what a repair run
 * fixes. A salvaged record is written straight back, which re-protects
 * it with the restored header.
 */
static int ntfsck_salvage_mft_record(ntfs_volume *vol, u64 mft_no,
		MFT_RECORD *mrec)
{
	u16 expected_usa_ofs;
	u16 expected_usa_count;
	problem_code_t code;
	problem_context_t pctx = {0, };

	if (!NVolFsck(vol) || !vol->mft_na)
		return STATUS_ERROR;

	/* Refuse non-allocated records, as ntfs_mft_records_read() does. */
	if ((s64)mft_no + 1 > vol->mft_na->initialized_size >>
			vol->mft_record_size_bits)
		return STATUS_ERROR;

	if (ntfs_attr_pread(vol->mft_na,
				(s64)mft_no << vol->mft_record_size_bits,
				vol->mft_record_size, mrec) !=
			vol->mft_record_size)
		return STATUS_ERROR;

	if (vol->major_ver < 3 || (vol->major_ver == 3 && !vol->minor_ver))
		expected_usa_ofs = (sizeof(MFT_RECORD_OLD) + 1) & ~1;
	else
		expected_usa_ofs = (sizeof(MFT_RECORD) + 1) & ~1;
	expected_usa_count = (vol->mft_record_size >= NTFS_BLOCK_SIZE) ?
		vol->mft_record_size / NTFS_BLOCK_SIZE + 1 : 1;

	if (ntfs_is_file_record(mrec->magic)) {
		/* A canonical header means the sectors themselves are torn. */
		if (le16_to_cpu(mrec->usa_ofs) == expected_usa_ofs &&
				le16_to_cpu(mrec->usa_count) ==
				expected_usa_count)
			return STATUS_ERROR;

		mrec->usa_ofs = cpu_to_le16(expected_usa_ofs);
		mrec->usa_count = cpu_to_le16(expected_usa_count);

		if (ntfs_mst_post_read_fixup_warn((NTFS_RECORD *)mrec,
					vol->mft_record_size, FALSE))
			return STATUS_ERROR;

		code = PR_MFT_USA_CORRUPTED;
	} else if (mrec->magic == magic_BAAD) {
		u16 *usa, *tail;
		int i;

		/* With the fixup header gone too there is nothing to trust. */
		if (le16_to_cpu(mrec->usa_ofs) != expected_usa_ofs ||
				le16_to_cpu(mrec->usa_count) !=
				expected_usa_count)
			return STATUS_ERROR;

		/* Deprotect without tail verification. */
		usa = (u16 *)((u8 *)mrec + expected_usa_ofs);
		tail = (u16 *)((u8 *)mrec + NTFS_BLOCK_SIZE) - 1;
		for (i = 1; i < expected_usa_count; i++) {
			*tail = usa[i];
			tail += NTFS_BLOCK_SIZE / sizeof(u16);
		}
		mrec->magic = magic_FILE;

		code = PR_MFT_BAAD_RECORD;
	} else
		return STATUS_ERROR;

	pctx.inum = mft_no;
	fsck_err_found();
	if (!ntfs_fix_problem(vol, code, &pctx))
		return STATUS_ERROR;

	if (ntfs_mft_record_write(vol, mft_no, mrec))
		return STATUS_ERROR;

	fsck_err_fixed();
	return STATUS_OK;
}

static ntfs_inode *ntfsck_open_inode_after_raw_mft_check(ntfs_volume *vol,
		u64 mft_no, BOOL expect_in_use)
{
	MFT_RECORD *mrec;
	ntfs_inode *ni = NULL;
	BOOL dirty = FALSE;
	BOOL readable;

	mrec = ntfs_malloc(vol->mft_record_size);
	if (!mrec)
		return NULL;

	/* A failed fixup does not fail the read: it leaves BAAD magic. */
	readable = !ntfs_mft_record_read(vol, mft_no, mrec);
	if (!readable || mrec->magic == magic_BAAD)
		readable = !ntfsck_salvage_mft_record(vol, mft_no, mrec);

	if (readable && !ntfs_mft_record_check(vol, mft_no, mrec)) {
		dirty = ntfsck_repair_raw_index_root_fields(vol, mft_no, mrec);
		if (expect_in_use && NVolFsck(vol) && !NVolFsNoRepair(vol) &&
				!(mrec->flags & MFT_RECORD_IN_USE)) {
			ntfs_log_error("Inode(%llu): MFT in-use flag is cleared but the MFT bitmap marks it allocated. Fixed.\n",
					(unsigned long long)mft_no);
			mrec->flags |= MFT_RECORD_IN_USE;
			dirty = TRUE;
		}
		if (dirty) {
			fsck_err_found();
			if (ntfs_mft_record_write(vol, mft_no, mrec))
				goto out;
			fsck_err_fixed();
		}
		ni = ntfsck_open_inode(vol, mft_no);
	}

	out:
	ntfs_free(mrec);
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

static VCN ntfsck_runlist_end_vcn(const runlist *rl)
{
	int index = 0;

	if (!rl)
		return 0;

	while (rl[index].length)
		index++;

	return rl[index].vcn;
}

struct ntfsck_attrlist_item {
	ntfs_inode *record_ni;
	ATTR_RECORD *attr;
};

static int ntfsck_compare_attrlist_items(ntfs_volume *vol,
		const struct ntfsck_attrlist_item *left,
		const struct ntfsck_attrlist_item *right)
{
	VCN left_lowest_vcn;
	VCN right_lowest_vcn;
	u16 left_instance;
	u16 right_instance;
	int rc;

	rc = (int)le32_to_cpu(left->attr->type) -
		(int)le32_to_cpu(right->attr->type);
	if (rc)
		return rc;

	if (!left->attr->name_length && right->attr->name_length)
		return -1;
	if (left->attr->name_length && !right->attr->name_length)
		return 1;
	if (left->attr->name_length && right->attr->name_length) {
		rc = ntfs_names_full_collate(
				(ntfschar *)((u8 *)left->attr +
				le16_to_cpu(left->attr->name_offset)),
				left->attr->name_length,
				(ntfschar *)((u8 *)right->attr +
				le16_to_cpu(right->attr->name_offset)),
				right->attr->name_length,
				CASE_SENSITIVE,
				vol->upcase,
				vol->upcase_len);
		if (rc)
			return rc;
	}

	left_lowest_vcn = left->attr->non_resident ?
		sle64_to_cpu(left->attr->lowest_vcn) : 0;
	right_lowest_vcn = right->attr->non_resident ?
		sle64_to_cpu(right->attr->lowest_vcn) : 0;
	if (left_lowest_vcn < right_lowest_vcn)
		return -1;
	if (left_lowest_vcn > right_lowest_vcn)
		return 1;

	left_instance = left_lowest_vcn ? 0 : le16_to_cpu(left->attr->instance);
	right_instance = right_lowest_vcn ? 0 : le16_to_cpu(right->attr->instance);
	if (left_instance < right_instance)
		return -1;
	if (left_instance > right_instance)
		return 1;

	if (left->record_ni->mft_no < right->record_ni->mft_no)
		return -1;
	if (left->record_ni->mft_no > right->record_ni->mft_no)
		return 1;

	return 0;
}

static void ntfsck_sort_attrlist_items(ntfs_volume *vol,
		struct ntfsck_attrlist_item *items, size_t count)
{
	size_t index;

	for (index = 1; index < count; index++) {
		struct ntfsck_attrlist_item item = items[index];
		size_t sort_index = index;

		while (sort_index > 0 &&
				ntfsck_compare_attrlist_items(vol,
					&items[sort_index - 1], &item) > 0) {
			items[sort_index] = items[sort_index - 1];
			sort_index--;
		}
		items[sort_index] = item;
	}
}

static int ntfsck_collect_attrlist_items(ntfs_inode *base_ni,
		struct ntfsck_attrlist_item **items, size_t *item_count)
{
	struct ntfsck_attrlist_item *collected = NULL;
	size_t capacity = 0;
	size_t count = 0;
	int extent_index;

	if (!base_ni || !items || !item_count)
		return STATUS_ERROR;

	for (extent_index = -1; extent_index < base_ni->nr_extents;
			extent_index++) {
		ntfs_attr_search_ctx *ctx;
		ntfs_inode *record_ni;
		int ret;

		record_ni = extent_index < 0 ? base_ni :
			base_ni->extent_nis[extent_index];
		ctx = ntfs_attr_get_search_ctx(record_ni, NULL);
		if (!ctx)
			goto err_out;

		while (!(ret = ntfs_attrs_walk(ctx))) {
			struct ntfsck_attrlist_item *new_items;

			if (ctx->attr->type == AT_ATTRIBUTE_LIST)
				continue;

			if (count == capacity) {
				size_t new_capacity = capacity ? capacity * 2 : 16;

				new_items = realloc(collected,
						new_capacity * sizeof(*collected));
				if (!new_items) {
					ntfs_attr_put_search_ctx(ctx);
					goto err_out;
				}
				collected = new_items;
				capacity = new_capacity;
			}

			collected[count].record_ni = record_ni;
			collected[count].attr = ctx->attr;
			count++;
		}

		ntfs_attr_put_search_ctx(ctx);
		if (ret && errno != ENOENT)
			goto err_out;
	}

	*items = collected;
	*item_count = count;
	return STATUS_OK;

err_out:
	free(collected);
	return STATUS_ERROR;
}

static int ntfsck_rebuild_attr_list(ntfs_inode *ni)
{
	struct ntfsck_attrlist_item *items = NULL;
	ntfs_inode *base_ni;
	ntfs_attr *na = NULL;
	u8 *new_al = NULL;
	u32 new_al_len = 0;
	size_t item_count = 0;
	size_t index;
	size_t offset = 0;
	int ret = STATUS_ERROR;

	if (!ni)
		return STATUS_ERROR;

	base_ni = ni->nr_extents == -1 ? ni->base_ni : ni;
	if (!base_ni || !NInoAttrList(base_ni) || !base_ni->attr_list)
		return STATUS_ERROR;

	if (base_ni->nr_extents > 0 && !base_ni->extent_nis)
		return STATUS_ERROR;

	if (ntfsck_collect_attrlist_items(base_ni, &items, &item_count))
		goto out;

	if (!item_count) {
		ntfs_log_error("No attributes available to rebuild attrlist of "
				"inode(%"PRIu64")\n", base_ni->mft_no);
		goto out;
	}

	ntfsck_sort_attrlist_items(base_ni->vol, items, item_count);

	for (index = 0; index < item_count; index++) {
		u32 entry_len;

		entry_len = (offsetof(ATTR_LIST_ENTRY, name) +
				items[index].attr->name_length * sizeof(ntfschar) + 7) & ~7;
		if (new_al_len > 0x40000U - entry_len) {
			ntfs_log_error("Rebuilt attrlist of inode(%"PRIu64") is too large\n",
					base_ni->mft_no);
			goto out;
		}
		new_al_len += entry_len;
	}

	new_al = ntfs_calloc(new_al_len);
	if (!new_al)
		goto out;

	for (index = 0; index < item_count; index++) {
		ATTR_LIST_ENTRY *entry = (ATTR_LIST_ENTRY *)(new_al + offset);
		ATTR_RECORD *attr = items[index].attr;
		u32 entry_len = (offsetof(ATTR_LIST_ENTRY, name) +
				attr->name_length * sizeof(ntfschar) + 7) & ~7;

		entry->type = attr->type;
		entry->length = cpu_to_le16(entry_len);
		entry->name_length = attr->name_length;
		entry->name_offset = offsetof(ATTR_LIST_ENTRY, name);
		entry->lowest_vcn = attr->non_resident ?
			attr->lowest_vcn : const_cpu_to_sle64(0);
		entry->mft_reference = MK_LE_MREF(items[index].record_ni->mft_no,
				le16_to_cpu(items[index].record_ni->mrec->sequence_number));
		entry->instance = attr->non_resident && sle64_to_cpu(attr->lowest_vcn) ?
			const_cpu_to_le16(0) : attr->instance;
		if (attr->name_length)
			memcpy(entry->name,
					(u8 *)attr + le16_to_cpu(attr->name_offset),
					attr->name_length * sizeof(ntfschar));
		offset += entry_len;
	}

	na = ntfs_attr_open(base_ni, AT_ATTRIBUTE_LIST, AT_UNNAMED, 0);
	if (!na)
		goto out;

	if (ntfs_attr_truncate(na, new_al_len)) {
		ntfs_log_perror("Failed to resize attrlist of inode(%"PRIu64")",
				base_ni->mft_no);
		goto out;
	}

	if (ntfs_attr_pwrite(na, 0, new_al_len, new_al) != new_al_len) {
		ntfs_log_perror("Failed to rewrite attrlist of inode(%"PRIu64")",
				base_ni->mft_no);
		goto out;
	}

	free(base_ni->attr_list);
	base_ni->attr_list = new_al;
	base_ni->attr_list_size = new_al_len;
	NInoSetAttrList(base_ni);
	NInoAttrListSetDirty(base_ni);
	ntfs_inode_mark_dirty(base_ni);
	new_al = NULL;
	ret = STATUS_OK;

out:
	if (na)
		ntfs_attr_close(na);
	free(new_al);
	free(items);
	return ret;
}

/*
 * Seed the fsck occupancy oracle from every non-resident runlist of @ni. Run
 * by the pass-1 MFT scan before any repair can allocate, so the allocator
 * barrier (ntfs_cluster_alloc -> ntfs_fsck_or_alloc_lcnbmp) sees full
 * occupancy and never hands out an in-use cluster.
 */
static int ntfsck_update_lcn_bitmap(ntfs_inode *ni)
{
	ntfs_volume *vol;
	ntfs_attr_search_ctx *actx;

	if (!ni)
		return -EINVAL;

	vol = ni->vol;

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
			ntfs_log_error("Failed to decompress runlist(mft_no:%"PRIu64
					", type:0x%x). "
					"Leaving inconsistent metadata.\n",
					ni->mft_no, actx->attr->type);
			continue;
		}

		while (rl[i].length) {
			/*
			 * Record occupancy in the oracle before any repair can
			 * allocate, so the allocator barrier never reuses these
			 * clusters (cluster duplication avoidance in ntfsck).
			 */
			/* lcn corrupted */
			if (rl[i].lcn >= vol->nr_clusters) {
				/* truncate runlist */
				rl[i].lcn = LCN_ENOENT;
				rl[i].length = 0;
				break;
			}

			/* length corrupted */
			if (rl[i].lcn + rl[i].length >= vol->nr_clusters) {
				/* adjust length */
				rl[i].length = vol->nr_clusters - rl[i].lcn;
			}

			if (rl[i].lcn > (LCN)LCN_HOLE)
				ntfs_fsck_set_alloc_lcnbmp_range(ni->vol,
						rl[i].lcn, rl[i].length);
			++i;
		}

		free(rl);
	}

	ntfs_attr_put_search_ctx(actx);

	return STATUS_OK;
}

static int __ntfsck_check_non_resident_attr(ntfs_attr *na,
		ntfs_attr_search_ctx *actx, struct rl_size *rls, int set_bit)
{
	BOOL need_fix = FALSE;
	problem_context_t pctx = {0, };

	ntfs_volume *vol;
	ntfs_inode *ni;
	ATTR_RECORD *a;

	ni = na->ni;
	vol = na->ni->vol;
	a =  actx->attr;

	ntfs_init_problem_ctx(&pctx, ni, na, actx, NULL, NULL, a, NULL);

	/* check whole cluster runlist and set cluster bitmap of fsck */
	if (ntfsck_check_attr_runlist(na, rls, &need_fix, set_bit)) {
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
			if (ntfsck_update_runlist(na, rls->alloc_size, actx)) {
				/* The caller stops the current repair and leaves it unfixed. */
				return STATUS_ERROR;
			}
			fsck_err_fixed();
		}
	}
	return STATUS_OK;
}

static void ntfsck_set_attr_lcnbmp(ntfs_attr *na)
{
	ntfs_attr_search_ctx *actx;
	struct rl_size rls = {0, };

	actx = ntfs_attr_get_search_ctx(na->ni, NULL);
	if (!actx)
		return;

	if (ntfs_attr_lookup(na->type, na->name, na->name_len, 0,
				0, NULL, 0, actx)) {
		ntfs_attr_put_search_ctx(actx);
		return;
	}

	if (!actx->attr || !actx->attr->non_resident) {
		ntfs_attr_put_search_ctx(actx);
		return;
	}

	__ntfsck_check_non_resident_attr(na, actx, &rls, 1);
	ntfs_attr_put_search_ctx(actx);
}

static void ntfsck_clear_attr_lcnbmp(ntfs_attr *na)
{
	ntfs_attr_search_ctx *actx;
	struct rl_size rls = {0, };

	actx = ntfs_attr_get_search_ctx(na->ni, NULL);
	if (!actx)
		return;

	if (ntfs_attr_lookup(na->type, na->name, na->name_len, 0,
				0, NULL, 0, actx)) {
		ntfs_attr_put_search_ctx(actx);
		return;
	}

	if (!actx->attr || !actx->attr->non_resident) {
		ntfs_attr_put_search_ctx(actx);
		return;
	}

	__ntfsck_check_non_resident_attr(na, actx, &rls, 0);
	ntfs_attr_put_search_ctx(actx);
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

			/* check lcn corrupted */
			if (rl[i].lcn >= vol->nr_clusters) {
				/* truncate runlist */
				rl[i].lcn = LCN_ENOENT;
				rl[i].length = 0;
				break;
			}

			/* check length corrupted */
			if (rl[i].lcn + rl[i].length >= vol->nr_clusters) {
				/* adjust length */
				rl[i].length = vol->nr_clusters - rl[i].lcn;
			}

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
		if (MREF(mft_no) == ni->mft_no &&
				!MSEQNO_LE(ictx->entry->indexed_file) &&
				ni->mrec->sequence_number) {
			/*
			 * The entry was minted while the record had sequence
			 * number zero: rebind it instead of failing the add
			 * and leaving a stale duplicate behind.
			 */
			ictx->entry->indexed_file = MK_LE_MREF(ni->mft_no,
					le16_to_cpu(ni->mrec->sequence_number));
			ntfsck_update_index_entry(ictx);
		} else if ((MSEQNO_LE(ictx->entry->indexed_file) !=
					le16_to_cpu(ni->mrec->sequence_number)) ||
				(MREF(mft_no) != ni->mft_no)) {
			/* found index and orphaned inode is different */
			ntfs_log_error("mft number of inode(%"PRIu64
					") and parent index(%"PRIu64") "
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
			INDEX_ENTRY *ie = ictx->entry;
			FILE_NAME_ATTR *ie_fn = (FILE_NAME_ATTR *)&ie->key.file_name;

			if (ntfsck_check_orphan_inode(parent_ni, ni) ||
					ntfsck_check_orphan_file_type(ni, ictx, ie_fn)) {
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
		if (check_flag == TRUE) {
			if (ntfsck_check_orphan_inode(parent_ni, ni)) {
				ntfs_log_error("Failed to check inode(%"PRIu64") "
						"for repairing orphan inode\n", ni->mft_no);
				ntfs_index_ctx_put(ictx);
				return STATUS_ERROR;
			}
		}
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
		ntfs_attr *ia_na = NULL;

		/* check runlist for cluster duplication */
		ia_na = ntfs_attr_open(ni, AT_INDEX_ALLOCATION, NTFS_INDEX_I30, 4);
		if (ia_na)
			ntfsck_set_attr_lcnbmp(ia_na);
		ntfs_attr_close(ia_na);

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

static int ntfsck_add_filename_to_parent(ntfs_volume *vol,
		ntfs_inode *parent_ni, ntfs_inode *ni, FILE_NAME_ATTR *fn)
{
	FILE_NAME_ATTR *tfn;
	int tfn_len;
	int ret;

	if (!vol || !parent_ni || !ni || !fn)
		return STATUS_ERROR;

	tfn_len = sizeof(FILE_NAME_ATTR) +
		fn->file_name_length * sizeof(ntfschar);
	tfn = ntfs_calloc(tfn_len);
	if (!tfn)
		return STATUS_ERROR;

	memcpy(tfn, fn, tfn_len);
	tfn->parent_directory = MK_LE_MREF(parent_ni->mft_no,
			le16_to_cpu(parent_ni->mrec->sequence_number));

	ret = ntfs_index_add_filename(parent_ni, tfn,
			MK_MREF(ni->mft_no,
			le16_to_cpu(ni->mrec->sequence_number)));
	if (ret) {
		ntfs_log_error("Failed to add index(%"PRIu64") to parent(%"PRIu64") "
				"err(%d)\n", ni->mft_no, parent_ni->mft_no, ret);
		free(tfn);
		return STATUS_ERROR;
	}

	if (parent_ni->attr_list) {
		if (ntfsck_check_attr_list(parent_ni) ||
				ntfs_inode_attach_all_extents(parent_ni)) {
			free(tfn);
			return STATUS_ERROR;
		}
	}

	ntfsck_set_mft_record_bitmap(parent_ni, TRUE);
	ntfs_inode_mark_dirty(parent_ni);

	ret = ntfsck_find_and_check_index(parent_ni, ni, tfn, TRUE);
	free(tfn);
	if (ret != STATUS_OK)
		return STATUS_ERROR;

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
		ntfs_inode *ni, INDEX_ENTRY *ie, ntfs_index_context *ictx)
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

	if (ntfsck_cmp_parent_mft_sequence(parent_ni, fn) &&
			MSEQNO_LE(fn->parent_directory)) {
		ntfs_log_error("Seuqnece number of parent(%"PRIu64")"
				"and parent directory in $FN of inode(%"PRIu64") is not same\n",
				parent_ni->mft_no, MREF_LE(fn->parent_directory));
		ntfs_attr_put_search_ctx(ctx);
		return STATUS_ERROR;
	}

	/*
	 * A zero sequence number in a parent reference disables every stale
	 * reference check, and it can only have been minted while the parent record
	 * itself had sequence number zero. The parent binding by mft number is
	 * already verified above, so refresh both copies of the reference from the
	 * parent record.
	 */
	if (!MSEQNO_LE(fn->parent_directory) ||
			!MSEQNO_LE(ie_fn->parent_directory)) {
		u16 pdir_seq = le16_to_cpu(parent_ni->mrec->sequence_number);
		problem_context_t pctx = {0, };

		ntfs_init_problem_ctx(&pctx, ni, NULL, ctx, ictx, ni->mrec,
				NULL, fn);
		fsck_err_found();
		if (ntfs_fix_problem(ni->vol, PR_FN_PARENT_SEQNO_ZERO, &pctx) &&
				pdir_seq) {
			fn->parent_directory =
				MK_LE_MREF(parent_ni->mft_no, pdir_seq);
			ie_fn->parent_directory = fn->parent_directory;
			ntfs_inode_mark_dirty(ctx->ntfs_ino);
			/*
			 * The index walk reloads ictx->ib without flushing
			 * a dirty block, so write the entry out right away.
			 */
			if (!ntfsck_update_index_entry(ictx))
				fsck_err_fixed();
		}
	}

	ntfs_attr_put_search_ctx(ctx);
	return STATUS_OK;
}

/*
 * check indexed_file of index entry and mft number and sequence of inode
 * and also check parent mft number and sequence in $FN
 */
static int ntfsck_check_inode_fields(ntfs_inode *parent_ni,
		ntfs_inode *ni, INDEX_ENTRY *ie, ntfs_index_context *ictx)
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
	if (idx_seq && ni_seq != idx_seq) {
		ntfs_log_error("Mismatch sequence number of index and inode(%"PRIu64")\n",
				ni->mft_no);
		return STATUS_ERROR;
	}

	/* check parent mft record of $FN and parent mft record and sequence */
	if (ntfsck_check_parent_mft_record(parent_ni, ni, ie, ictx))
		return STATUS_ERROR;

	/*
	 * A zero sequence number in the reference disables every stale reference
	 * check, and the name and parent binding verified just above prove the entry
	 * belongs to this record: rebind it to the record's real sequence number.
	 */
	if (!idx_seq) {
		problem_context_t pctx = {0, };

		ntfs_init_problem_ctx(&pctx, ni, NULL, NULL, ictx, ni->mrec,
				NULL, NULL);
		fsck_err_found();
		if (ntfs_fix_problem(ni->vol, PR_IDX_SEQNO_ZERO, &pctx) &&
				ni_seq) {
			ie->indexed_file = MK_LE_MREF(ni->mft_no, ni_seq);
			/*
			 * The index walk reloads ictx->ib without flushing
			 * a dirty block, so write the entry out right away.
			 */
			if (!ntfsck_update_index_entry(ictx))
				fsck_err_fixed();
		}
	}

	return STATUS_OK;
}

static int ntfsck_check_orphan_inode_fields(ntfs_inode *parent_ni, ntfs_inode *ni)
{
	if (!parent_ni || !ni)
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

	--nlink;
	ni->mrec->link_count = cpu_to_le16(nlink);
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

				ntfs_log_error("Not found parent inode(%"PRIu64")"
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

				if (ntfsck_cmp_parent_mft_sequence(parent_ni, fn) &&
						!MSEQNO_LE(fn->parent_directory)) {
					/*
					 * A zero sequence in the parent
					 * reference was minted while the
					 * parent record had sequence number
					 * zero: refresh it instead of
					 * dropping a healthy $FILE_NAME.
					 */
					fn->parent_directory =
						MK_LE_MREF(parent_ni->mft_no,
						le16_to_cpu(parent_ni->mrec->sequence_number));
					ntfs_inode_mark_dirty(ctx->ntfs_ino);
				} else if (ntfsck_cmp_parent_mft_sequence(parent_ni, fn)) {
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
	struct orphan_mft *of;
	int is_used;
	ntfs_attr_search_ctx *ctx = NULL;
	BOOL raw_retry_done = FALSE;
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
		raw_retry_done = TRUE;
		ni = ntfsck_open_inode_after_raw_mft_check(vol, mft_num,
				is_used > 0);
	}
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

	retry_validate:
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		ntfs_log_error("Failed to allocate attribute context\n");
		ntfsck_close_inode(ni);
		return;
	}

	if (ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0,
				CASE_SENSITIVE, 0, NULL, 0, ctx)) {
		ntfs_log_error("Failed to find filename of inode(%"PRIu64")\n",
				ni->mft_no);
		goto err_check_inode;
	}

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
	ctx = NULL;
	ntfsck_close_inode(ni);
	ni = NULL;

	if (!raw_retry_done) {
		raw_retry_done = TRUE;
		ni = ntfsck_open_inode_after_raw_mft_check(vol, mft_num,
				is_used > 0);
		if (ni)
			goto retry_validate;
	}

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
		ntfs_log_error("Parent MFT reference is different "
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
				ntfs_inode_mark_dirty(ni);
				NInoFileNameSetDirty(ni);
				/*
				 * The index walk reloads ictx->ib without
				 * flushing a dirty block, so write the entry
				 * out right away.
				 */
				if (!ntfsck_update_index_entry(ictx))
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
				ntfs_inode_mark_dirty(ni);
				NInoFileNameSetDirty(ni);
				if (!ntfsck_update_index_entry(ictx))
					fsck_err_fixed();
			}
		}

		/* if inode is directory, then skip size fields check */
		goto out;
	}

	if (utils_is_metadata(ni) == 1)
		goto out;

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

			if (!ntfsck_update_index_entry(ictx))
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

	/* Is checking MFT_RECORD_IS_4 need? */

	if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
		/* mft record flags is set to directory */
		if (ntfs_attr_exist(ni, AT_INDEX_ROOT, NTFS_INDEX_I30, 4)) {
			if (!(ie_flags & FILE_ATTR_I30_INDEX_PRESENT)) {
				ie_flags |= FILE_ATTR_I30_INDEX_PRESENT;
				ie_fn->file_attributes |= FILE_ATTR_I30_INDEX_PRESENT;

				fsck_err_found();
				if (ntfs_fix_problem(vol, PR_DIR_FLAG_MISMATCH_IDX_FN, &pctx)) {
					/*
					 * The index walk reloads ictx->ib
					 * without flushing a dirty block, so
					 * write the entry out right away.
					 */
					if (!ntfsck_update_index_entry(ictx))
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
					if (!ntfsck_update_index_entry(ictx))
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
					if (!ntfsck_update_index_entry(ictx))
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
				if (!ntfsck_update_index_entry(ictx))
					fsck_err_fixed();
			}
		}
	}
	return (int32_t)ie_flags;
}

static int ntfsck_check_orphan_file_type(ntfs_inode *ni, ntfs_index_context *ictx,
		FILE_NAME_ATTR *ie_fn)
{
	int32_t flags;
	int ret;

	flags = ntfsck_check_file_type(ni, ictx, ie_fn);
	if (flags < 0)
		return STATUS_ERROR;

	/* check $FILE_NAME */
	ret = ntfsck_check_file_name_attr(ni, ie_fn, ictx);
	if (ret < 0)
		return STATUS_ERROR;

	return STATUS_OK;
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
	BOOL rebuilt_attr_list = FALSE;
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

		/*
		 * A non-resident $DATA with allocated_size zero owns no clusters, so map it
		 * as an empty runlist without decoding the mapping pairs. Converting such
		 * an attribute back to resident (Windows behavior) is a repair, not a
		 * mapping concern, and is done by ntfsck_check_non_resident_attr() with the
		 * sizes from the attribute record.
		 */
		if (!utils_is_metadata(ni) &&
				na->type == AT_DATA &&
				sle64_to_cpu(attr->lowest_vcn) == 0 &&
				sle64_to_cpu(attr->allocated_size) == 0) {

			rl = malloc(sizeof(runlist_element));
			if (!rl) {
				ntfs_attr_put_search_ctx(actx);
				return NULL;
			}
			rl[0].vcn = 0;
			rl[0].lcn = LCN_ENOENT;
			rl[0].length = 0;
			na->rl = rl;

			goto out;
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

			/*
			 * Compare highest_vcn against the decoded runlist instead of
			 * trusting the first extent's allocated_size field.
			 */
			last_vcn = ntfsck_runlist_end_vcn(rl);
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
			if (!rebuilt_attr_list) {
				pctx.ctx = actx;
				fsck_err_found();
				if (ntfs_fix_problem(vol, PR_ATTRLIST_REBUILD, &pctx) &&
						!ntfsck_rebuild_attr_list(ni)) {
					fsck_err_fixed();
					rebuilt_attr_list = TRUE;
					free(rl);
					rl = NULL;
					na->rl = NULL;
					ntfs_attr_put_search_ctx(actx);
					actx = ntfs_attr_get_search_ctx(ni, NULL);
					if (!actx)
						return NULL;
					next_vcn = last_vcn = highest_vcn = 0;
					continue;
				}
			}
			err = EIO;
			break;
		}
	}

	if (err == ENOENT)
		NAttrSetFullyMapped(na);

	if (rl)
		last_vcn = ntfsck_runlist_end_vcn(rl);

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
	if (r_size != bm_na->data_size || r_size < 0) {
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
	ret = STATUS_OK;
out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);

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
 * Remove $IA/$BITMAP, and initialize $IR attribute for repairing. This
 * function should be called when index attributes are corrupted.
 */
static int ntfsck_initialize_named_index_attr(ntfs_inode *ni,
		ntfschar *name, u32 name_len)
{
	ntfs_attr *bm_na = NULL;
	ntfs_attr *ia_na = NULL;
	ntfs_attr *ir_na = NULL;
	int ret = STATUS_ERROR;

	/*
	 * Remove both ia attr and bitmap attr and recreate them.
	 */
	ia_na = ntfs_attr_open(ni, AT_INDEX_ALLOCATION, name, name_len);
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

	bm_na = ntfs_attr_open(ni, AT_BITMAP, name, name_len);
	if (bm_na) {
		if (ntfs_attr_rm(bm_na)) {
			ntfs_log_error("Failed to remove $BITMAP attr. of "
					" inode(%"PRIu64")\n", ni->mft_no);
			goto out;
		}
		ntfs_attr_close(bm_na);
		bm_na = NULL;
	}

	ir_na = ntfs_attr_open(ni, AT_INDEX_ROOT, name, name_len);
	if (!ir_na) {
		ntfs_log_verbose("Can't open index root attribute from mft(%"PRIu64") "
				"entry\n",
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

		ir = ntfs_ir_lookup2(ni, name, name_len);
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

static int ntfsck_initialize_index_attr(ntfs_inode *ni)
{
	return ntfsck_initialize_named_index_attr(ni, NTFS_INDEX_I30, 4);
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
		ntfs_log_error("Failed to get cluster run in directory(%"PRId64")\n",
				na->ni->mft_no);
		return STATUS_ERROR;
	}

	if (*need_fix == TRUE) {
		ntfs_log_error("Non-resident cluster run of inode(%"PRId64")(%02x:%"PRIu64") "
				"corrupted. rl_size(%"PRIx64":%"PRIx64"). Truncate it\n",
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
	u32 backup_attr_list_size = 0;
	s64 backup_allocated_size;

	if (!na->ni)
		return STATUS_ERROR;

	ni = na->ni;
	backup_allocated_size = na->allocated_size;
	if (NInoAttrList(ni))
		backup_attr_list_size = ni->attr_list_size;

	/* apply rl to disk */
	na->allocated_size = new_size;
	if (ntfs_attr_update_mapping_pairs(na, 0)) {
		na->allocated_size = backup_allocated_size;
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
	ntfs_volume *vol;
	ntfs_inode *ni;
	ATTR_RECORD *a;

	s64 data_size;
	s64 alloc_size;
	s64 init_size;
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

	if (__ntfsck_check_non_resident_attr(na, actx, &rls, set_bit))
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
	 * initialized_size records how many bytes of data_size have actually been
	 * written; everything from there up to data_size reads back as zero. It must
	 * therefore stay within [0, data_size] -- a value past data_size would
	 * expose uninitialized cluster contents as file data.
	 */
	init_size = sle64_to_cpu(a->initialized_size);
	if (init_size < 0 || init_size > data_size) {
		fsck_err_found();
		if (ntfs_fix_problem(vol, PR_ATTR_INITIALIZED_SIZE_MISMATCH, &pctx)) {
			init_size = (init_size < 0) ? 0 : data_size;
			a->initialized_size = cpu_to_sle64(init_size);
			na->initialized_size = init_size;
			ntfs_inode_mark_dirty(actx->ntfs_ino);
			fsck_err_fixed();
		}
	}

	/*
	 * Everything below rewrites the attribute's structure -- rebuilding an
	 * index, shrinking the runlist or forcing the attribute resident. That is
	 * unsafe for system files: their correct size follows from the volume
	 * geometry (e.g.
	 */
	if (utils_is_metadata(ni))
		goto out;

	/*
	 * $INDEX_ALLOCATION is never sparse and never has an uninitialized
	 * tail: every allocated index block is written, so initialized_size
	 * always equals data_size, and data_size is a whole number of index
	 * blocks. (data_size need not equal allocated_size, which is only
	 * cluster-aligned.)  A violation means the size fields are corrupt, so
	 * rebuild the index from scratch -- the same safe path used below for
	 * a runlist/allocation mismatch.
	 */
	if (na->type == AT_INDEX_ALLOCATION &&
			(init_size != data_size ||
			 (vol->indx_record_size &&
			  (data_size & (vol->indx_record_size - 1))))) {
		fsck_err_found();
		if (ntfs_fix_problem(vol, PR_ATTR_NON_RESIDENT_SIZES_MISMATCH,
					&pctx)) {
			if (!ntfsck_initialize_index_attr(ni))
				fsck_err_fixed();
		}
		goto out;
	}

	/*
	 * An empty non-resident $DATA (no clusters, every size field zero) is not
	 * corruption -- truncation to zero can legitimately leave the attribute
	 * non-resident -- but Windows normalizes such an attribute back to resident,
	 * so convert it the same way. Encrypted attributes cannot be made resident
	 * and the layout is harmless, so leave them alone.
	 */
	if (na->type == AT_DATA && alloc_size == 0 && data_size == 0 &&
			init_size == 0 && rls.alloc_size == 0 &&
			!(na->data_flags & ATTR_IS_ENCRYPTED)) {
		fsck_err_found();
		if (ntfs_fix_problem(vol, PR_ATTR_EMPTY_NON_RESIDENT_DATA,
					&pctx)) {
			if (!ntfs_non_resident_attr_shrink(na, 0) &&
					!NAttrNonResident(na))
				fsck_err_fixed();
		}
		goto out;
	}

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

	if (na->type == AT_INDEX_ALLOCATION) {
		if (!ntfsck_initialize_index_attr(ni))
			fsck_err_fixed();
	} else if (!ntfs_non_resident_attr_shrink(na, new_size))
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
		/* Reinitialize both $IA and $BITMAP when $IA is resident. */
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
	if (ia_na && ia_na->allocated_size == 0) {
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
		if (!ntfsck_initialize_index_attr(ni)) {
			ret = STATUS_OK;
			fsck_err_fixed();
		}
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
	u32 al_length = 0;
	u32 al_real_length = 0;
	u32 remaining;
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
		remaining = al_end - (u8 *)al_entry;
		if (remaining < sizeof(ATTR_LIST_ENTRY))
			break;

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
		if (al_length < sizeof(ATTR_LIST_ENTRY) || al_length & 7) {
			ret = STATUS_ERROR;
			goto out;
		}

		if (remaining < al_length)
			break;

		al_real_length += al_length;
		next_al_entry =
			(ATTR_LIST_ENTRY *)((u8 *)al_entry + al_length);

		if ((u8 *)next_al_entry >= al_end)
			break;

		remaining = al_end - (u8 *)next_al_entry;
		if (remaining < sizeof(ATTR_LIST_ENTRY))
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

/*
 * RFC Phase 6: validate the $EA (extended attribute) chain.
 *
 * Walk the EA_ATTR linked list applying the structural rules used by
 * ntfs_set_ntfs_ea() (chain integrity, name/value bounds, null terminator)
 * and cross-check the packed size / NEED_EA count against $EA_INFORMATION.
 * Following the RFC's "deletion over dubious repair" principle, a corrupt
 * chain causes both $EA and $EA_INFORMATION to be removed together; the
 * primary $DATA is never touched. Name characters are intentionally not
 * validated, matching chkdsk (and ntfs_set_ntfs_ea()), to avoid destroying
 * otherwise valid extended attributes.
 */
#define NTFSCK_EA_MAX_SIZE	(256 * 1024)
static int ntfsck_check_ea(ntfs_inode *ni)
{
	ntfs_attr_search_ctx *ctx;
	ntfs_attr *ea_na = NULL;
	ntfs_attr *eainfo_na = NULL;
	EA_INFORMATION eainfo;
	u8 *buf = NULL;
	s64 ea_size;
	size_t offs, nextoffs = 0;
	u32 ea_packed = 0;
	int ea_count = 0;
	BOOL have_eainfo = FALSE;
	BOOL corrupt = FALSE;
	problem_context_t pctx = {0, };

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		return STATUS_ERROR;

	if (!ntfs_attr_lookup(AT_EA_INFORMATION, AT_UNNAMED, 0, CASE_SENSITIVE,
				0, NULL, 0, ctx)) {
		have_eainfo = TRUE;
		if (le32_to_cpu(ctx->attr->value_length) < sizeof(EA_INFORMATION))
			corrupt = TRUE;
		else
			memcpy(&eainfo, (u8 *)ctx->attr +
					le16_to_cpu(ctx->attr->value_offset),
					sizeof(EA_INFORMATION));
	}
	ntfs_attr_put_search_ctx(ctx);

	ea_na = ntfs_attr_open(ni, AT_EA, AT_UNNAMED, 0);

	/* Neither present: nothing to validate. */
	if (!ea_na && !have_eainfo)
		return STATUS_OK;

	/* One present without the other, or malformed $EA_INFORMATION. */
	if (!ea_na || !have_eainfo) {
		corrupt = TRUE;
		goto verdict;
	}
	if (corrupt)
		goto verdict;

	ea_size = ea_na->data_size;
	if (ea_size <= 0 || ea_size > NTFSCK_EA_MAX_SIZE) {
		corrupt = TRUE;
		goto verdict;
	}

	buf = ntfs_malloc(ea_size);
	if (!buf) {
		ntfs_attr_close(ea_na);
		return STATUS_ERROR;
	}
	if (ntfs_attr_pread(ea_na, 0, ea_size, buf) != ea_size) {
		corrupt = TRUE;
		goto verdict;
	}

	/* Walk the chain (mirrors ntfs_set_ntfs_ea()'s consistency check). */
	offs = 0;
	while (offs < (size_t)ea_size) {
		const EA_ATTR *p_ea = (const EA_ATTR *)&buf[offs];
		u32 entry_end;

		if (offs + offsetof(EA_ATTR, name) > (size_t)ea_size) {
			corrupt = TRUE;
			break;
		}

		nextoffs = offs + le32_to_cpu(p_ea->next_entry_offset);
		entry_end = offs + offsetof(EA_ATTR, name) + p_ea->name_length +
				1 + le16_to_cpu(p_ea->value_length);

		if (!(nextoffs > offs &&
				nextoffs <= (size_t)ea_size &&
				!(nextoffs & 3) &&
				p_ea->name_length &&
				entry_end <= nextoffs &&
				entry_end >= (nextoffs - 3) &&
				!p_ea->name[p_ea->name_length])) {
			corrupt = TRUE;
			break;
		}

		if (p_ea->flags & NEED_EA)
			ea_count++;
		/* header(4) + name + 1 + value, excluding next_entry_offset */
		ea_packed += 5 + p_ea->name_length +
				le16_to_cpu(p_ea->value_length);
		offs = nextoffs;
	}

	/*
	 * Cross-validate against $EA_INFORMATION. Only the well-defined packed size
	 * and NEED_EA count are compared; ea_query_length (the unpacked
	 * ZwQueryEaFile buffer size) uses a different layout across Windows
	 * versions, so comparing it would risk false positives.
	 */
	if (!corrupt &&
			(le16_to_cpu(eainfo.ea_length) != ea_packed ||
			 le16_to_cpu(eainfo.need_ea_count) != ea_count))
		corrupt = TRUE;

verdict:
	free(buf);

	if (corrupt) {
		ntfs_init_problem_ctx(&pctx, ni, NULL, NULL, NULL, ni->mrec,
				NULL, NULL);
		fsck_err_found();
		if (ntfs_fix_problem(ni->vol, PR_EA_CHAIN_CORRUPTED, &pctx)) {
			int rm_ok = 1;

			if (ea_na && ntfs_attr_rm(ea_na))
				rm_ok = 0;
			eainfo_na = ntfs_attr_open(ni, AT_EA_INFORMATION,
					AT_UNNAMED, 0);
			if (eainfo_na) {
				if (ntfs_attr_rm(eainfo_na))
					rm_ok = 0;
				ntfs_attr_close(eainfo_na);
			}
			if (rm_ok) {
				ntfs_inode_mark_dirty(ni);
				fsck_err_fixed();
			}
		}
	}

	if (ea_na)
		ntfs_attr_close(ea_na);
	return STATUS_OK;
}
/*
 * RFC reparse-point validation.
 *
 * Checks performed:
 *   - consistency between the $STANDARD_INFORMATION reparse flag and the
 *     presence of a $REPARSE_POINT attribute (the attribute is ground truth);
 *   - structural validity of the reparse data (tag not reserved-zero,
 *     reparse_data_length <= 16 KiB, header/length consistency and payload
 *     bounds), reusing ntfs_reparse_data_is_valid();
 * On corruption the reparse data and its $Extend/$Reparse index entry are
 * removed together via ntfs_remove_ntfs_reparse_data(), which also clears the
 * reparse flag.
 *
 * NOTE: full multi-hop circular-reference detection (RFC "Floyd" cycle check)
 * is not implemented here: it requires offline resolution of NT target paths
 * (\??\C:\...) to MFT records, infrastructure ntfsck does not yet have.
 * Doing it hastily risks deleting valid links, so it is deliberately left out.
 */
#define NTFSCK_REPARSE_MAX_DATA		(16 * 1024)
/*
 * ntfsck_reparse_recall_flag_recoverable - is this only a missing recall flag?
 *
 * WSL special files (socket, fifo, character or block device) are stored as
 * data-less reparse points and are valid only when $STANDARD_INFORMATION carries
 * FILE_ATTRIBUTE_RECALL_ON_OPEN. A creator that fails to persist that flag
 * leaves an otherwise well-formed stub that ntfs_reparse_data_is_valid() then
 * rejects. Recognise exactly that case so it can be repaired by restoring the
 * flag instead of destroying the special file.
 */
static BOOL ntfsck_reparse_recall_flag_recoverable(ntfs_inode *ni,
		const REPARSE_POINT *rp, s64 attr_size)
{
	if (attr_size != (s64)sizeof(REPARSE_POINT) ||
			le16_to_cpu(rp->reparse_data_length) != 0 ||
			(ni->flags & FILE_ATTRIBUTE_RECALL_ON_OPEN))
		return FALSE;

	switch (rp->reparse_tag) {
	case IO_REPARSE_TAG_AF_UNIX:
	case IO_REPARSE_TAG_LX_FIFO:
	case IO_REPARSE_TAG_LX_CHR:
	case IO_REPARSE_TAG_LX_BLK:
		return TRUE;
	default:
		return FALSE;
	}
}

static int ntfsck_check_reparse(ntfs_inode *ni)
{
	REPARSE_POINT *rp = NULL;
	s64 attr_size = 0;
	BOOL has_attr, has_flag;
	BOOL corrupt = FALSE;
	BOOL recall_missing = FALSE;
	problem_context_t pctx = {0, };

	has_flag = (ni->flags & FILE_ATTR_REPARSE_POINT) ? TRUE : FALSE;

	/*
	 * Probe for the attribute quietly: this runs on every checked inode and
	 * ntfs_attr_readall() logs a perror for each inode that lacks the attribute
	 * -- which is the overwhelming majority. ntfs_attr_exist() only reports
	 * presence, and we read the data (which then cannot fail with ENOENT) only
	 * when it is actually there.
	 */
	has_attr = ntfs_attr_exist(ni, AT_REPARSE_POINT, AT_UNNAMED, 0) ?
			TRUE : FALSE;

	if (!has_attr && !has_flag)
		return STATUS_OK;

	/* Attribute present: read and validate its structure. */
	if (has_attr) {
		rp = (REPARSE_POINT *)ntfs_attr_readall(ni, AT_REPARSE_POINT,
				(ntfschar *)NULL, 0, &attr_size);
		if (!rp ||
				attr_size < (s64)sizeof(REPARSE_POINT) ||
				attr_size > NTFSCK_REPARSE_MAX_DATA +
					(s64)(sizeof(REPARSE_POINT) + sizeof(GUID)) ||
				le16_to_cpu(rp->reparse_data_length) >
					NTFSCK_REPARSE_MAX_DATA ||
				!ntfs_reparse_data_is_valid(ni, rp,
					(size_t)attr_size)) {
			corrupt = TRUE;
			if (rp && ntfsck_reparse_recall_flag_recoverable(ni, rp,
						attr_size))
				recall_missing = TRUE;
		}
		free(rp);
	}

	ntfs_init_problem_ctx(&pctx, ni, NULL, NULL, NULL, ni->mrec, NULL, NULL);

	/*
	 * A WSL special file that only lost FILE_ATTRIBUTE_RECALL_ON_OPEN is
	 * repaired by restoring the flag, keeping the device node / fifo /
	 * socket intact instead of deleting its reparse data.
	 */
	if (recall_missing) {
		fsck_err_found();
		if (ntfs_fix_problem(ni->vol, PR_REPARSE_RECALL_FLAG_MISSING,
					&pctx)) {
			/*
			 * The flag belongs in $STANDARD_INFORMATION only; $FILE_NAME
			 * intentionally does not carry it, so update ni->flags (which
			 * is written back to $STANDARD_INFORMATION) without marking
			 * the file name dirty.
			 */
			ni->flags |= FILE_ATTRIBUTE_RECALL_ON_OPEN;
			ntfs_inode_mark_dirty(ni);
			fsck_err_fixed();
		}
		return STATUS_OK;
	}

	if (corrupt) {
		fsck_err_found();
		if (ntfs_fix_problem(ni->vol, PR_REPARSE_ATTR_CORRUPTED, &pctx)) {
			BOOL removed = FALSE;

			if (!ntfs_remove_ntfs_reparse_data(ni)) {
				removed = TRUE;
			} else {
				ntfs_attr *rna;

				/*
				 * ntfs_remove_ntfs_reparse_data() removes the $Extend/$Reparse index
				 * entry first and gives up on the whole operation if that fails -- e.g.
				 * the reparse data is too corrupt to yield a tag, or the $Reparse index
				 * itself is damaged -- leaving the bad $REPARSE_POINT attribute in place
				 * to be re-detected on every run. Force the attribute out so the
				 * corruption cannot persist; any stale $Reparse index entry is reconciled
				 * when that index is structurally revalidated.
				 */
				rna = ntfs_attr_open(ni, AT_REPARSE_POINT,
						AT_UNNAMED, 0);
				if (rna) {
					if (!ntfs_attr_rm(rna)) {
						ni->flags &=
							~FILE_ATTR_REPARSE_POINT;
						NInoFileNameSetDirty(ni);
						removed = TRUE;
					}
					ntfs_attr_close(rna);
				}
			}
			if (removed) {
				ntfs_inode_mark_dirty(ni);
				fsck_err_fixed();
			}
		}
		return STATUS_OK;
	}

	/* Structure is fine (or absent): reconcile the reparse flag. */
	if (has_attr != has_flag) {
		fsck_err_found();
		if (ntfs_fix_problem(ni->vol, PR_REPARSE_FLAG_MISMATCH, &pctx)) {
			if (has_attr)
				ni->flags |= FILE_ATTR_REPARSE_POINT;
			else
				ni->flags &= ~FILE_ATTR_REPARSE_POINT;
			NInoFileNameSetDirty(ni);
			ntfs_inode_mark_dirty(ni);
			fsck_err_fixed();
		}
	}

	return STATUS_OK;
}
static int ntfsck_sparse_compression_unit(ntfs_attr *na, s64 cb_vcn_bytes);

/*
 * ntfsck_check_compressed - validate every compression unit of an inode.
 *
 * Each non-resident compressed $DATA attribute is read one compression unit at
 * a time, which drives the LZNT1 decompressor. A unit that fails to
 * decompress is reported. In salvage-aggressive mode (and when repairs are
 * allowed) the unrecoverable unit is replaced with a sparse hole so that the
 * rest of the file becomes readable instead of the whole file erroring out.
 */
static void ntfsck_check_compressed(ntfs_inode *ni)
{
	ntfs_attr_search_ctx *ctx;
	u8 *buf = NULL;
	s64 buf_size = 0;
	problem_context_t pctx = {0, };

	/*
	 * Decompressing every compression unit of every compressed file is expensive
	 * (Windows volumes compress many files), so this deep pass is opt-in via
	 * salvage-aggressive mode, which is also the only mode that can act on what
	 * it finds.
	 */
	if (!opt_salvage)
		return;

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		return;

	while (!ntfs_attr_lookup(AT_DATA, NULL, 0, CASE_SENSITIVE, 0, NULL, 0,
				ctx)) {
		ATTR_RECORD *a = ctx->attr;
		ntfschar *name;
		ntfs_attr *na;
		s64 vcn, size, cb_size;

		/* Only non-resident compressed attributes contain CBs. */
		if (!a->non_resident ||
				!(a->flags & ATTR_COMPRESSION_MASK))
			continue;

		name = (ntfschar *)((u8 *)a + le16_to_cpu(a->name_offset));
		na = ntfs_attr_open(ni, AT_DATA,
				a->name_length ? name : AT_UNNAMED,
				a->name_length);
		if (!na)
			continue;

		if (!NAttrCompressed(na) || na->compression_block_size == 0) {
			ntfs_attr_close(na);
			continue;
		}

		cb_size = na->compression_block_size;
		size = na->data_size;

		if (cb_size > buf_size) {
			u8 *nbuf = realloc(buf, cb_size);

			if (!nbuf) {
				ntfs_attr_close(na);
				break;
			}
			buf = nbuf;
			buf_size = cb_size;
		}

		for (vcn = 0; vcn < size; vcn += cb_size) {
			s64 want = size - vcn;
			s64 got;

			if (want > cb_size)
				want = cb_size;

			got = ntfs_attr_pread(na, vcn, want, buf);
			if (got == want)
				continue;

			/* This compression unit could not be decompressed. */
			ntfs_init_problem_ctx(&pctx, ni, na, NULL, NULL,
					ni->mrec, a, NULL);
			fsck_err_found();
			ntfs_log_error("Inode(%"PRIu64"): compression unit at "
					"offset %"PRId64" failed to decompress\n",
					ni->mft_no, vcn);
			ntfs_fix_problem(ni->vol, PR_COMPRESSED_UNIT_CORRUPTED,
					&pctx);

			/*
			 * Destructive salvage: turn the dead unit into a hole.
			 * Only under -S, and only if the operator agrees to the
			 * PR_COMPRESSED_UNIT_SPARSED prompt.
			 */
			if (opt_salvage &&
					ntfs_fix_problem(ni->vol,
						PR_COMPRESSED_UNIT_SPARSED, &pctx)) {
				if (!ntfsck_sparse_compression_unit(na, vcn))
					fsck_err_fixed();
			}
		}
		ntfs_attr_close(na);
	}

	free(buf);
	ntfs_attr_put_search_ctx(ctx);
}

/*
 * ntfsck_sparse_compression_unit - replace one compression unit with a hole.
 *
 * @na:		compressed attribute
 * @cb_vcn_bytes: byte offset (compression-unit aligned) of the dead unit
 *
 * The unit's real clusters are freed and its VCN range becomes a single sparse
 * hole, so the file reads back zeros there instead of failing to decompress.
 * The attribute's mapping pairs and compressed-size accounting are rewritten to
 * match. This is destructive (the unit's contents are gone) and is only
 * reached under salvage-aggressive mode.
 *
 * Returns 0 on success, -1 on failure.
 */
static int ntfsck_sparse_compression_unit(ntfs_attr *na, s64 cb_vcn_bytes)
{
	ntfs_volume *vol = na->ni->vol;
	runlist *new_rl, *punch_rl = NULL;
	VCN start_vcn;
	s64 len, alloc_clusters;
	int rl_size;

	if (!NAttrCompressed(na) || na->compression_block_clusters == 0)
		return -1;

	if (ntfs_attr_map_whole_runlist(na))
		return -1;

	start_vcn = cb_vcn_bytes >> vol->cluster_size_bits;
	len = na->compression_block_clusters;

	/* Keep the hole within the attribute's allocated cluster range. */
	alloc_clusters = na->allocated_size >> vol->cluster_size_bits;
	if (start_vcn >= alloc_clusters)
		return -1;
	if (start_vcn + len > alloc_clusters)
		len = alloc_clusters - start_vcn;
	if (len <= 0)
		return -1;

	for (rl_size = 0; na->rl[rl_size].length; rl_size++)
		;
	rl_size++;	/* count the terminator too */

	new_rl = ntfs_rl_punch_hole(na->rl, rl_size, start_vcn, len, &punch_rl);
	if (!new_rl)
		return -1;
	na->rl = new_rl;

	/* Release the clusters that used to back the (now dead) unit. */
	if (punch_rl) {
		ntfs_cluster_free_from_rl(vol, punch_rl);
		free(punch_rl);
	}

	/* Recompute the compressed size from the new (holier) runlist. */
	na->compressed_size = ntfs_rl_get_compressed_size(vol, na->rl);

	NAttrSetRunlistDirty(na);
	if (ntfs_attr_update_mapping_pairs(na, 0))
		return -1;

	ntfs_inode_mark_dirty(na->ni);
	return 0;
}
/*
 * The hard link count in the MFT record header must equal the number of
 * $FILE_NAME attributes of the record: every name, including a separate
 * DOS short name, is one $FILE_NAME plus one index entry in a directory.
 * The directory walk verifies the index-entry side of every name (and
 * the orphan pass rebuilds it), so counting the attributes completes the
 * link accounting. A wrong count is dangerous in both directions: too
 * low frees the record while names still point at it, too high keeps a
 * deleted record allocated forever.
 *
 * A record without any $FILE_NAME is left alone: the name checks that
 * follow remove the referencing index entry and hand the record to the
 * orphan pass, which does its own link accounting.
 */
static void ntfsck_check_link_count(ntfs_inode *ni)
{
	ntfs_attr_search_ctx *ctx;
	u16 nlink = 0;
	int walk_err;
	problem_context_t pctx = {0, };

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		return;

	while (!ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0,
				CASE_SENSITIVE, 0, NULL, 0, ctx))
		nlink++;
	walk_err = errno;
	ntfs_attr_put_search_ctx(ctx);

	/* The walk itself failed: this count proves nothing. */
	if (walk_err != ENOENT)
		return;

	if (!nlink || nlink == le16_to_cpu(ni->mrec->link_count))
		return;

	ntfs_init_problem_ctx(&pctx, ni, NULL, NULL, NULL, ni->mrec,
			NULL, NULL);
	pctx.dsize = nlink;
	fsck_err_found();
	if (ntfs_fix_problem(ni->vol, PR_MFT_LINK_COUNT_MISMATCH, &pctx)) {
		ni->mrec->link_count = cpu_to_le16(nlink);
		ntfs_inode_mark_dirty(ni);
		fsck_err_fixed();
	}
}

static int ntfsck_check_inode(ntfs_inode *ni, INDEX_ENTRY *ie,
		ntfs_index_context *ictx)
{
	FILE_NAME_ATTR *ie_fn = (FILE_NAME_ATTR *)&ie->key.file_name;
	int32_t flags;
	int ret;

	ret = ntfsck_check_inode_non_resident(ni, 1);
	if (ret)
		goto err_out;

	if (ni->attr_list) {
		if (ntfsck_check_attr_list(ni))
			goto err_out;

		if (ntfs_inode_attach_all_extents(ni))
			goto err_out;
	}

	ntfsck_check_link_count(ni);

	if (ntfsck_check_inode_fields(ictx->ni, ni, ie, ictx))
		goto remove_index_out;

	/* Check file type */
	flags = ntfsck_check_file_type(ni, ictx, ie_fn);
	if (flags < 0)
		goto remove_index_out;

	if (flags & FILE_ATTR_I30_INDEX_PRESENT) {
		ret = ntfsck_check_directory(ni);
		if (ret)
			goto remove_index_out;
	} else if (flags & FILE_ATTR_VIEW_INDEX_PRESENT) {
		ret = ntfsck_check_view_index(ni);
		if (ret)
			goto remove_index_out;
	} else if (ni->mrec->flags & MFT_RECORD_IS_4) {
		ret = ntfsck_check_extend_inode(ni);
		if (ret)
			goto remove_index_out;
	} else {
		ret = ntfsck_check_file(ni);
		if (ret)
			goto remove_index_out;
	}

	/* validate extended attribute chain ($EA / $EA_INFORMATION) */
	ntfsck_check_ea(ni);

	/* validate reparse point ($REPARSE_POINT / $Extend/$Reparse) */
	ntfsck_check_reparse(ni);

	/* validate compression units of compressed data attributes */
	ntfsck_check_compressed(ni);

	/* check $FILE_NAME */
	ret = ntfsck_check_file_name_attr(ni, ie_fn, ictx);
	if (ret < 0)
		goto remove_index_out;

	/* FALSE or TRUE? */
	ntfsck_set_mft_record_bitmap(ni, FALSE);
	return STATUS_OK;

remove_index_out:
	ntfsck_check_inode_non_resident(ni, 0);
	return STATUS_NOT_FOUND;

err_out:
	ntfsck_check_inode_non_resident(ni, 0);
	return STATUS_ERROR;
}

static int ntfsck_check_system_inode_detail(ntfs_inode *ni)
{
	if (!ni)
		return STATUS_ERROR;

	switch (ni->mft_no) {
	case FILE_MFT:
	case FILE_MFTMirr:
	case FILE_LogFile:
	case FILE_AttrDef:
	case FILE_Bitmap:
	case FILE_Boot:
	case FILE_BadClus:
	case FILE_UpCase:
		return ntfsck_check_file(ni);
	default:
		return STATUS_OK;
	}
}

static int ntfsck_check_extend_inode(ntfs_inode *ni)
{
	ntfs_attr_search_ctx *ctx;
	BOOL has_data = FALSE;
	BOOL has_logged_stream = FALSE;
	BOOL has_unnamed_data = FALSE;
	int ret;

	if (!ni)
		return STATUS_ERROR;

	if (ntfs_attr_exist(ni, AT_INDEX_ROOT, NTFS_INDEX_Q, 2) ||
			ntfs_attr_exist(ni, AT_INDEX_ROOT, NTFS_INDEX_O, 2) ||
			ntfs_attr_exist(ni, AT_INDEX_ROOT, NTFS_INDEX_R, 2))
		return ntfsck_check_view_index(ni);

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		return STATUS_ERROR;

	while (!(ret = ntfs_attrs_walk(ctx))) {
		if (ctx->attr->type == AT_DATA) {
			has_data = TRUE;
			if (!ctx->attr->name_length)
				has_unnamed_data = TRUE;
		} else if (ctx->attr->type == AT_LOGGED_UTILITY_STREAM) {
			has_logged_stream = TRUE;
		}
	}

	if (ret == -1 && errno == ENOENT)
		ret = STATUS_OK;

	ntfs_attr_put_search_ctx(ctx);
	if (ret)
		return STATUS_ERROR;

	if (has_unnamed_data)
		return ntfsck_check_file(ni);

	if (has_data || has_logged_stream)
		return STATUS_OK;

	ntfs_log_error("$Extend sub-file inode(%"PRIu64") has no data or "
			"logged utility stream\n", ni->mft_no);
	return STATUS_ERROR;
}

static int ntfsck_check_system_inode(ntfs_inode *ni, INDEX_ENTRY *ie,
		ntfs_index_context *ictx)
{
	int ret;

	ret = ntfsck_check_inode_non_resident(ni, 1);
	if (ret)
		goto err_out;

	if (ni->attr_list) {
		if (ntfsck_check_attr_list(ni))
			goto err_out;

		if (ntfs_inode_attach_all_extents(ni))
			goto err_out;
	}

	ntfsck_check_link_count(ni);

	if (ntfsck_check_inode_fields(ictx->ni, ni, ie, ictx))
		goto err_out;

	if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
		ret = ntfsck_check_directory(ni);
		if (ret)
			goto err_out;
	} else if (ni->mrec->flags & MFT_RECORD_IS_VIEW_INDEX) {
		ret = ntfsck_check_view_index(ni);
		if (ret)
			goto err_out;
	}

	ret = ntfsck_check_system_inode_detail(ni);
	if (ret)
		goto err_out;

	ntfsck_set_mft_record_bitmap(ni, FALSE);
	return STATUS_OK;

err_out:
	ntfsck_check_inode_non_resident(ni, 0);
	return STATUS_ERROR;
}

static int ntfsck_check_orphan_inode(ntfs_inode *parent_ni, ntfs_inode *ni)
{
	int ret;

	if (ntfsck_check_orphan_inode_fields(parent_ni, ni))
		goto out;

	ret = ntfsck_check_inode_non_resident(ni, 1);
	if (ret)
		goto err_out;

	if (ni->attr_list) {
		if (ntfsck_check_attr_list(ni))
			goto err_out;

		if (ntfs_inode_attach_all_extents(ni))
			goto err_out;
	}

	if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
		ret = ntfsck_check_directory(ni);
		if (ret)
			goto err_out;
	} else if (ni->mrec->flags & MFT_RECORD_IS_VIEW_INDEX) {
		ret = ntfsck_check_view_index(ni);
		if (ret)
			goto err_out;
	} else if (ni->mrec->flags & MFT_RECORD_IS_4) {
		ret = ntfsck_check_extend_inode(ni);
		if (ret)
			goto err_out;
	} else {
		ret = ntfsck_check_file(ni);
		if (ret)
			goto err_out;
	}

	/*
	 * Re-linked orphans must get the same attribute validation as inodes
	 * reached through the normal directory walk (see ntfsck_check_inode());
	 * otherwise corruption inside an orphan -- a bad reparse point, a broken
	 * $EA chain, an undecompressable unit -- survives the recovery pass and
	 * is only caught on the next full run, so ntfsck never converges.
	 */
	ntfsck_check_ea(ni);
	ntfsck_check_reparse(ni);
	ntfsck_check_compressed(ni);

	return STATUS_OK;

err_out:
	ntfsck_check_inode_non_resident(ni, 0);
out:
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

		/*
		 * Checking for system files or not. Deliberately do not use
		 * utils_is_metadata() here: it also matches ordinary user files carrying
		 * SYSTEM|HIDDEN attributes (e.g. bootmgr, "System Volume Information").
		 */
		if ((utils_is_system_metadata(ni) == 1) ||
				((utils_is_system_metadata(ictx->ni) == 1) &&
				 (ictx->ni->mft_no != FILE_root))) {
			/*
			 * Do not check return value because system files can be deleted.
			 * this check may be already done in check system files.
			 */
			ret = ntfsck_check_system_inode(ni, ie, ictx);
		} else {
			ret = ntfsck_check_inode(ni, ie, ictx);
			if (ret == STATUS_NOT_FOUND) {
				ntfs_log_error("Failed to check inode(%"PRIu64") "
						"in parent(%"PRIu64") index.\n",
						ni->mft_no, ictx->ni->mft_no);

				NInoFileNameClearDirty(ni);
				NInoAttrListClearDirty(ni);
				NInoClearDirty(ni);

				/* Do not clear bitmap on disk */
				ntfsck_close_inode(ni);
				goto remove_index;
			} else if (ret) {
				ntfs_log_error("Failed to validate inode(%"PRIu64") "
						"from parent(%"PRIu64") without deleting its "
						"index entry.\n",
						ni->mft_no, ictx->ni->mft_no);
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
		} else {
			/*
			 * Removal declined (no-repair mode): the error is
			 * counted, keep walking the remaining entries instead
			 * of aborting the whole directory scan.
			 */
			ret = STATUS_OK;
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
	s64 pos;	/* ib index of vcn */
	u32 bpos;	/* byte position in bitmap for ib index of vcn */
	u32 old_size;
	u32 new_size;
	u8 *new_ibm;
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
		old_size = ictx->ni->fsck_ibm_size;
		new_size = (bpos + 1 + 7) & ~7U;
		new_ibm = ntfs_realloc(ictx->ni->fsck_ibm, new_size);
		if (!new_ibm) {
			ntfs_log_perror("Failed to realloc fsck_ibm(%"PRId64")",
					(s64)new_size);
			return STATUS_ERROR;
		}

		ictx->ni->fsck_ibm = new_ibm;
		memset(ictx->ni->fsck_ibm + old_size, 0, new_size - old_size);
		ictx->ni->fsck_ibm_size = new_size;
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
	s64 old_size;
	u8 *ni_ibm = NULL;	/* for index bitmap reading from disk: $BITMAP */
	u8 *new_ibm = NULL;
	ntfs_volume *vol;
	int ret = STATUS_OK;
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
		ntfs_log_error("\nBitmap changed during check_inodes\n");
		fsck_err_found();

		if (ni->fsck_ibm_size < ibm_size) {
			old_size = ni->fsck_ibm_size;
			new_ibm = ntfs_realloc(ni->fsck_ibm, ibm_size);
			if (!new_ibm) {
				ret = STATUS_ERROR;
				goto out;
			}
			ni->fsck_ibm = new_ibm;
			memset(ni->fsck_ibm + old_size, 0, ibm_size - old_size);
			ni->fsck_ibm_size = ibm_size;
		}

		if (ntfs_fix_problem(vol, PR_IDX_BITMAP_SIZE_MISMATCH, &pctx)) {
			if (ni->fsck_ibm_size > ibm_size) {
				ntfs_log_error("Refusing to grow $BITMAP of inode(%"PRIu64") "
						"during index bitmap verification\n",
						ni->mft_no);
				ret = STATUS_ERROR;
				goto out;
			}

			wcnt = ntfs_attr_pwrite(bm_na, 0, ibm_size, ni->fsck_ibm);
			if (wcnt == ibm_size)
				fsck_err_fixed();
			else {
				ntfs_log_error("Can't write $BITMAP(%"PRId64") "
						"of inode(%"PRIu64")\n", wcnt, ni->mft_no);
				ret = STATUS_ERROR;
			}
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

	return ret;
}

/*
 * Zero the stale LSN of the index block at byte position @pos after a
 * $LogFile reset. As with MFT records (see ntfsck_reset_mft_lsn()) the LSN is
 * not multi sector protected, so it is poked in place: no fixup round trip,
 * and blocks whose fixup or content is broken get scrubbed all the same.
 */
static void ntfsck_reset_ib_lsn(ntfs_attr *ia_na, s64 pos)
{
	INDEX_BLOCK ib;

	/* magic through lsn: the first 16 bytes are enough */
	if (ntfs_attr_pread(ia_na, pos,
				offsetof(INDEX_BLOCK, index_block_vcn), &ib) !=
			offsetof(INDEX_BLOCK, index_block_vcn))
		return;
	if (!ntfs_is_indx_record(ib.magic) || !ib.lsn)
		return;
	ib.lsn = const_cpu_to_sle64(0);
	ntfs_attr_pwrite(ia_na, pos + offsetof(INDEX_BLOCK, lsn),
			sizeof(ib.lsn), &ib.lsn);
}

static void ntfsck_validate_index_blocks(ntfs_volume *vol,
		ntfs_index_context *ictx)
{
	problem_code_t init_problem = PR_INDEX_INITIALIZE;
	ntfs_attr *bmp_na = NULL;
	INDEX_ALLOCATION *ia;
	INDEX_ENTRY *ie;
	INDEX_HEADER *ih;
	INDEX_ROOT *ir = ictx->ir;
	ntfs_inode *ni = ictx->ni;
	VCN vcn;
	u32 ir_size = le32_to_cpu(ir->index.index_length);
	u32 ir_entries_offset;
	u32 ir_entries_len;
	u8 *ir_buf = NULL, *ia_buf = NULL, *bmp_buf = NULL, *index_end;
	u64 max_ib_bits;
	u32 vcn_per_ib;
	VCN max_vcn;
	int ret = STATUS_OK;
	int ie_ret;
	BOOL ir_repaired = FALSE;
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

	/*
	 * index_length is measured from the start of the INDEX_HEADER, so the
	 * entries occupy only (index_length - entries_offset) bytes. Copy just that
	 * region; using index_length as the copy length would over-read
	 * entries_offset bytes past the last entry (and malloc(0) when index_length
	 * is zero).
	 */
	ir_entries_offset = le32_to_cpu(ir->index.entries_offset);
	if (ir_size < ir_entries_offset ||
			ir_entries_offset < sizeof(INDEX_HEADER)) {
		ntfs_log_error("INDEX_ROOT of inode %"PRIu64" has an invalid "
				"index_length(%u)/entries_offset(%u)\n",
				ni->mft_no, ir_size, ir_entries_offset);
		goto initialize_index;
	}
	ir_entries_len = ir_size - ir_entries_offset;

	ir_buf = malloc(ir_entries_len ? ir_entries_len : 1);
	if (!ir_buf) {
		ntfs_log_error("Failed to allocate ir buffer\n");
		goto out;
	}

	memcpy(ir_buf, (u8 *)&ir->index + ir_entries_offset, ir_entries_len);

	/* check entries in INDEX_ROOT */
	ie = (INDEX_ENTRY *)ir_buf;
	ih = &ir->index;
	index_end = (u8 *)ir_buf + ir_entries_len;
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
						") is in not allocated bitmap cluster\n",
						ni->mft_no);
				goto initialize_index;
			}
		}

		/* The index key must not overflow from the entry. */
		ie_ret = ntfs_index_entry_inconsistent(vol, ie,
				ictx->ir->collation_rule, ni->mft_no, NULL);
		if (ie_ret < 0) {
			ntfs_log_error("Index entry(%p) of inode(%"PRIu64
					") is inconsistent\n", ie, ni->mft_no);
			goto initialize_index;
		}
		if (ie_ret > 0)
			ir_repaired = TRUE;

		/* The last entry cannot contain a name. */
		if (ie->ie_flags & INDEX_ENTRY_END)
			break;

		if (!le16_to_cpu(ie->length))
			break;
	}

	/*
	 * The entries were walked in a scratch copy, so a repair made by
	 * ntfs_index_entry_inconsistent() lives only in ir_buf. Put it back in the
	 * resident INDEX_ROOT and mark the inode dirty; otherwise every repair round
	 * rediscovers the same entry, counts it as found and fixed, and writes
	 * nothing -- fsck never converges.
	 */
	if (ir_repaired) {
		memcpy((u8 *)&ir->index + ir_entries_offset, ir_buf,
				ir_entries_len);
		/*
		 * INDEX_ROOT can be relocated into an extent record, in which
		 * case ir points into that record, not into ni->mrec.
		 */
		if (ictx->actx && ictx->actx->ntfs_ino)
			ntfs_inode_mark_dirty(ictx->actx->ntfs_ino);
		ntfs_inode_mark_dirty(ni);
	}

	ia_buf = ntfs_malloc(ictx->block_size);
	if (!ia_buf) {
		ntfs_log_error("Failed to allocate ia buffer\n");
		goto out;
	}

	max_ib_bits = bmp_na->data_size << NTFSCK_BYTE_TO_BITS;
	max_vcn = ictx->ia_na->data_size >> ictx->vcn_size_bits;
	vcn_per_ib = ictx->block_size >> ictx->vcn_size_bits;

	/* check index block and entries in INDEX_ALLOCATION */
	for (vcn = 0; vcn < max_vcn; vcn += vcn_per_ib) {
		u32 bmp_bit;	/* bit location in $BITMAP for vcn */
		BOOL mst_salvaged = FALSE;
		BOOL ib_repaired = FALSE;

		/* one bit of $Bitmap represents one index block,
		 * so if vcn size is smaller than ib, one bit represent
		 * the multiple number of vcn.(vcn_per_ib) */
		bmp_bit = (vcn << ictx->vcn_size_bits) / ictx->block_size;
		if (max_ib_bits <= bmp_bit)
			break;

		/*
		 * The journal any LSN refers to was reset in parse #1 and a stale value
		 * would make a future log replay skip its redo of this block (see
		 * ntfsck_reset_mft_lsn()). Poked before the bitmap test because allocated
		 * blocks the index bitmap marks free never reach the checks below, yet they
		 * too are re-initialized through the log once the index grows.
		 */
		if (logfile_was_reset)
			ntfsck_reset_ib_lsn(ictx->ia_na,
					vcn << ictx->vcn_size_bits);

		if (!ntfs_bit_get(bmp_buf, bmp_bit))
			continue;

		if (ntfsck_read_index_block(ictx, vcn,
				(INDEX_BLOCK *)ia_buf, &mst_salvaged)) {
			ntfs_log_error("Failed to read index blocks of inode(%"PRIu64"), %d\n",
					ictx->ni->mft_no, errno);
			goto initialize_index;
		}
		if (ntfsck_repair_index_block(ictx, vcn,
				(INDEX_BLOCK *)ia_buf, mst_salvaged))
			goto initialize_index;

		if (ntfs_index_block_inconsistent(vol, ictx->ia_na,
					(INDEX_ALLOCATION *)ia_buf,
					ictx->block_size, ni->mft_no, vcn)) {
			ntfs_log_error("Index block of inode(%"PRIu64") is inconsistent\n",
					ni->mft_no);
			goto initialize_index;
		}

		/* check index entries in a INDEX_ALLOCATION block */
		ia = (INDEX_ALLOCATION *)ia_buf;
		ih = &ia->index;
		index_end = (u8 *)ih + le32_to_cpu(ih->index_length);
		ie = (INDEX_ENTRY *)((u8 *)&ia->index +
				le32_to_cpu(ia->index.entries_offset));

		for (;; ie = (INDEX_ENTRY *)((u8 *)ie + le16_to_cpu(ie->length))) {
			/*
			 * Check the entry bounds before dereferencing ie. Advancing by ie->length
			 * can move ie past index_end (ntfs_index_block_inconsistent() only
			 * validated the block header, not the entry chain), so reading
			 * ie->ie_flags or the sub-node VCN first would over-read the index block
			 * buffer.
			 */
			if (((u8 *)ie < (u8 *)ia) ||
					((u8 *)ie + sizeof(INDEX_ENTRY_HEADER) > index_end) ||
					((u8 *)ie + le16_to_cpu(ie->length) > index_end)) {
				ntfs_log_error("Index entry out of bounds in inode "
						"(%"PRId64")\n", ni->mft_no);
				goto initialize_index;
			}

			/* check bitmap for sub-node */
			if (ie->ie_flags & INDEX_ENTRY_NODE) {
				VCN vcn = ntfs_ie_get_vcn(ie);

				/* calculate bit location in $Bitmap for vcn */
				bmp_bit = (vcn << ictx->vcn_size_bits) / ictx->block_size;
				if (max_ib_bits <= bmp_bit) {
					ntfs_log_error("Subnode of inode(%"PRIu64
							") is larger than max vcn\n",
							ni->mft_no);
					goto initialize_index;
				}

				if (!ntfs_bit_get(bmp_buf, bmp_bit)) {
					ntfs_log_error("Subnode of inode(%"PRIu64
							") is not set on $BITMAP\n",
							ni->mft_no);
					goto initialize_index;
				}
			}

			/* The index key must not overflow from the entry. */
			ie_ret = ntfs_index_entry_inconsistent(vol, ie,
					ictx->ir->collation_rule, ni->mft_no, NULL);
			if (ie_ret < 0) {
				ntfs_log_error("Index entry(%p) of inode(%"PRIu64
						") is inconsistent\n", ie, ni->mft_no);
				goto initialize_index;
			}
			if (ie_ret > 0)
				ib_repaired = TRUE;

			/* The last entry cannot contain a name. */
			if (ie->ie_flags & INDEX_ENTRY_END)
				break;

			if (!le16_to_cpu(ie->length))
				break;
		}

		/*
		 * As with the root, an entry repaired above only exists in ia_buf. Write
		 * the block back rather than rebuilding the whole index: the repair is
		 * enough to make the block walkable, and a discarded one would be
		 * rediscovered on every repair round.
		 */
		if (ib_repaired && ntfs_ib_write(ictx, (INDEX_BLOCK *)ia_buf))
			goto initialize_index;
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

	if (ictx->name_len == 4 &&
			!memcmp(ictx->name, NTFS_INDEX_I30, 4 * sizeof(ntfschar)))
		init_problem = PR_DIR_IDX_INITIALIZE;

	ntfs_init_problem_ctx(&pctx, ni, NULL, NULL, NULL, ni->mrec, NULL, NULL);
	fsck_err_found();
	if (!ntfs_fix_problem(vol, init_problem, &pctx))
		goto out;

	if (ni->mft_no == FILE_root && init_problem == PR_DIR_IDX_INITIALIZE)
		ret = ntfsck_initiaiize_root_index(ni, ictx);
	else
		ret = ntfsck_initialize_named_index_attr(ni,
				ictx->name, ictx->name_len);

	if (ret)
		ntfs_log_perror("Failed to initialize index attributes of inode(%"PRIu64")\n",
				ni->mft_no);
	else
		fsck_err_fixed();

	ntfs_log_info("inode(%"PRIu64") index is initialized\n", ni->mft_no);

	goto out;
}

static int ntfsck_validate_named_index(ntfs_inode *ni,
		ntfschar *name, u32 name_len)
{
	ntfs_attr_search_ctx *ctx = NULL;
	ntfs_index_context *ictx = NULL;
	INDEX_ROOT *ir;
	ntfs_volume *vol;
	int ret = STATUS_ERROR;

	if (!ni || !name || !name_len)
		return STATUS_ERROR;

	vol = ni->vol;
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		return STATUS_ERROR;

	if (ntfs_attr_lookup(AT_INDEX_ROOT, name, name_len, CASE_SENSITIVE,
				0, NULL, 0, ctx)) {
		ntfs_log_perror("Index root attribute missing in inode %"PRId64"",
				ni->mft_no);
		goto out;
	}
	if (ntfsck_repair_named_index_root(ni, ctx))
		goto out;

	ictx = ntfs_index_ctx_get(ni, name, name_len);
	if (!ictx)
		goto out;

	ir = (INDEX_ROOT *)((u8 *)ctx->attr +
			le16_to_cpu(ctx->attr->value_offset));
	ictx->ir = ir;
	ictx->actx = ctx;
	ctx = NULL;
	ictx->parent_vcn[ictx->pindex] = VCN_INDEX_ROOT_PARENT;
	ictx->is_in_root = TRUE;
	ictx->parent_pos[ictx->pindex] = 0;

	ictx->block_size = le32_to_cpu(ir->index_block_size);
	if (ictx->block_size < NTFS_BLOCK_SIZE) {
		ntfs_log_perror("Index block size (%d) is smaller than the "
				"sector size (%d)", ictx->block_size,
				NTFS_BLOCK_SIZE);
		goto out;
	}

	if (vol->cluster_size <= ictx->block_size)
		ictx->vcn_size_bits = vol->cluster_size_bits;
	else
		ictx->vcn_size_bits = NTFS_BLOCK_SIZE_BITS;

	ntfsck_validate_index_blocks(vol, ictx);
	ret = STATUS_OK;

out:
	if (ictx)
		ntfs_index_ctx_put(ictx);
	else if (ctx)
		ntfs_attr_put_search_ctx(ctx);

	return ret;
}

static int ntfsck_check_view_index(ntfs_inode *ni)
{
	struct named_index {
		ntfschar *name;
		u32 name_len;
	};
	static const struct named_index indexes[] = {
		{ NTFS_INDEX_SII, 4 },
		{ NTFS_INDEX_SDH, 4 },
		{ NTFS_INDEX_Q, 2 },
		{ NTFS_INDEX_O, 2 },
		{ NTFS_INDEX_R, 2 },
	};
	int i;
	BOOL found_index = FALSE;

	if (!ni)
		return STATUS_ERROR;

	for (i = 0; i < (int)(sizeof(indexes) / sizeof(indexes[0])); i++) {
		if (!ntfs_attr_exist(ni, AT_INDEX_ROOT,
					indexes[i].name, indexes[i].name_len))
			continue;

		found_index = TRUE;
		if (ntfsck_validate_named_index(ni,
					indexes[i].name, indexes[i].name_len))
			return STATUS_ERROR;
	}

	if (!found_index) {
		ntfs_log_error("View index inode(%"PRIu64") has no known index root\n",
				ni->mft_no);
		return STATUS_ERROR;
	}

	return STATUS_OK;
}

static int ntfsck_remove_index(ntfs_inode *parent_ni, ntfs_index_context *ictx,
		INDEX_ENTRY *ie)
{
	void *key;
	int key_len;

	if (!parent_ni || !ie || !ictx)
		return STATUS_ERROR;

	key = &ie->key;
	key_len = le16_to_cpu(ie->key_length);

	if (ntfs_index_lookup(key, key_len, ictx)) {
		ntfs_log_error("Failed to find index entry of inode(%"PRIu64").\n",
				parent_ni->mft_no);
		return STATUS_ERROR;
	}

	if (ntfs_index_rm(ictx))
		return STATUS_ERROR;

	return STATUS_OK;
}

static int ntfsck_check_lostfound_filename(ntfs_inode *ni, ntfs_index_context *ictx)
{
	FILE_NAME_ATTR *fn;
	ATTR_RECORD *attr;
	ntfs_attr_search_ctx *actx = NULL;
	ntfs_inode *root_ni = NULL;
	int ret;

	if (!ni || !ictx || !ictx->ni)
		return STATUS_ERROR;

	root_ni = ictx->ni;

	actx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!actx)
		return STATUS_ERROR;

	ret = ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, CASE_SENSITIVE,
			0, NULL, 0, actx);
	if (ret) {
		ntfs_attr_put_search_ctx(actx);
		return STATUS_ERROR;
	}

	attr = actx->attr;
	fn = (FILE_NAME_ATTR *)((u8 *)attr + le16_to_cpu(attr->value_offset));

	if (ntfs_index_lookup(fn, sizeof(FILE_NAME_ATTR), ictx)) {
		ntfs_attr_put_search_ctx(actx);
		return STATUS_ERROR;
	}

	if (MREF_LE(fn->parent_directory) != FILE_root) {
		fn->parent_directory = MK_LE_MREF(FILE_root,
				le16_to_cpu(root_ni->mrec->sequence_number));
		ntfs_inode_mark_dirty(ni);
	}
	ntfs_attr_put_search_ctx(actx);
	return STATUS_OK;
}

static void ntfsck_create_lost_found(ntfs_volume *vol, ntfs_inode *root_ni)
{
	ntfs_inode *lf_ni = NULL; /* lost+found inode */
	int ucs_namelen;
	ntfschar *ucs_name = (ntfschar *)NULL;

	ucs_namelen = ntfs_mbstoucs(FILENAME_LOST_FOUND, &ucs_name);
	if (ucs_namelen < 0)
		return;

	if (!NVolReadOnly(vol)) {
		lf_ni = ntfs_create(root_ni, 0, ucs_name, ucs_namelen, S_IFDIR);
		if (!lf_ni) {
			ntfs_log_error("Failed to create 'lost+found'\n");
			free(ucs_name);
			return;
		}
		ntfs_log_info("%s(%"PRIu64") created\n",
				FILENAME_LOST_FOUND, lf_ni->mft_no);
		vol->lost_found = lf_ni->mft_no;
		ntfsck_set_mft_record_bitmap(lf_ni, TRUE);
		ntfsck_close_inode(lf_ni);
	}

	free(ucs_name);
}

static void ntfsck_check_lost_found(ntfs_volume *vol, ntfs_inode *root_ni,
		ntfs_index_context *ictx)
{
	ntfs_inode *lf_ni = NULL;	/* lost+found inode */
	u64 lf_mftno = (u64)-1;		/* lost+found mft record number */
	INDEX_ENTRY *ie = NULL;
	int ucs_namelen;
	ntfschar *ucs_name = (ntfschar *)NULL;

	ucs_namelen = ntfs_mbstoucs(FILENAME_LOST_FOUND, &ucs_name);
	if (ucs_namelen < 0)
		return;

	ie = __ntfs_inode_lookup_by_name(root_ni, ucs_name, ucs_namelen);
	if (ie) {
		lf_mftno = le64_to_cpu(ie->indexed_file);
		lf_ni = ntfsck_open_inode(vol, MREF(lf_mftno));
		if (!lf_ni) {
			ntfs_log_verbose("Failed to open %s(%"PRIu64").\n",
					FILENAME_LOST_FOUND, MREF(lf_mftno));
			goto err_out;
		}

		/* inode check and parent mft check */
		if (ntfsck_check_lostfound_filename(lf_ni, ictx))
			goto err_out;

		vol->lost_found = lf_ni->mft_no;
		free(ie);
	}

	free(ucs_name);

	if (lf_ni)
		ntfsck_close_inode(lf_ni);
	return;

err_out:
	if (lf_ni)
		ntfsck_close_inode(lf_ni);
	ntfsck_remove_index(root_ni, ictx, ie);
	vol->lost_found = 0;
	if (ie)
		free(ie);
	free(ucs_name);
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

		/*
		 * Repair INDEX_ROOT header fields (index_block_size,
		 * clusters_per_index_block, collation_rule, entries_offset, index_length,
		 * ...) before trusting ir->index_block_size below. View indexes get this
		 * through ntfsck_validate_named_index(); the directory $I30 path needs the
		 * same fix-up, otherwise a corrupt header makes the whole directory skip
		 * repair.
		 */
		if (ntfsck_repair_named_index_root(dir_ni, ctx)) {
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
		next = (INDEX_ENTRY *)((u8 *)&ir->index +
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
				dir_ni->fsck_ibm = ntfs_calloc(bm_na->data_size);
				if (!dir_ni->fsck_ibm) {
					ntfs_log_perror("Failed to allocate fsck_ibm memory\n");
					goto err_continue;
				}
				dir_ni->fsck_ibm_size = bm_na->data_size;
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

	if (total_cnt < checked_cnt)
		total_cnt = 0;
	else
		total_cnt -= checked_cnt;

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

/* Flush every pending device write to stable storage. */
static int ntfsck_device_sync(ntfs_volume *vol)
{
	if (!vol || !vol->dev || !vol->dev->d_ops || !vol->dev->d_ops->sync)
		return STATUS_OK;
	return vol->dev->d_ops->sync(vol->dev);
}

static BOOL ntfsck_repair_enabled(void)
{
	return (option.flags & (NTFS_MNT_FS_AUTO_REPAIR |
				NTFS_MNT_FS_ASK_REPAIR |
				NTFS_MNT_FS_YES_REPAIR)) != 0;
}

/*
 * ntfsck_begin_repair - open a crash-safe repair transaction.
 *
 * Before the first repair write, durably record on disk that a repair is in
 * progress by making sure VOLUME_IS_DIRTY is set and flushed. If ntfsck is
 * then interrupted, the volume stays marked dirty and is re-checked on the
 * next run instead of being trusted as clean. This is the same fail-safe
 * guarantee a write-ahead log provides - an interrupted repair never leaves
 * the volume advertised as consistent - enforced here at the volume level.
 * The matching commit is ntfsck_reset_dirty(), which only runs after all
 * repair writes have been flushed (see main()).
 */
static int ntfsck_begin_repair(ntfs_volume *vol)
{
	if (!ntfsck_repair_enabled())
		return STATUS_OK;

	if (!(vol->flags & VOLUME_IS_DIRTY)) {
		le16 flags = vol->flags | VOLUME_IS_DIRTY;

		if (ntfs_volume_write_flags(vol, flags)) {
			ntfs_log_error("Failed to mark volume dirty before "
					"repair.\n");
			return STATUS_ERROR;
		}
	}

	/* Make the in-progress marker durable before touching metadata. */
	if (ntfsck_device_sync(vol))
		ntfs_log_verbose("Warning: could not flush the dirty marker.\n");

	return STATUS_OK;
}

static int ntfsck_reset_dirty(ntfs_volume *vol)
{
	le16 flags;

	if (!(vol->flags & VOLUME_IS_DIRTY))
		return STATUS_OK;

	ntfs_log_verbose("Resetting dirty flag.\n");

	/*
	 * Commit point of the repair transaction: every repair write must be
	 * on stable storage before the volume is advertised clean, otherwise a
	 * power loss between clearing the flag and flushing the data would
	 * leave a "clean" but inconsistent volume.
	 */
	if (ntfsck_device_sync(vol))
		ntfs_log_verbose("Warning: device sync before clearing dirty "
				"flag failed.\n");

	flags = vol->flags & ~VOLUME_IS_DIRTY;

	if (ntfs_volume_write_flags(vol, flags)) {
		ntfs_log_error("Error setting volume flags.\n");
		return STATUS_ERROR;
	}
	return 0;
}

/*
 * ntfsck_logfile_is_dirty - does $LogFile hold journal data that needs a reset?
 *
 * ntfsck cannot replay the journal, so its only recovery is to empty $LogFile.
 * But an already empty journal, or one the last OS left cleanly closed, carries
 * nothing to replay, and rewriting it every run just churns the disk and nags
 * the operator. Return TRUE only when the journal is genuinely dirty:
 *   - ntfs_check_logfile() found it inconsistent (unreadable restart pages);
 *   - or it holds a restart area whose client list is still in use and which is
 *     not flagged RESTART_VOLUME_IS_CLEAN (i.e. an unclean shutdown).
 * An empty journal (NVolLogFileEmpty) or a clean restart area returns FALSE.
 */
static BOOL ntfsck_logfile_is_dirty(ntfs_volume *vol)
{
	ntfs_inode *ni;
	ntfs_attr *na;
	RESTART_PAGE_HEADER *rp = NULL;
	const RESTART_AREA *ra;
	BOOL dirty = TRUE;

	ni = ntfs_inode_open(vol, FILE_LogFile);
	if (!ni)
		return TRUE;
	na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
	if (!na) {
		ntfs_inode_close(ni);
		return TRUE;
	}

	if (!ntfs_check_logfile(na, &rp)) {
		/* Inconsistent journal: reset is the only way out. */
		dirty = TRUE;
	} else if (NVolLogFileEmpty(vol)) {
		/* Already empty, nothing to replay. */
		dirty = FALSE;
	} else if (rp) {
		ra = (const RESTART_AREA *)((const u8 *)rp +
				le16_to_cpu(rp->restart_area_offset));
		/* Clean iff no client is in use or the volume-clean bit is set. */
		if (ra->client_in_use_list == LOGFILE_NO_CLIENT ||
				(ra->flags & RESTART_VOLUME_IS_CLEAN))
			dirty = FALSE;
	} else {
		/* Consistent journal with no restart area: treat as clean. */
		dirty = FALSE;
	}

	free(rp);
	ntfs_attr_close(na);
	ntfs_inode_close(ni);
	return dirty;
}

/*
 * Zero the LSN a cached MFT record buffer carries, so that a later sync
 * of the inode cannot write a stale value over what
 * ntfsck_reset_mft_lsn() put on disk.
 */
static void ntfsck_zero_cached_lsn(ntfs_inode *ni)
{
	s32 i;

	if (!ni)
		return;

	ni->mrec->lsn = const_cpu_to_sle64(0);
	for (i = 0; i < ni->nr_extents; i++)
		ni->extent_nis[i]->mrec->lsn = const_cpu_to_sle64(0);
}

/*
 * Every LSN on the volume refers to the journal that was just thrown
 * away. The next driver to mount initializes a fresh log whose LSNs
 * restart low, and recovery decides "this update is already on disk" by
 * comparing a record's LSN against a log record's LSN, so a stale large
 * LSN makes a future replay silently skip its redo and corrupt the
 * volume long after fsck ran. Zero the field in every MFT record, the
 * state mkntfs creates alongside an empty journal.
 *
 * The LSN sits in the first sector and is no sector tail, so it is not
 * multi sector protected: write it in place, with no fixup round trip.
 * That also scrubs free records whose own fixup header is corrupted,
 * which a protected write could never reach. Index blocks carry an LSN
 * too; ntfsck_validate_index_blocks() pokes those the same way, as it
 * is the one place every allocated index block already passes through.
 *
 * The long-lived inodes the mount opened still cache their records with
 * the old LSN, so those buffers are scrubbed as well lest a later sync
 * write the stale value back.
 */
static void ntfsck_reset_mft_lsn(ntfs_volume *vol)
{
	MFT_RECORD *mrec;
	s64 nr_mft_records, mft_num, pos;
	s64 reset_cnt = 0;

	mrec = ntfs_malloc(vol->mft_record_size);
	if (!mrec)
		return;

	nr_mft_records = vol->mft_na->initialized_size >>
			vol->mft_record_size_bits;
	for (mft_num = 0; mft_num < nr_mft_records; mft_num++) {
		pos = mft_num << vol->mft_record_size_bits;
		/* magic through lsn: the first 16 bytes are enough */
		if (ntfs_attr_pread(vol->mft_na, pos,
					offsetof(MFT_RECORD, sequence_number),
					mrec) !=
				offsetof(MFT_RECORD, sequence_number))
			continue;
		if (!ntfs_is_file_record(mrec->magic) || !mrec->lsn)
			continue;
		mrec->lsn = const_cpu_to_sle64(0);
		if (ntfs_attr_pwrite(vol->mft_na,
					pos + offsetof(MFT_RECORD, lsn),
					sizeof(mrec->lsn), &mrec->lsn) !=
				sizeof(mrec->lsn)) {
			ntfs_log_error("Failed to reset LSN of mft record(%"
					PRId64")\n", mft_num);
			continue;
		}
		if (mft_num < vol->mftmirr_size)
			ntfs_attr_pwrite(vol->mftmirr_na,
					pos + offsetof(MFT_RECORD, lsn),
					sizeof(mrec->lsn), &mrec->lsn);
		reset_cnt++;
	}
	ntfs_free(mrec);

	ntfsck_zero_cached_lsn(vol->mft_ni);
	ntfsck_zero_cached_lsn(vol->mftmirr_ni);
	ntfsck_zero_cached_lsn(vol->vol_ni);
	ntfsck_zero_cached_lsn(vol->lcnbmp_ni);
	ntfsck_zero_cached_lsn(vol->secure_ni);

	ntfs_log_info("Reset LSN of %"PRId64" mft records\n", reset_cnt);
}

/*
 * Zero the stale LSN of every block of one named index allocation.
 * ntfsck_validate_index_blocks() covers the indexes the directory walk
 * reaches, but $Secure never enters that walk (ntfsck_check_index()
 * skips the inodes the mount holds open), so its $SDH/$SII blocks are
 * swept here right after the $LogFile reset.
 */
static void ntfsck_reset_named_ia_lsn(ntfs_inode *ni, ntfschar *name,
		u32 name_len)
{
	ntfs_attr_search_ctx *ctx;
	INDEX_ROOT *ir;
	ntfs_attr *ia_na;
	u32 block_size;
	s64 pos;

	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		return;
	if (ntfs_attr_lookup(AT_INDEX_ROOT, name, name_len, CASE_SENSITIVE,
				0, NULL, 0, ctx)) {
		ntfs_attr_put_search_ctx(ctx);
		return;
	}
	ir = (INDEX_ROOT *)((u8 *)ctx->attr +
			le16_to_cpu(ctx->attr->value_offset));
	block_size = le32_to_cpu(ir->index_block_size);
	ntfs_attr_put_search_ctx(ctx);
	if (block_size < NTFS_BLOCK_SIZE)
		return;

	ia_na = ntfs_attr_open(ni, AT_INDEX_ALLOCATION, name, name_len);
	if (!ia_na)
		return;
	for (pos = 0; pos + block_size <= ia_na->data_size; pos += block_size)
		ntfsck_reset_ib_lsn(ia_na, pos);
	ntfs_attr_close(ia_na);
}

static void ntfsck_reset_secure_lsn(ntfs_volume *vol)
{
	if (!vol->secure_ni)
		return;

	ntfsck_reset_named_ia_lsn(vol->secure_ni, NTFS_INDEX_SDH, 4);
	ntfsck_reset_named_ia_lsn(vol->secure_ni, NTFS_INDEX_SII, 4);
}

static int ntfsck_replay_log(ntfs_volume *vol)
{
	problem_context_t pctx = {0, };

	fsck_start_step("Reset logfile...");

	/*
	 * ntfsck cannot replay the journal, so a dirty $LogFile is emptied. A
	 * journal that is already empty or was cleanly closed needs nothing, so
	 * leave it untouched rather than resetting it on every run.
	 */
	if (!ntfsck_logfile_is_dirty(vol)) {
		ntfs_log_verbose("$LogFile is empty or clean, no reset needed\n");
		fsck_end_step();
		return STATUS_OK;
	}

	ntfs_log_info("ntfsck does not support log replay, $LogFile needs reset\n");

	/*
	 * The actual reset is gated on ntfs_fix_problem(): with -n it returns FALSE
	 * (and the volume is read-only anyway), so $LogFile is left untouched. Only
	 * announce the reset when it is really performed.
	 */
	if (ntfs_fix_problem(vol, PR_RESET_LOG_FILE, &pctx)) {
		ntfs_log_info("Resetting $LogFile\n");
		if (ntfs_logfile_reset(vol)) {
			check_failed("ntfs logfile reset failed, errno : %d\n", errno);
			return STATUS_ERROR;
		}
		logfile_was_reset = TRUE;
		ntfsck_reset_mft_lsn(vol);
		ntfsck_reset_secure_lsn(vol);
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

/*
 * $SDS layout constants. Security descriptors are stored in 0x40000-byte
 * blocks that alternate primary / backup: block 0 is primary, block 1 holds
 * the byte-for-byte backup of block 0, block 2 is primary again, and so on.
 */
#define NTFSCK_SDS_BLOCK	0x40000
#define NTFSCK_SDS_ALIGN	16
/* On-disk $SDS entry header size (before the embedded descriptor). */
#define NTFSCK_SDS_HDR		((u32)offsetof(SDS_ENTRY, sid))

/*
 * ntfsck_security_hash - Windows security-descriptor hash.
 *
 * The hash accumulates 32-bit little-endian words of the self-relative
 * descriptor with a rotate-left-by-3 between each step. This is the value
 * cached in the $SDS entry header and mirrored in the $SII / $SDH indices.
 */
static le32 ntfsck_security_hash(const SECURITY_DESCRIPTOR_RELATIVE *sd, u32 len)
{
	const le32 *pos = (const le32 *)sd;
	const le32 *end = pos + (len >> 2);
	u32 hash = 0;

	while (pos < end) {
		hash = (hash << 3) | (hash >> (32 - 3));
		hash += le32_to_cpu(*pos);
		pos++;
	}
	return cpu_to_le32(hash);
}

/*
 * ntfsck_check_secure_index - cross-check one $SDS entry against $SII or $SDH.
 *
 * The index must hold an entry for @key whose cached header
 * {hash, security_id, offset, length} matches the $SDS entry @ref. A missing
 * or disagreeing index entry means the security database is inconsistent.
 * Read-only: inconsistencies are reported, never rewritten.
 */
static void ntfsck_check_secure_index(ntfs_volume *vol,
		ntfs_index_context *ictx, const void *key, int key_len,
		const SECURITY_DESCRIPTOR_HEADER *ref, problem_code_t pcode,
		const char *idxname, problem_context_t *pctx)
{
	const INDEX_ENTRY *ie;
	const SECURITY_DESCRIPTOR_HEADER *h;
	u16 doff;

	if (!ictx)
		return;		/* index absent - already reported by caller */

	ntfs_index_ctx_reinit(ictx);
	if (ntfs_index_lookup(key, key_len, ictx)) {
		fsck_err_found();
		ntfs_log_error("$Secure %s: no index entry for security_id %u "
				"(offset %"PRIu64")\n", idxname,
				le32_to_cpu(ref->security_id),
				le64_to_cpu(ref->offset));
		ntfs_fix_problem(vol, pcode, pctx);
		return;
	}

	/*
	 * The entry data (a SECURITY_DESCRIPTOR_HEADER for both $SII and $SDH)
	 * lives at ie->data_offset, not at ictx->data (which points at the key).
	 */
	ie = ictx->entry;
	doff = le16_to_cpu(ie->data_offset);
	if (doff + sizeof(*h) > le16_to_cpu(ie->length)) {
		fsck_err_found();
		ntfs_log_error("$Secure %s: index entry for security_id %u "
				"has a truncated data record (offset %"PRIu64")\n",
				idxname, le32_to_cpu(ref->security_id),
				le64_to_cpu(ref->offset));
		ntfs_fix_problem(vol, pcode, pctx);
		return;
	}

	h = (const SECURITY_DESCRIPTOR_HEADER *)((const u8 *)ie + doff);
	if (h->hash != ref->hash || h->security_id != ref->security_id ||
			h->offset != ref->offset || h->length != ref->length) {
		fsck_err_found();
		ntfs_log_error("$Secure %s: index entry for security_id %u "
				"disagrees with $SDS (offset %"PRIu64")\n",
				idxname, le32_to_cpu(ref->security_id),
				le64_to_cpu(ref->offset));
		ntfs_fix_problem(vol, pcode, pctx);
	}
}

/*
 * ntfsck_secure_is_live - is this $SDS entry part of the authoritative live set?
 *
 * $SDS is not a densely packed array: Windows leaves gaps and stale descriptors
 * between live entries as security_ids are added and retired, and only the $SII
 * index (keyed by security_id) authoritatively enumerates the descriptors the
 * filesystem actually uses. An entry is live iff $SII lists its security_id and
 * points back at the very offset the entry occupies; anything else is dead space
 * that must not be validated or reported as corrupt.
 */
static int ntfsck_secure_is_live(ntfs_index_context *sii, le32 sid, le64 offset)
{
	const INDEX_ENTRY *ie;
	const SECURITY_DESCRIPTOR_HEADER *h;
	SII_INDEX_KEY key;
	u16 doff;

	if (!sii)
		return 0;

	ntfs_index_ctx_reinit(sii);
	key.security_id = sid;
	if (ntfs_index_lookup(&key, sizeof(key), sii))
		return 0;

	ie = sii->entry;
	doff = le16_to_cpu(ie->data_offset);
	if (doff + sizeof(*h) > le16_to_cpu(ie->length))
		return 0;

	h = (const SECURITY_DESCRIPTOR_HEADER *)((const u8 *)ie + doff);
	return h->offset == offset;
}

/*
 * Does @ictx already hold an entry for @key whose cached header matches @ref?
 * The read-only counterpart of ntfsck_check_secure_index(), used to decide
 * whether $SDH needs rebuilding without reporting each descriptor.
 */
static BOOL ntfsck_secure_index_present(ntfs_index_context *ictx,
		const void *key, int key_len,
		const SECURITY_DESCRIPTOR_HEADER *ref)
{
	const INDEX_ENTRY *ie;
	const SECURITY_DESCRIPTOR_HEADER *h;
	u16 doff;

	if (!ictx)
		return FALSE;

	ntfs_index_ctx_reinit(ictx);
	if (ntfs_index_lookup(key, key_len, ictx))
		return FALSE;

	ie = ictx->entry;
	doff = le16_to_cpu(ie->data_offset);
	if (doff + sizeof(*h) > le16_to_cpu(ie->length))
		return FALSE;

	h = (const SECURITY_DESCRIPTOR_HEADER *)((const u8 *)ie + doff);
	return h->hash == ref->hash && h->security_id == ref->security_id &&
			h->offset == ref->offset && h->length == ref->length;
}

/*
 * ntfsck_rebuild_secure_sdh - regenerate $Secure's $SDH index from $SDS/$SII.
 *
 * $SDH is a pure accelerator: it maps a descriptor's hash to the same
 * {hash, security_id, offset, length} header $SII already holds, so it can be
 * rebuilt losslessly from the two authoritative sources without touching a
 * single access control entry. That is the only safe way to repair it -- the
 * index block itself may be gone -- and it is exactly what an interrupted
 * "add security descriptor" transaction leaves behind: $SDS and $SII updated,
 * $SDH not.
 *
 * Empty $SDH (dropping its now corrupt index allocation and bitmap, resetting
 * the root to a bare end entry), then walk $SDS and re-insert one entry for
 * every descriptor $SII still lists as live. @sii must be present and sound;
 * without it the live set is unknowable and the index must be left alone.
 */
static int ntfsck_rebuild_secure_sdh(ntfs_inode *ni, ntfs_index_context *sii)
{
	ntfs_attr *na = NULL;
	u8 *pbuf = NULL;
	u8 iebuf[sizeof(INDEX_ENTRY)];
	INDEX_ENTRY *ie = (INDEX_ENTRY *)iebuf;
	SDH_INDEX_DATA *sdh_data;
	s64 data_size, base;
	int ret = -1;

	if (!sii)
		return -1;

	/* Empty $SDH so it can be repopulated from scratch. */
	if (ntfsck_initialize_named_index_attr(ni, NTFS_INDEX_SDH, 4))
		return -1;

	na = ntfs_attr_open(ni, AT_DATA, STREAM_SDS, 4);
	if (!na)
		goto out;
	data_size = na->data_size;

	pbuf = ntfs_malloc(NTFSCK_SDS_BLOCK);
	if (!pbuf)
		goto out;

	for (base = 0; base < data_size; base += 2 * NTFSCK_SDS_BLOCK) {
		s64 plen = data_size - base;
		s64 p;

		if (plen > NTFSCK_SDS_BLOCK)
			plen = NTFSCK_SDS_BLOCK;
		if (ntfs_attr_pread(na, base, plen, pbuf) != plen)
			goto out;

		p = 0;
		while (p + (s64)NTFSCK_SDS_HDR <= plen) {
			SDS_ENTRY *e = (SDS_ENTRY *)(pbuf + p);
			u32 length = le32_to_cpu(e->length);
			ntfs_index_context *sdh;
			int add_err;

			if (!length && !le32_to_cpu(e->security_id))
				break;
			if (le64_to_cpu(e->offset) != (u64)(base + p) ||
					length < NTFSCK_SDS_HDR ||
					p + length > plen) {
				p += NTFSCK_SDS_ALIGN;
				continue;
			}
			if (!ntfsck_secure_is_live(sii, e->security_id, e->offset))
				goto next;

			/* One $SDH entry, laid out exactly as mkntfs builds it. */
			memset(iebuf, 0, sizeof(iebuf));
			ie->data_offset = const_cpu_to_le16(0x18);
			ie->data_length = const_cpu_to_le16(0x14);
			ie->reservedV = const_cpu_to_le32(0);
			ie->length = const_cpu_to_le16(0x30);
			ie->key_length = const_cpu_to_le16(0x08);
			ie->ie_flags = const_cpu_to_le16(0);
			ie->key.sdh.hash = e->hash;
			ie->key.sdh.security_id = e->security_id;
			sdh_data = (SDH_INDEX_DATA *)((u8 *)ie + 0x18);
			sdh_data->hash = e->hash;
			sdh_data->security_id = e->security_id;
			sdh_data->offset = e->offset;
			sdh_data->length = e->length;
			sdh_data->reserved_II = const_cpu_to_le32(0x00490049);

			/*
			 * Use a fresh context per insert: ntfs_ie_add() leaves a
			 * modified index block only marked dirty in icx->ib, and
			 * a subsequent ntfs_index_lookup() on the same context
			 * reads a fresh block from disk, discarding the pending
			 * write. ntfs_index_ctx_put() flushes it, so scope each
			 * add to its own get/put pair as ntfs_index_add_filename
			 * does.
			 */
			sdh = ntfs_index_ctx_get(ni, NTFS_INDEX_SDH, 4);
			if (!sdh)
				goto out;
			add_err = ntfs_ie_add(sdh, ie);
			ntfs_index_ctx_put(sdh);
			if (add_err)
				goto out;
next:
			p = (p + length + NTFSCK_SDS_ALIGN - 1) &
					~(s64)(NTFSCK_SDS_ALIGN - 1);
		}
	}

	/*
	 * Any index allocation the inserts promoted the root into was allocated
	 * through ntfs_cluster_alloc(), which already recorded those clusters in
	 * fsck's own lcn bitmap; re-marking them here would trip a false cluster
	 * duplication and corrupt the freshly built runlist.
	 */
	if (ntfs_inode_sync(ni))
		goto out;

	ret = 0;
out:
	if (na)
		ntfs_attr_close(na);
	free(pbuf);
	return ret;
}

/*
 * ntfsck_check_secure - deep cross-validation of $Secure ($SDS).
 *
 * Walks the $SDS stream one primary/backup block pair at a time. Because $SDS
 * legitimately contains gaps and retired descriptors between live entries, only
 * the entries the $SII index still references are validated; dead space is
 * skipped rather than mistaken for corruption. For every live descriptor it
 * verifies:
 *   - the entry's self-recorded offset matches its physical position;
 *   - the entry length and descriptor stay within the stream;
 *   - the descriptor revision is valid;
 *   - the recomputed hash matches the hash cached in the entry header;
 *   - the backup copy (primary offset + 0x40000) is byte-identical;
 *   - the $SII and $SDH index entries for the descriptor exist and their
 *     cached {hash, security_id, offset, length} header agrees with $SDS.
 *
 * This is a read-only integrity pass: the security database is never rewritten,
 * because reconstructing $SDS / $SII / $SDH from partial data risks corrupting
 * the access control of every file. Detected inconsistencies are reported so
 * that an operator can decide how to recover.
 */
static void ntfsck_check_secure(ntfs_inode *ni)
{
	ntfs_volume *vol = ni->vol;
	ntfs_attr *na;
	ntfs_index_context *sii = NULL, *sdh = NULL;
	u8 *pbuf = NULL, *bbuf = NULL;
	s64 data_size, base;
	int sdh_bad = 0;
	problem_context_t pctx = {0, };

	na = ntfs_attr_open(ni, AT_DATA, STREAM_SDS, 4);
	if (!na)
		return;		/* no $SDS stream - nothing to validate */

	data_size = na->data_size;
	if (data_size < (s64)NTFSCK_SDS_HDR)
		goto out;

	pbuf = ntfs_malloc(NTFSCK_SDS_BLOCK);
	bbuf = ntfs_malloc(NTFSCK_SDS_BLOCK);
	if (!pbuf || !bbuf)
		goto out;

	ntfs_init_problem_ctx(&pctx, ni, na, NULL, NULL, ni->mrec, NULL, NULL);

	/* Index contexts for cross-checking each descriptor against $SII/$SDH. */
	if (ntfs_attr_exist(ni, AT_INDEX_ROOT, NTFS_INDEX_SII, 4))
		sii = ntfs_index_ctx_get(ni, NTFS_INDEX_SII, 4);
	else {
		fsck_err_found();
		ntfs_log_error("$Secure: $SII index is missing\n");
		ntfs_fix_problem(vol, PR_SECURE_SII_MISMATCH, &pctx);
	}
	if (ntfs_attr_exist(ni, AT_INDEX_ROOT, NTFS_INDEX_SDH, 4))
		sdh = ntfs_index_ctx_get(ni, NTFS_INDEX_SDH, 4);
	else {
		fsck_err_found();
		ntfs_log_error("$Secure: $SDH index is missing\n");
		ntfs_fix_problem(vol, PR_SECURE_SDH_MISMATCH, &pctx);
	}

	/* Iterate over primary blocks; each has its backup 0x40000 later. */
	for (base = 0; base < data_size; base += 2 * NTFSCK_SDS_BLOCK) {
		s64 plen = data_size - base;
		s64 blen;
		s64 p;

		if (plen > NTFSCK_SDS_BLOCK)
			plen = NTFSCK_SDS_BLOCK;
		if (ntfs_attr_pread(na, base, plen, pbuf) != plen)
			break;

		blen = data_size - (base + NTFSCK_SDS_BLOCK);
		if (blen > NTFSCK_SDS_BLOCK)
			blen = NTFSCK_SDS_BLOCK;
		if (blen > 0) {
			if (ntfs_attr_pread(na, base + NTFSCK_SDS_BLOCK, blen,
					bbuf) != blen)
				blen = 0;
		} else
			blen = 0;

		p = 0;
		while (p + (s64)NTFSCK_SDS_HDR <= plen) {
			SDS_ENTRY *e = (SDS_ENTRY *)(pbuf + p);
			u32 length = le32_to_cpu(e->length);
			u32 descr_len;
			SECURITY_DESCRIPTOR_RELATIVE *sd;
			SECURITY_DESCRIPTOR_HEADER ref;
			SII_INDEX_KEY siikey;
			SDH_INDEX_KEY sdhkey;

			/* A zero-length entry marks the end of this block. */
			if (!length && !le32_to_cpu(e->security_id))
				break;

			/*
			 * A live entry records its own stream offset and stays within the block.
			 * Anything else at this 16-byte slot is a gap or a retired descriptor, so
			 * resync onto the next slot instead of flagging dead space as corrupt.
			 */
			if (le64_to_cpu(e->offset) != (u64)(base + p) ||
					length < NTFSCK_SDS_HDR ||
					p + length > plen) {
				p += NTFSCK_SDS_ALIGN;
				continue;
			}

			/*
			 * Only validate descriptors $SII still references; an
			 * entry $SII does not point back to is retired and must
			 * not be reported.
			 */
			if (!ntfsck_secure_is_live(sii, e->security_id,
						e->offset))
				goto next_entry;

			descr_len = length - NTFSCK_SDS_HDR;
			sd = (SECURITY_DESCRIPTOR_RELATIVE *)(pbuf + p +
					NTFSCK_SDS_HDR);

			if (descr_len < sizeof(SECURITY_DESCRIPTOR_RELATIVE) ||
					sd->revision != SECURITY_DESCRIPTOR_REVISION) {
				fsck_err_found();
				ntfs_log_error("$Secure $SDS: descriptor at offset "
						"%"PRId64" is invalid\n", base + p);
				ntfs_fix_problem(vol,
						PR_SECURE_SDS_ENTRY_CORRUPTED, &pctx);
			} else if (ntfsck_security_hash(sd, descr_len) != e->hash) {
				fsck_err_found();
				ntfs_log_error("$Secure $SDS: hash mismatch at "
						"offset %"PRId64" (id=%u)\n",
						base + p,
						le32_to_cpu(e->security_id));
				ntfs_fix_problem(vol,
						PR_SECURE_SDS_HASH_MISMATCH, &pctx);
			}

			/*
			 * Compare against the backup copy when available. The
			 * primary just passed its hash check, so it is the good
			 * copy; restore the backup from it.
			 */
			if (blen >= p + (s64)length &&
					memcmp(pbuf + p, bbuf + p, length)) {
				fsck_err_found();
				ntfs_log_error("$Secure $SDS: backup copy differs "
						"at offset %"PRId64"\n", base + p);
				if (ntfs_fix_problem(vol,
						PR_SECURE_SDS_MIRROR_MISMATCH, &pctx)) {
					if (ntfs_attr_pwrite(na,
							base + NTFSCK_SDS_BLOCK + p,
							length, pbuf + p) ==
							(s64)length) {
						memcpy(bbuf + p, pbuf + p, length);
						fsck_err_fixed();
					}
				}
			}

			/* Cross-check the descriptor's $SII and $SDH entries. */
			ref.hash = e->hash;
			ref.security_id = e->security_id;
			ref.offset = e->offset;
			ref.length = e->length;

			siikey.security_id = e->security_id;
			ntfsck_check_secure_index(vol, sii, &siikey,
					sizeof(siikey), &ref,
					PR_SECURE_SII_MISMATCH, "$SII", &pctx);

			/*
			 * $SDH is derived, so a single wrong entry condemns the
			 * whole index: aggregate here and rebuild once below
			 * rather than report each descriptor.
			 */
			sdhkey.hash = e->hash;
			sdhkey.security_id = e->security_id;
			if (sdh && !ntfsck_secure_index_present(sdh, &sdhkey,
						sizeof(sdhkey), &ref))
				sdh_bad++;

next_entry:
			p = (p + length + NTFSCK_SDS_ALIGN - 1) &
					~(s64)(NTFSCK_SDS_ALIGN - 1);
		}
	}

	/*
	 * Rebuild $SDH as a whole when it disagrees with $SDS, but only when
	 * $SII is there to name the live set it must be rebuilt from.
	 */
	if (sdh_bad && sii) {
		fsck_err_found();
		ntfs_log_error("Inode(%"PRIu64"): $Secure $SDH index does not "
				"match $SDS (%d descriptor%s)\n", ni->mft_no,
				sdh_bad, sdh_bad > 1 ? "s" : "");
		if (ntfs_fix_problem(vol, PR_SECURE_SDH_MISMATCH, &pctx)) {
			ntfs_index_ctx_put(sdh);
			sdh = NULL;
			if (!ntfsck_rebuild_secure_sdh(ni, sii))
				fsck_err_fixed();
		}
	}

out:
	if (sii)
		ntfs_index_ctx_put(sii);
	if (sdh)
		ntfs_index_ctx_put(sdh);
	free(pbuf);
	free(bbuf);
	ntfs_attr_close(na);
}

/*
 * ntfsck_check_upcase - restore $UpCase to its canonical size.
 *
 * $UpCase/$DATA must hold the full 65536-character upcase table (131072
 * bytes). ntfs_device_mount() already regenerates a table whose ASCII range
 * is corrupt, but a size that is merely truncated -- with the low characters
 * still intact -- passes that check and leaves the collation table short,
 * which silently breaks case-insensitive name comparisons. When the on-disk
 * size differs from the default, rewrite both the size and the contents from
 * the standard table (this mirrors ntfs_upcase_repair()).
 *
 * $UpCase is not one of the inodes the volume keeps open, and the pass-2
 * system-file loop skips inodes it does not already hold open, so this runs as
 * a one-shot over its own freshly opened inode rather than per-inode.
 * ntfs_device_mount() closes $UpCase after loading it, so opening it here
 * cannot create a duplicate in-core inode.
 */
static void ntfsck_check_upcase(ntfs_volume *vol)
{
	ntfs_inode *ni;
	ntfs_attr *na;
	ntfschar *uc = NULL;
	u32 uc_len;
	s64 uc_bytes;
	problem_context_t pctx = {0, };

	ni = ntfs_inode_open(vol, FILE_UpCase);
	if (!ni)
		return;

	na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
	if (!na) {
		ntfs_inode_close(ni);
		return;
	}

	uc_len = ntfs_upcase_build_default(&uc);
	if (!uc_len || !uc) {
		free(uc);
		ntfs_attr_close(na);
		ntfs_inode_close(ni);
		return;
	}
	uc_bytes = (s64)uc_len << 1;

	if (na->data_size != uc_bytes) {
		ntfs_init_problem_ctx(&pctx, ni, na, NULL, NULL, ni->mrec,
				NULL, NULL);
		fsck_err_found();
		if (ntfs_fix_problem(vol, PR_UPCASE_CORRUPTED, &pctx)) {
			if (!ntfs_attr_truncate(na, uc_bytes) &&
					ntfs_attr_pwrite(na, 0, uc_bytes, uc) ==
						uc_bytes) {
				/* Adopt the fresh table for the rest of fsck. */
				free(vol->upcase);
				vol->upcase = uc;
				vol->upcase_len = uc_len;
				uc = NULL;
				ntfs_inode_mark_dirty(ni);
				fsck_err_fixed();
			}
		}
	}

	free(uc);
	ntfs_attr_close(na);
	ntfs_inode_close(ni);
}

/*
 * The number of mft records $MFTMirr mirrors, as ntfs_boot_sector_parse()
 * derives it from the volume geometry. vol->mftmirr_size cannot be used: when
 * $MFTMirr is short, ntfs_device_mount() lowers it to whatever could be read,
 * so it describes the damage rather than the expected value.
 */
static int ntfsck_expected_mftmirr_size(const ntfs_volume *vol)
{
	if (vol->cluster_size <= 4 * vol->mft_record_size)
		return 4;
	return vol->cluster_size >> vol->mft_record_size_bits;
}

/*
 * ntfsck_check_mftmirr - restore $MFTMirr to its canonical size.
 *
 * $MFTMirr/$DATA holds a copy of the first mftmirr_size mft records, a size
 * fixed by the volume geometry. A truncated mirror still mounts -- the mount
 * path just compares fewer records -- but ntfs_mft_records_write() then stops
 * mirroring the records that fell off the end (it skips anything past
 * initialized_size), so the mirror silently drifts from $MFT and is useless
 * for the recovery it exists to provide.
 *
 * Resize the attribute and rewrite its contents from $MFT. Growing it back
 * without refilling it would leave zeroed records behind, which the next mount
 * would report as a $MFT/$MFTMirr mismatch.
 */
static void ntfsck_check_mftmirr(ntfs_volume *vol)
{
	ntfs_attr *na = vol->mftmirr_na;
	int mirr_size = ntfsck_expected_mftmirr_size(vol);
	s64 expected = (s64)mirr_size << vol->mft_record_size_bits;
	problem_context_t pctx = {0, };
	u8 *buf;

	if (!na || na->data_size == expected)
		return;

	ntfs_init_problem_ctx(&pctx, vol->mftmirr_ni, na, NULL, NULL,
			vol->mftmirr_ni->mrec, NULL, NULL);
	pctx.dsize = expected;
	fsck_err_found();
	if (!ntfs_fix_problem(vol, PR_MFTMIRR_SIZE_MISMATCH, &pctx))
		return;

	if (ntfs_attr_truncate(na, expected)) {
		ntfs_log_error("Failed to resize $MFTMirr to %"PRId64"\n",
				expected);
		return;
	}

	buf = ntfs_malloc(expected);
	if (!buf)
		return;

	/*
	 * Copy the records raw, update sequence array included. The mirror is
	 * validated by a plain memcmp() against $MFT, and ntfs_attr_mst_pwrite()
	 * would run its own pre-write fixup and leave every copied record with an
	 * update sequence number one ahead of the original.
	 */
	if (ntfs_attr_pread(vol->mft_na, 0, expected, buf) != expected) {
		ntfs_log_error("Failed to read the first %d records of $MFT\n",
				mirr_size);
		free(buf);
		return;
	}

	if (ntfs_attr_pwrite(na, 0, expected, buf) != expected) {
		ntfs_log_error("Failed to write %d records to $MFTMirr\n",
				mirr_size);
		free(buf);
		return;
	}
	free(buf);

	vol->mftmirr_size = mirr_size;

	/*
	 * Record 1 was copied from $MFT before the new size reached the disk,
	 * so the mirror now holds a stale copy of the very inode being resized.
	 * Sync it: the write goes through ntfs_mft_records_write(), which - now
	 * that mftmirr_size and the mirror's initialized_size cover record 1 -
	 * refreshes both $MFT and the mirror.
	 *
	 * It also cannot wait until unmount. __ntfs_volume_release() releases
	 * vol->mft_na before syncing vol->mftmirr_ni, and ntfs_mft_records_write()
	 * fails with EINVAL once mft_na is gone, so a dirty inode 1 is dropped.
	 */
	if (ntfs_inode_sync(vol->mftmirr_ni)) {
		ntfs_log_perror("Failed to sync $MFTMirr");
		return;
	}

	fsck_err_fixed();
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
		if (ntfsck_check_inode_non_resident(ni, 1))
			return -EIO;

		if ((ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) &&
				ntfsck_check_directory(ni))
			return -EIO;

		/* Deep cross-validation of the security database. */
		if (ni->mft_no == FILE_Secure)
			ntfsck_check_secure(ni);

		/* The mirror's size follows from the volume geometry. */
		if (ni->mft_no == FILE_MFTMirr)
			ntfsck_check_mftmirr(vol);
		break;
	case FILE_Bitmap:
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

	return 0;
}

static int ntfsck_check_system_files(ntfs_volume *vol)
{
	ntfs_inode *sys_ni, *root_ni;
	ntfs_attr_search_ctx *root_ctx, *sys_ctx;
	ntfs_index_context *ictx;
	INDEX_ENTRY *ie;
	FILE_NAME_ATTR *fn;
	FILE_NAME_ATTR *ie_fn;
	s64 mft_num;
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

	root_ctx = ntfs_attr_get_search_ctx(root_ni, NULL);
	if (!root_ctx)
		goto close_inode;

	ictx = ntfs_index_ctx_get(root_ni, NTFS_INDEX_I30, 4);
	if (!ictx)
		goto put_attr_ctx;

	/* check lost found here */
	ntfsck_check_lost_found(vol, root_ni, ictx);
	ntfs_index_ctx_reinit(ictx);

	/* Restore a truncated $UpCase collation table to its full size. */
	ntfsck_check_upcase(vol);

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

		if (sys_ni->attr_list && ntfsck_check_attr_list(sys_ni)) {
			ntfsck_close_inode(sys_ni);
			goto check_trivial;
		}

		if (ntfs_inode_attach_all_extents(sys_ni)) {
			ntfsck_close_inode(sys_ni);
			goto check_trivial;
		}
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
			problem_context_t pctx = {0, };
			int lookup_err = errno;

			if (lookup_err != ENOENT) {
				ntfs_log_error("Failed to lookup system file entry"
						"(%"PRId64") in root\n", mft_num);
				ntfs_attr_put_search_ctx(sys_ctx);
				ntfsck_close_inode(sys_ni);
				goto check_trivial;
			}

			ntfs_init_problem_ctx(&pctx, sys_ni, NULL, NULL,
					ictx, NULL, NULL, fn);
			fsck_err_found();
			if (!ntfs_fix_problem(vol,
					PR_ROOT_MISSING_SYSTEM_FILE_ENTRY, &pctx) ||
					ntfsck_add_filename_to_parent(vol, root_ni,
						sys_ni, fn)) {
				ntfs_attr_put_search_ctx(sys_ctx);
				ntfsck_close_inode(sys_ni);
				goto check_trivial;
			}

			ntfs_index_ctx_reinit(ictx);
			ret = ntfs_index_lookup(fn,
					le32_to_cpu(sys_ctx->attr->value_length), ictx);
			if (ret) {
				ntfs_log_error("Failed to restore system file entry"
						"(%"PRId64") in root\n", mft_num);
				ntfs_attr_put_search_ctx(sys_ctx);
				ntfsck_close_inode(sys_ni);
				goto check_trivial;
			}
			fsck_err_fixed();
		}

		ie = ictx->entry;
		ie_fn = (FILE_NAME_ATTR *)&ie->key.file_name;
		ntfs_attr_put_search_ctx(sys_ctx);

		if (ntfsck_check_inode_fields(root_ni, sys_ni, ie, ictx) ||
				ntfsck_check_file_type(sys_ni, ictx, ie_fn) < 0 ||
				ntfsck_check_file_name_attr(sys_ni, ie_fn, ictx) < 0) {
			ntfsck_close_inode(sys_ni);
			goto check_trivial;
		}

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

/*
 * Count clusters that the on-disk $Bitmap marks in-use but the fsck-computed
 * bitmap marks free. These are the clusters a FINAL apply would release.
 */
static s64 ntfsck_bitmap_count_to_free(ntfs_volume *vol, ntfs_attr *na,
		get_bmp_func func)
{
	s64 count, pos, total, remain, rcnt;
	s64 to_free = 0;
	u8 *disk_bm, *fsck_bm;
	s64 j;

	disk_bm = ntfs_calloc(NTFS_BUF_SIZE);
	if (!disk_bm)
		return -1;

	pos = 0;
	count = NTFS_BUF_SIZE;
	total = na->data_size;
	remain = total;
	if (total < count)
		count = total;

	while (1) {
		memset(disk_bm, 0, NTFS_BUF_SIZE);
		rcnt = ntfs_attr_pread(na, pos, count, disk_bm);
		if (rcnt != count) {
			free(disk_bm);
			return -1;
		}

		fsck_bm = func(vol, pos);
		/* bits set on disk but clear in fsck => would be freed */
		for (j = 0; j < count; j++) {
			u8 b = disk_bm[j] & ~fsck_bm[j];

			if (b)
				to_free += __builtin_popcount((unsigned)b);
		}

		pos += count;
		remain -= count;
		if (remain && remain < NTFS_BUF_SIZE)
			count = remain;
		if (!remain)
			break;
	}

	free(disk_bm);
	return to_free;
}

/*
 * Consensus barrier for a cluster $Bitmap mass-free. When the FINAL apply
 * would release a large fraction of the volume, the scan that produced the
 * fsck ground-truth must itself be trustworthy; otherwise we may be about to
 * free clusters that belong to files we simply failed to read.
 *
 * Three independent indicators are evaluated; if two or more fail, the
 * mass-free is refused (the caller keeps the on-disk bits set - the safe
 * direction, which leaks space but never destroys data).
 *
 * Returns TRUE if the mass-free must be blocked.
 */
static BOOL ntfsck_bitmap_consensus_block(ntfs_volume *vol, s64 to_free)
{
	s64 nr_clusters = vol->nr_clusters;
	int fails = 0;

	/* Only engage for a genuine mass-free (> 5% of the volume). */
	if (nr_clusters <= 0 || to_free * 20 < nr_clusters)
		return FALSE;

	/* Indicator 1: EIO rate during the MFT scan must be < 0.1%. */
	if (total_inuse_mft > 0 && fsck_scan_eio * 1000 > total_inuse_mft)
		fails++;

	/* Indicator 2: MFT yield (opened / in-use) must be > 90%. */
	if (total_inuse_mft > 0 &&
			total_valid_mft * 100 < total_inuse_mft * 90)
		fails++;

	/* Indicator 3: lost-cluster ratio must be < 10% of the volume. */
	if (to_free * 10 >= nr_clusters)
		fails++;

	if (fails >= 2) {
		ntfs_log_error("Cluster bitmap consensus failed: to_free=%"PRId64
				" of %"PRId64" clusters, in-use MFT=%"PRId64
				", valid MFT=%"PRId64", scan EIO=%"PRId64
				" (indicators failed=%d)\n",
				to_free, nr_clusters, total_inuse_mft,
				total_valid_mft, fsck_scan_eio, fails);
		return TRUE;
	}
	return FALSE;
}
static int ntfsck_apply_bitmap(ntfs_volume *vol, ntfs_attr *na, get_bmp_func func, int wtype)
{
	s64 count, pos, total, remain;
	s64 rcnt, wcnt;
	u8 *disk_bm;
	u8 *fsck_bm;
	u8 *dbmb;
	u8 *fbmb;
	s64 word_count;
	s64 tail_bytes;
	unsigned long i;
	unsigned long *dbml;
	unsigned long *fbml;
	int ret = STATUS_OK;
	BOOL block_mass_free = FALSE;
	problem_context_t pctx = {0, };

	if (na != vol->lcnbmp_na && na != vol->mftbmp_na)
		return STATUS_ERROR;

	/*
	 * Before a FINAL cluster-bitmap apply, decide whether the scan is
	 * trustworthy enough to free a large number of clusters. Only the cluster
	 * bitmap is subject to this barrier - the MFT bitmap is validated
	 * record-by-record elsewhere.
	 */
	if (na == vol->lcnbmp_na && wtype == FSCK_BMP_FINAL) {
		s64 to_free = ntfsck_bitmap_count_to_free(vol, na, func);

		if (to_free > 0)
			block_mass_free = ntfsck_bitmap_consensus_block(vol,
					to_free);
	}

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

	if (block_mass_free) {
		fsck_err_found();
		ntfs_fix_problem(vol, PR_CLUSTER_BITMAP_CONSENSUS_FAIL, &pctx);
	}

	/* apply btimap(fsck OR lcnbmp) to disk */
	while (1) {
		/* read bitmap from disk */
		memset(disk_bm, 0, NTFS_BUF_SIZE);
		rcnt = ntfs_attr_pread(na, pos, count, disk_bm);
		if (rcnt == STATUS_ERROR) {
			ntfs_log_error("Couldn't get $Bitmap $DATA");
			ret = STATUS_ERROR;
			break;
		}

		if (rcnt != count) {
			ntfs_log_error("Couldn't get $Bitmap, read count error\n");
			ret = STATUS_ERROR;
			break;
		}

		fsck_bm = func(vol, pos);

		if (!memcmp(fsck_bm, disk_bm, count))
			goto next;

		/* ondisk lcnbmp OR fsck lcnbmp */
		word_count = count / sizeof(unsigned long);
		tail_bytes = count % sizeof(unsigned long);
		for (i = 0; i < word_count; i++) {
			dbml = (unsigned long *)disk_bm + i;
			fbml = (unsigned long *)fsck_bm + i;
			if (*dbml != *fbml) {
#ifdef DEBUG
				ntfs_log_info("%s bitmap(%d):\n",
						na->type == 0xb0 ? "MFT" : "LCN", wtype);
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

		dbmb = disk_bm + (word_count * sizeof(unsigned long));
		fbmb = fsck_bm + (word_count * sizeof(unsigned long));
		for (i = 0; i < tail_bytes; i++)
			dbmb[i] |= fbmb[i];

		if (wtype == FSCK_BMP_FINAL)
			fsck_err_found();

		if (ntfs_fix_problem(vol, PR_CLUSTER_BITMAP_MISMATCH, &pctx)) {
			if (wtype == FSCK_BMP_INITIAL)
				wcnt = ntfs_attr_pwrite(na, pos, count, disk_bm);
			else if (block_mass_free) {
				/*
				 * Consensus barrier tripped: write the OR of disk and fsck bitmaps so
				 * that used clusters are still marked, but no cluster is freed.
				 */
				wcnt = ntfs_attr_pwrite(na, pos, count, disk_bm);
			} else if (wtype == FSCK_BMP_FINAL) {
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
	return ret;
}

static int ntfsck_check_orphaned_mft(ntfs_volume *vol)
{
	struct orphan_mft *entry = NULL;
	ntfs_inode *root_ni;
	u64 cnt = 1;
	problem_context_t pctx = {0, };

	fsck_start_step("Check orphaned mft...");

	if (ntfsck_apply_bitmap(vol, vol->lcnbmp_na,
			ntfs_fsck_find_lcnbmp_block, FSCK_BMP_INITIAL))
		return STATUS_ERROR;
	if (ntfsck_apply_bitmap(vol, vol->mftbmp_na,
			ntfs_fsck_find_mftbmp_block, FSCK_BMP_INITIAL))
		return STATUS_ERROR;

	progress_init(&prog, 0, orphan_cnt + 1, 1000, pb_flags);

	/* check lost found directory */
	if (!vol->lost_found && orphan_cnt > 0) {
		root_ni = ntfsck_open_inode(vol, FILE_root);
		if (!root_ni) {
			ntfs_log_error("Failed to open root inode\n");
			return STATUS_ERROR;
		}
		ntfsck_create_lost_found(vol, root_ni);
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
				ntfs_log_error("failed to add entry(%"PRIu64
						") orphaned file\n",
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

	if (ntfsck_apply_bitmap(vol, vol->lcnbmp_na,
			ntfs_fsck_find_lcnbmp_block, FSCK_BMP_FINAL))
		return STATUS_ERROR;
	if (ntfsck_apply_bitmap(vol, vol->mftbmp_na,
			ntfs_fsck_find_mftbmp_block, FSCK_BMP_FINAL))
		return STATUS_ERROR;

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
		ntfs_log_error("Failed to read backup boot sector on %s.\n",
				(sector == vol->nr_sectors) ?
				"last sector" : "middle sector");
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
				"(pos:%"PRId64").\n", bb_sector >> spc_bits);
		free(bb_buf);
		return STATUS_OK;
	}

	free(bb_buf);
	return STATUS_ERROR;
}

/*
 * The references that were minted while the record still had its real
 * sequence number are the only place it survives. For a base record ask the
 * directory index entry each $FILE_NAME points back to; for an extent record
 * ask the $ATTRIBUTE_LIST entries naming it.
 */
static u16 ntfsck_recover_seq_no(ntfs_inode *base_ni, ntfs_inode *ni)
{
	ntfs_attr_search_ctx *actx;
	FILE_NAME_ATTR *fn;
	u16 seq_no = 0;

	if (base_ni != ni) {
		u8 *al = base_ni->attr_list;
		u8 *al_end = al + base_ni->attr_list_size;
		ATTR_LIST_ENTRY *ale;
		u16 ale_len;

		while (al + sizeof(ATTR_LIST_ENTRY) <= al_end) {
			ale = (ATTR_LIST_ENTRY *)al;
			ale_len = le16_to_cpu(ale->length);
			if (ale_len < sizeof(ATTR_LIST_ENTRY) ||
					al + ale_len > al_end)
				break;
			if (MREF_LE(ale->mft_reference) == ni->mft_no &&
					MSEQNO_LE(ale->mft_reference))
				return MSEQNO_LE(ale->mft_reference);
			al += ale_len;
		}
		return 1;
	}

	actx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!actx)
		return 1;
	while (!seq_no && !ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0,
				CASE_SENSITIVE, 0, NULL, 0, actx)) {
		ntfs_inode *parent_ni;
		ntfs_index_context *ictx;

		fn = (FILE_NAME_ATTR *)((u8 *)actx->attr +
				le16_to_cpu(actx->attr->value_offset));
		if (MREF_LE(fn->parent_directory) == ni->mft_no)
			continue;
		parent_ni = ntfsck_open_inode(ni->vol,
				MREF_LE(fn->parent_directory));
		if (!parent_ni)
			continue;
		ictx = ntfs_index_ctx_get(parent_ni, NTFS_INDEX_I30, 4);
		if (ictx) {
			if (!ntfs_index_lookup(fn, sizeof(FILE_NAME_ATTR),
						ictx) &&
					MREF_LE(ictx->entry->indexed_file) ==
					ni->mft_no)
				seq_no = MSEQNO_LE(ictx->entry->indexed_file);
			ntfs_index_ctx_put(ictx);
		}
		ntfsck_close_inode(parent_ni);
	}
	ntfs_attr_put_search_ctx(actx);

	return seq_no ? seq_no : 1;
}

/*
 * A zero sequence number can never be caught as stale: reference checks skip
 * validation when the sequence in the reference is zero, and the record free
 * path refuses to increment a zero sequence, so references minted from such a
 * record keep resolving to whatever occupies the slot later. Restore the
 * sequence number a surviving reference still remembers (one when none does),
 * together with the references that must match the record exactly: the
 * $ATTRIBUTE_LIST entries naming this record and, for a base record, the back
 * reference held by each extent record.
 */
static void ntfsck_fix_zero_seq_no(ntfs_inode *base_ni, ntfs_inode *ni)
{
	problem_context_t pctx = {0, };
	u16 seq_no;
	s32 i;

	ntfs_init_problem_ctx(&pctx, ni, NULL, NULL, NULL, ni->mrec,
			NULL, NULL);
	fsck_err_found();
	if (!ntfs_fix_problem(ni->vol, PR_MFT_SEQNO_ZERO, &pctx))
		return;

	seq_no = ntfsck_recover_seq_no(base_ni, ni);
	ni->mrec->sequence_number = cpu_to_le16(seq_no);

	if (base_ni->attr_list) {
		u8 *al = base_ni->attr_list;
		u8 *al_end = al + base_ni->attr_list_size;
		ATTR_LIST_ENTRY *ale;
		u16 ale_len;

		while (al + sizeof(ATTR_LIST_ENTRY) <= al_end) {
			ale = (ATTR_LIST_ENTRY *)al;
			ale_len = le16_to_cpu(ale->length);
			if (ale_len < sizeof(ATTR_LIST_ENTRY) ||
					al + ale_len > al_end)
				break;
			if (MREF_LE(ale->mft_reference) == ni->mft_no &&
					MSEQNO_LE(ale->mft_reference) !=
					seq_no) {
				ale->mft_reference =
					MK_LE_MREF(ni->mft_no, seq_no);
				NInoAttrListSetDirty(base_ni);
			}
			al += ale_len;
		}
	}

	if (base_ni == ni) {
		for (i = 0; i < ni->nr_extents; i++) {
			ntfs_inode *eni = ni->extent_nis[i];

			if (eni->mrec->base_mft_record ==
					MK_LE_MREF(ni->mft_no, seq_no))
				continue;
			eni->mrec->base_mft_record =
				MK_LE_MREF(ni->mft_no, seq_no);
			ntfs_inode_mark_dirty(eni);
		}
	}

	ntfs_inode_mark_dirty(ni);
	fsck_err_fixed();
}

static void ntfsck_check_seq_no(ntfs_inode *ni)
{
	s32 i;

	if (!ni->mrec->sequence_number)
		ntfsck_fix_zero_seq_no(ni, ni);
	for (i = 0; i < ni->nr_extents; i++) {
		if (!ni->extent_nis[i]->mrec->sequence_number)
			ntfsck_fix_zero_seq_no(ni, ni->extent_nis[i]);
	}
}

/*
 * ntfs_extent_inode_open() rejects an extent record whose sequence number no
 * longer matches the $ATTRIBUTE_LIST reference, so an extent whose sequence
 * number was wiped to zero makes the whole base inode unattachable and parse
 * #2 would tear it down. The reference still remembers the real sequence
 * number: restore it raw before retrying the attach (the field sits in the
 * first sector of the record, outside the multi sector transfer protection).
 */
static int ntfsck_salvage_extent_seq_no(ntfs_inode *ni)
{
	ntfs_volume *vol = ni->vol;
	u8 *al = ni->attr_list;
	u8 *al_end = al + ni->attr_list_size;
	ATTR_LIST_ENTRY *ale;
	u16 ale_len;
	int salvaged = 0;

	if (!NVolFsck(vol) || !vol->mft_na || !al)
		return STATUS_ERROR;

	while (al + sizeof(ATTR_LIST_ENTRY) <= al_end) {
		u64 mft_no;
		u16 seq_no;
		s64 pos;
		u8 *pal;
		MFT_RECORD mrec;
		problem_context_t pctx = {0, };

		ale = (ATTR_LIST_ENTRY *)al;
		ale_len = le16_to_cpu(ale->length);
		if (ale_len < sizeof(ATTR_LIST_ENTRY) || al + ale_len > al_end)
			break;
		al += ale_len;

		mft_no = MREF_LE(ale->mft_reference);
		seq_no = MSEQNO_LE(ale->mft_reference);
		if (mft_no == ni->mft_no || !seq_no)
			continue;
		/* several entries name one extent: handle each record once */
		for (pal = ni->attr_list; pal < (u8 *)ale;
				pal += le16_to_cpu(
					((ATTR_LIST_ENTRY *)pal)->length))
			if (MREF_LE(((ATTR_LIST_ENTRY *)pal)->mft_reference) ==
					mft_no)
				break;
		if (pal < (u8 *)ale)
			continue;
		if ((s64)mft_no + 1 > vol->mft_na->initialized_size >>
				vol->mft_record_size_bits)
			continue;

		pos = (s64)mft_no << vol->mft_record_size_bits;
		if (ntfs_attr_pread(vol->mft_na, pos, sizeof(mrec), &mrec) !=
				sizeof(mrec))
			continue;
		if (!ntfs_is_file_record(mrec.magic) ||
				mrec.sequence_number ||
				!(mrec.flags & MFT_RECORD_IN_USE) ||
				MREF_LE(mrec.base_mft_record) != ni->mft_no)
			continue;

		pctx.inum = mft_no;
		fsck_err_found();
		if (!ntfs_fix_problem(vol, PR_MFT_SEQNO_ZERO, &pctx))
			continue;

		mrec.sequence_number = cpu_to_le16(seq_no);
		if (ntfs_attr_pwrite(vol->mft_na,
					pos + offsetof(MFT_RECORD, sequence_number),
					sizeof(mrec.sequence_number),
					&mrec.sequence_number) !=
				sizeof(mrec.sequence_number)) {
			ntfs_log_error("Failed to restore the sequence number "
					"of mft record(%"PRIu64")\n", mft_no);
			continue;
		}
		if ((s64)mft_no < vol->mftmirr_size)
			ntfs_attr_pwrite(vol->mftmirr_na,
					pos + offsetof(MFT_RECORD, sequence_number),
					sizeof(mrec.sequence_number),
					&mrec.sequence_number);
		fsck_err_fixed();
		salvaged++;
	}

	return salvaged ? STATUS_OK : STATUS_ERROR;
}

static int ntfsck_scan_mft_record(ntfs_volume *vol, s64 mft_num)
{
	ntfs_inode *ni = NULL;
	int is_used;
	BOOL raw_retry_done = FALSE;

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

	/* The bitmap says this record is allocated (in-use). */
	total_inuse_mft++;

	ni = ntfsck_open_inode(vol, mft_num);
	if (!ni) {
		if (errno == EIO)
			fsck_scan_eio++;
		raw_retry_done = TRUE;
		ni = ntfsck_open_inode_after_raw_mft_check(vol, mft_num,
				is_used > 0);
	}
	if (!ni)
		return STATUS_ERROR;

	total_valid_mft++;

	retry_validate:
	if (ni->attr_list) {
		if (ntfsck_check_attr_list(ni))
			goto err_check_inode;

		if (ntfs_inode_attach_all_extents(ni) &&
				(ntfsck_salvage_extent_seq_no(ni) ||
				 ntfs_inode_attach_all_extents(ni)))
			goto err_check_inode;
	}

	ntfsck_check_seq_no(ni);

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
	ni = NULL;

	if (!raw_retry_done) {
		raw_retry_done = TRUE;
		ni = ntfsck_open_inode_after_raw_mft_check(vol, mft_num,
				is_used > 0);
		if (ni)
			goto retry_validate;
	}

	ntfsck_check_mft_record_unused(vol, mft_num);
	ntfs_fsck_mftbmp_clear(vol, mft_num);
	check_mftrec_in_use(vol, mft_num, 1);
	return STATUS_ERROR;
}

/*
 * The last mft record between $MFT/$DATA's initialized_size and @max_size that
 * was ever written: its multi sector transfer fixup verifies, it carries the
 * FILE magic, and it names itself. Returns -1 when there is no such record.
 *
 * $MFT/$BITMAP would be the obvious oracle and it is the wrong one. The bits
 * between the record count and the byte-rounded end of the bitmap are padding,
 * and on volumes Windows wrote they are not always zero; reading them as
 * evidence grows $MFT over records nobody ever created.
 */
static s64 ntfsck_last_written_mft_record(ntfs_volume *vol, s64 reach,
		s64 max_size)
{
	ntfs_attr *na = vol->mft_na;
	s64 saved_init = na->initialized_size;
	s64 saved_data = na->data_size;
	BOOL saved_warn = NVolNoFixupWarn(vol);
	s64 rec, end, last = -1;
	MFT_RECORD *m;

	m = ntfs_malloc(vol->mft_record_size);
	if (!m)
		return -1;

	rec = reach >> vol->mft_record_size_bits;
	end = max_size >> vol->mft_record_size_bits;

	/* Most of what we are about to read is not an mft record at all. */
	NVolSetNoFixupWarn(vol);

	/*
	 * ntfs_attr_pread() stops at data_size and serves zeroes above
	 * initialized_size rather than touching the disk, and above them is
	 * precisely where we need to look. The bump is in memory and lasts only for
	 * the scan.
	 */
	na->data_size = max_size;
	na->initialized_size = max_size;

	for (; rec < end; rec++) {
		if (ntfs_attr_mst_pread(na, rec << vol->mft_record_size_bits, 1,
					vol->mft_record_size, m) != 1)
			continue;
		if (!ntfs_is_file_record(m->magic))
			continue;
		/*
		 * Only allocated records can be hidden to any effect. A freed record keeps
		 * its FILE magic, and often even its stale MFT_RECORD_IN_USE flag (delete
		 * clears the $MFT/$BITMAP bit, not necessarily the record header), so the
		 * record's own flag is not trustworthy here.
		 */
		if (check_mftrec_in_use(vol, rec, 1) <= 0)
			continue;
		if (le32_to_cpu(m->bytes_allocated) != vol->mft_record_size)
			continue;
		if (le32_to_cpu(m->bytes_in_use) > vol->mft_record_size)
			continue;
		/*
		 * Only an ntfs 3.1 record carries its own number, and without it a stale
		 * record cannot be told from a live one. Leave the older layouts alone
		 * rather than guess.
		 */
		if (le16_to_cpu(m->usa_ofs) < 0x30 ||
				le32_to_cpu(m->mft_record_number) != rec)
			continue;
		last = rec;
	}

	na->initialized_size = saved_init;
	na->data_size = saved_data;
	if (!saved_warn)
		NVolClearNoFixupWarn(vol);
	free(m);
	return last;
}

/*
 * Rewrite $MFT/$DATA's own size fields. $MFT is being walked by everything
 * else, so update the attribute record, the open attribute and the inode
 * together, and get the record on disk before pass 1 reads it back.
 */
static int ntfsck_set_mft_size(ntfs_volume *vol, s64 data_size, s64 init_size)
{
	ntfs_attr_search_ctx *ctx;

	ctx = ntfs_attr_get_search_ctx(vol->mft_ni, NULL);
	if (!ctx)
		return -1;

	if (ntfs_attr_lookup(AT_DATA, AT_UNNAMED, 0, CASE_SENSITIVE, 0, NULL, 0,
				ctx)) {
		ntfs_log_perror("Failed to look up $MFT/$DATA");
		ntfs_attr_put_search_ctx(ctx);
		return -1;
	}

	ctx->attr->data_size = cpu_to_sle64(data_size);
	ctx->attr->initialized_size = cpu_to_sle64(init_size);
	ntfs_inode_mark_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);

	vol->mft_na->data_size = data_size;
	vol->mft_na->initialized_size = init_size;
	vol->mft_ni->data_size = data_size;

	if (ntfs_inode_sync(vol->mft_ni)) {
		ntfs_log_perror("Failed to sync $MFT");
		return -1;
	}

	return 0;
}

/*
 * ntfsck_check_mft_size - make $MFT/$DATA describe the records it really holds.
 *
 * Nothing can reach a record past initialized_size, nor past data_size: reads
 * stop at the one and are served zeroes above the other, so the inode cannot be
 * opened, and pass 3 then reads every index entry naming it as a dangling
 * reference and deletes it. A $DATA short by a few records costs the entire
 * directory tree below them.
 *
 * Those records are intact, though. They sit inside the runlist that mount
 * already validated against allocated_size, so find the last one that was ever
 * written and grow $DATA back over it. Growing further would be guesswork: the
 * space above holds nothing anyone wrote, and a $DATA that already reaches
 * beyond it is just an $MFT with freed records at the end.
 *
 * In the other direction the runlist is the authority. Mount rejects an
 * allocated_size that disagrees with it, so bytes past the allocation are not
 * addressable at all and a size claiming them can only be wrong.
 */
static void ntfsck_check_mft_size(ntfs_volume *vol)
{
	ntfs_attr *na = vol->mft_na;
	problem_context_t pctx = {0, };
	s64 last, expected, max_size, reach;

	max_size = (na->allocated_size >> vol->mft_record_size_bits) <<
		vol->mft_record_size_bits;

	if (na->data_size > max_size || na->initialized_size > max_size) {
		s64 init_size = na->initialized_size > max_size ?
			max_size : na->initialized_size;

		ntfs_init_problem_ctx(&pctx, vol->mft_ni, na, NULL, NULL,
				vol->mft_ni->mrec, NULL, NULL);
		fsck_err_found();
		if (ntfs_fix_problem(vol, PR_MFT_SIZE_EXCEEDS_ALLOCATION, &pctx) &&
				!ntfsck_set_mft_size(vol, max_size, init_size))
			fsck_err_fixed();
	}

	/* A record is reachable only below both sizes. */
	reach = na->data_size < na->initialized_size ?
		na->data_size : na->initialized_size;
	if (reach >= max_size)
		return;

	last = ntfsck_last_written_mft_record(vol, reach, max_size);
	if (last < 0)
		return;

	expected = (last + 1) << vol->mft_record_size_bits;
	if (reach >= expected)
		return;

	ntfs_init_problem_ctx(&pctx, vol->mft_ni, na, NULL, NULL,
			vol->mft_ni->mrec, NULL, NULL);
	pctx.dsize = expected;
	fsck_err_found();
	if (ntfs_fix_problem(vol, PR_MFT_SIZE_HIDES_RECORDS, &pctx) &&
			!ntfsck_set_mft_size(vol,
				na->data_size > expected ? na->data_size : expected,
				expected))
		fsck_err_fixed();
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

	ntfs_print_message(vol, PR_PRE_SCAN_MFT, &pctx);

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

/*
 * Upper bound on repair rounds. Each round strictly reduces the number of
 * errors left (see the loop in main()), so a handful of rounds is plenty; the
 * cap only guards against a pathological volume that never settles.
 */
#define NTFSCK_MAX_REPAIR_ROUNDS	8

/*
 * ntfsck_run_repair_passes - run the whole check/repair sequence once.
 *
 * Returns 0 when every pass ran to completion, -1 on a critical error that
 * makes continuing pointless. Accumulates into the global fsck_errors /
 * fsck_fixes counters; the caller resets those (and re-mounts) between rounds.
 *
 * @orphan_changed, when non-NULL, is set TRUE if orphan recovery (pass 5)
 * applied any fix this round. That pass relinks inodes and can leave new,
 * uncounted on-disk corruption behind -- a relinked inode's INDEX_ROOT header
 * -- which only the next round's checks would find, so the caller must
 * re-verify rather than stop on errors==fixes when it happened.
 */
static int ntfsck_run_repair_passes(ntfs_volume *vol, BOOL *orphan_changed)
{
	int ret = 0;
	int orphan_fixes_before;

	if (orphan_changed)
		*orphan_changed = FALSE;

	/*
	 * Journal handling comes first, before any MFT record is trusted or
	 * modified. ntfsck cannot replay $LogFile, so it resets a genuinely dirty
	 * journal here rather than leaving a stale one for the later passes to work
	 * around. $LogFile (inode 2) always lives in the head of $MFT, so it stays
	 * reachable regardless of a truncated $MFT/$DATA that
	 * ntfsck_check_mft_size() repairs next.
	 */
	if (ntfsck_replay_log(vol))
		return -1;

	/* $MFT must be whole before pass 1 decides which records exist. */
	ntfsck_check_mft_size(vol);

	/* pass 1 */
	ntfsck_scan_mft_records(vol);

	/* pass 2 */
	if (ntfsck_check_system_files(vol))
		return -1;

	mrec_temp_buf = ntfs_malloc(vol->sector_size);
	if (!mrec_temp_buf) {
		ntfs_log_perror("Couldn't allocate mrec_temp_buf buffer");
		return -1;
	}

	/* pass 3 */
	if (ntfsck_scan_index_entries(vol)) {
		ntfs_log_error("Stop processing fsck due to critical problems\n");
		ret = -1;
		goto out;
	}

	/* pass 4 */
	/* apply mft bitmap & cluster bitmap to disk */
	ntfsck_check_mft_records(vol);

	/* pass 5 */
	orphan_fixes_before = fsck_fixes;
	ntfsck_check_orphaned_mft(vol);
	if (orphan_changed)
		*orphan_changed = (fsck_fixes != orphan_fixes_before);

out:
	free(mrec_temp_buf);
	mrec_temp_buf = NULL;
	return ret;
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
	/*
	 * fsck_errors/fsck_fixes are reset between repair rounds, so they only
	 * ever describe the final round. Accumulate every round into these to
	 * report what the whole run did.
	 */
	int total_errors = 0, total_fixes = 0;
	unsigned long mnt_flags;
	BOOL check_dirty_only = FALSE;

	ntfs_log_set_handler(ntfs_log_handler_outerr);

	ntfs_log_set_levels(NTFS_LOG_LEVEL_INFO);
	ntfs_log_clear_levels(NTFS_LOG_LEVEL_TRACE|NTFS_LOG_LEVEL_ENTER|NTFS_LOG_LEVEL_LEAVE);
	pb_flags = NTFS_PROGBAR;
	option.verbose = 0;
	opterr = 0;
	option.flags = NTFS_MNT_FSCK | NTFS_MNT_IGNORE_HIBERFILE;

	while ((c = getopt_long(argc, argv, "aCnpqryhSvVD:", opts, NULL)) != EOF) {
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
		case 'S':
			opt_salvage = TRUE;
			break;
		case 'D':
			/* Consumed by libntfs ntfs_fsck_mount() via getenv(). */
			setenv("NTFSCK_SCRATCH_DIR", optarg, 1);
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

	/*
	 * Salvage-aggressive mode only makes sense together with a repair mode: it
	 * performs destructive recovery (e.g. sparsing out compression units that
	 * will not decompress). With a read-only check it has nothing to act on, so
	 * warn and disable it rather than silently doing extra work.
	 */
	if (opt_salvage) {
		if (option.flags & (NTFS_MNT_FS_NO_REPAIR | NTFS_MNT_RDONLY) ||
				check_dirty_only == TRUE) {
			ntfs_log_warning("Salvage mode (-S) has no effect without "
					"a repair mode; ignoring it.\n");
			opt_salvage = FALSE;
		} else {
			ntfs_log_warning("Salvage-aggressive mode enabled: "
					"unrecoverable data may be discarded to "
					"make the volume usable.\n");
		}
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

	/*
	 * Run the check/repair sequence until the volume stops changing. A single
	 * sweep is not always enough: a later pass can legitimately disturb
	 * something an earlier pass already validated -- most notably orphan
	 * recovery (pass 5) re-links inodes into directories the index scan (pass 3)
	 * has already walked, and reparse/index removals touch view indexes checked
	 * earlier in the run.
	 */
	{
		int max_rounds = ntfsck_repair_enabled() ?
				NTFSCK_MAX_REPAIR_ROUNDS : 1;
		int prev_fixes = -1;
		int round;

		for (round = 0; ; round++) {
			BOOL orphan_changed = FALSE;

			ntfsck_check_backup_boot(vol);

			/* Open a crash-safe repair transaction before any write. */
			ntfsck_begin_repair(vol);

			if (ntfsck_run_repair_passes(vol, &orphan_changed))
				goto err_out;

			/*
			 * A round that repaired everything it found leaves
			 * nothing for another round to do. A round that repaired
			 * nothing cannot do better next time either: what is left
			 * is what this build cannot fix. Only a round that fixed
			 * some but not all of what it found is worth repeating --
			 * an earlier repair may have unblocked a check that could
			 * not run the first time.
			 *
			 * The one exception is orphan recovery: it relinks inodes
			 * and can leave a fresh, uncounted inconsistency behind (a
			 * relinked inode's INDEX_ROOT header), so a round that
			 * fixed everything it found but did rebuild an orphan must
			 * still be re-verified. Otherwise this never re-verifies a
			 * repair: a fix that is counted but never written back, or
			 * one that disturbs a structure an earlier pass already
			 * accepted, ends the run reporting success and only the
			 * next invocation finds it.
			 */
			if (fsck_errors == fsck_fixes && !orphan_changed)
				break;			/* nothing left to repair */
			if (fsck_fixes == 0)
				break;			/* nothing changed; the rest is unfixable */
			if (round + 1 >= max_rounds)
				break;			/* iteration cap reached */
			if (prev_fixes >= 0 && fsck_fixes >= prev_fixes &&
					(fsck_errors - fsck_fixes) > 0)
				break;			/* not converging: give up */
			prev_fixes = fsck_fixes;

			ntfs_log_info("Repairs applied; re-checking the volume "
					"(round %d)...\n", round + 2);

			/* Re-mount for a fresh, self-consistent fsck state. */
			ntfs_fsck_umount(vol);
			vol = NULL;
			total_errors += fsck_errors;
			total_fixes += fsck_fixes;
			fsck_errors = 0;
			fsck_fixes = 0;
			total_cnt = 0;
			checked_cnt = 0;

			vol = ntfs_fsck_mount(path, option.flags);
			if (!vol) {
				ntfs_log_error("Failed to re-mount %s for repair "
						"round %d (errno %d)\n", path,
						round + 2, errno);
				fsck_err_found();
				goto err_out;
			}
		}
	}

err_out:
	/*
	 * Errors left are the ones the final round could not fix; the rounds before
	 * it ended with their own errors already repaired. The found and fixed
	 * totals, though, span the whole run -- reporting only the final round would
	 * hide every repair that made the volume clean.
	 */
	errors = fsck_errors - fsck_fixes;
	total_errors += fsck_errors;
	total_fixes += fsck_fixes;
	if (errors) {
		ntfs_log_info("%d errors left (errors:%d, fixed:%d)\n",
				errors, total_errors, total_fixes);
		ret = RETURN_FS_ERRORS_LEFT_UNCORRECTED;
	} else {
		ntfs_log_info("Clean, No errors found or left (errors:%d, fixed:%d)\n",
				total_errors, total_fixes);
		if (total_fixes)
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
