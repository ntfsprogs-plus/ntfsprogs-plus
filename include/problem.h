/* SPDX-License-Identifier : GPL-2.0 */
#ifndef PROBLEM_H
#define PROBLEM_H

#include "volume.h"

typedef enum {
	PR_PREEN_NOMSG	= 1 << 0,	/* Don't print a message if preening */
	PR_NO_NOMSG	= 1 << 1,
	PR_FLAG_MAX	= 1 << 6,
} problem_flag_t;

typedef enum {
	PR_PRE_SCAN_MFT		= 0x000001,
	PR_RESET_LOG_FILE,
	PR_MFT_FLAG_MISMATCH,
	PR_DIR_NONZERO_SIZE,
	PR_MFT_REPARSE_TAG_MISMATCH,
	PR_MFT_ALLOCATED_SIZE_MISMATCH,
	PR_MFT_DATA_SIZE_MISMATCH,
	PR_DIR_FLAG_MISMATCH_IDX_FN,
	PR_DIR_FLAG_MISMATCH_MFT_FN,
	PR_DIR_IR_NOT_EXIST,
	PR_MFT_FLAG_MISMATCH_IDX_FN,
	PR_FILE_HAVE_IR,
	PR_ATTR_LOWEST_VCN_IS_NOT_ZERO,
	PR_ATTR_NON_RESIDENT_SIZES_MISMATCH,
	PR_ATTR_VALUE_OFFSET_BADLY_ALIGNED,
	PR_ATTR_VALUE_OFFSET_CORRUPTED,
	PR_ATTR_NAME_OFFSET_CORRUPTED,
	PR_ATTR_LENGTH_CORRUPTED,
	PR_ATTR_FN_FLAG_MISMATCH,
	PR_ATTR_IR_SIZE_MISMATCH,
	PR_IA_MAGIC_CORRUPTED,
	PR_MFT_MAGIC_CORRUPTED,
	PR_MFT_SIZE_CORRUPTED,
	PR_MFT_ATTR_OFFSET_CORRUPTED,
	PR_MFT_BIU_CORRUPTED,
	PR_IE_ZERO_LENGTH,
	PR_BOOT_SECTOR_INVALID,
	PR_MOUNT_LOAD_MFT_FAILURE,
	PR_MOUNT_LOAD_MFTMIRR_FAILURE,
	PR_MOUNT_REPAIRED_MFTMIRR_CORRUPTED,
	PR_IE_FLAG_SUB_NODE_CORRUPTED,
	PR_MOUNT_MFT_MFTMIRR_MISMATCH,
	PR_IE_END_FLAG_CORRUPTED,
	PR_LOG_APPLY_RUNLIST_TO_DISK,
	PR_DIR_HAVE_RESIDENT_IA,
	PR_ATTRLIST_LENGTH_CORRUPTED,
	PR_IDX_ENTRY_CORRUPTED,
	PR_IDX_BITMAP_SIZE_MISMATCH,
	PR_IDX_BITMAP_MISMATCH,
	PR_CLUSTER_BITMAP_MISMATCH,
	PR_ORPHANED_MFT_REPAIR,
	PR_DIR_IDX_INITIALIZE,
	PR_BITMAP_MFT_SIZE_MISMATCH,
	PR_DIR_EMPTY_IE_LENGTH_CORRUPTED,
	PR_CLUSTER_DUPLICATION_FOUND,

	/* pass 4 */
	PR_ORPHANED_MFT_OPEN_FAILURE,
	PR_ORPHANED_MFT_CHECK_FAILURE,
} problem_code_t;

typedef struct problem_context {
	problem_code_t err_code;
	ntfs_inode *ni;
	ntfs_attr *na;
	ntfs_attr_search_ctx *ctx;
	ntfs_index_context *ictx;
	MFT_RECORD *m;
	ATTR_RECORD *a;
	FILE_NAME_ATTR *fn;
	union {
		u64 inum;
		u64 asize;
		u64 dsize;
		u64 vcn;
		u32 attr_type;
	};
	char *filename;
} problem_context_t;

typedef struct ntfs_problem {
	problem_code_t	code;
	const char	*desc;
	problem_flag_t	flags;
	int		log_level;
} ntfs_problem_t;

void ntfs_init_problem_ctx(problem_context_t *pctx, ntfs_inode *ni, ntfs_attr *na,
		ntfs_attr_search_ctx *ctx, ntfs_index_context *ictx,
		MFT_RECORD *m, ATTR_RECORD *a, FILE_NAME_ATTR *fn);
void ntfs_print_problem(ntfs_volume *vol, problem_code_t code, problem_context_t *pctx);
BOOL ntfs_fix_problem(ntfs_volume *vol, problem_code_t code, problem_context_t *pctx);
BOOL ntfs_ask_repair(const ntfs_volume *vol);
#endif
