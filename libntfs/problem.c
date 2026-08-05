/* SPDX-License-Identifier : GPL-2.0 */
/* problem.c : manage problem which is found during fsck */

#include <strings.h>
#include "problem.h"

BOOL fsck_step_header_open;

static struct ntfs_problem problem_table[] = {
	/* Pre-scan MFT */
	{ PR_PRE_SCAN_MFT,
		"Scan all mft entries and apply those lcn bitmap to disk.",
		PR_PREEN_NOMSG | PR_NO_NOMSG,
	},
	{ PR_RESET_LOG_FILE,
		"Reset logfile.",
		PR_PREEN_NOMSG | PR_NO_NOMSG,
	},
	{ PR_MFT_FLAG_MISMATCH,
		"Inode(@In:@IN): MFT flag set as directory, but MFT/$FN is not set.",
	},
	{ PR_DIR_NONZERO_SIZE,
		"Directory(@In:@IN) has non-zero length(@Fs:@Is).",
	},
	{ PR_MFT_REPARSE_TAG_MISMATCH,
		"Inode(@In:@IN): Reparse tag is different with IDX/$FN, MFT/$FN.",
	},
	{ PR_MFT_ALLOCATED_SIZE_MISMATCH,
		"Inode(@In): Allocated size is different with IDX/$FN(@Fs), MFT/$DATA(@Is).",
	},
	{ PR_MFT_DATA_SIZE_MISMATCH,
		"Inode(@In): Data size is different with IDX/$FN(@Fd), MFT/$DATA(@Id).",
	},
	{ PR_DIR_FLAG_MISMATCH_IDX_FN,
		"Directory(@In): MFT flag is set to directory, IDX/$FN is not.",
	},
	{ PR_DIR_FLAG_MISMATCH_MFT_FN,
		"Directory(@In): MFT/$FN flag is set to directory, but there's no $IR.",
	},
	{ PR_DIR_IR_NOT_EXIST,
		"Directory(@In): INDEX/$FN flag is set to directory, but there's no $IR.",
	},
	{ PR_MFT_FLAG_MISMATCH_IDX_FN,
		"Inode(@In): MFT/$FN is set to file, but IDX/$FN is set to directory.",
	},
	{ PR_FILE_HAVE_IR,
		"Inode(@In): MFT/$FN is set to file, but there's no $DATA, $IR exist.",
	},
	{ PR_ATTR_LOWEST_VCN_IS_NOT_ZERO,
		"Inode(@In:@At): Attirbute lowest vcn(@av) is not zero.",
	},
	{ PR_ATTR_NON_RESIDENT_SIZES_MISMATCH,
		"Inode(@In:@At): Size of non resident are corrupted.",
	},
	{ PR_ATTR_VALUE_OFFSET_BADLY_ALIGNED,
		"Inode(@In:@At): Value offset badly aligned in attribute.",
	},
	{ PR_ATTR_VALUE_OFFSET_CORRUPTED,
		"Inode(@In:@At): Value offset is corrupted in attribute.",
	},
	{ PR_ATTR_NAME_OFFSET_CORRUPTED,
		"Inode(@In:@At): Name offset is corrupted in attribute.",
	},
	{ PR_ATTR_LENGTH_CORRUPTED,
		"Inode(@In:@At): Attribute length is corrupted in attribute.",
	},
	{ PR_ATTR_FN_FLAG_MISMATCH,
		"Inode(@In:@At): $FN flag's not matched attribute flag.",
	},
	{ PR_IA_MAGIC_CORRUPTED,
		"Directory(@In): Index block(vcn:@av) signature is corrupted.",
	},
	{ PR_MFT_MAGIC_CORRUPTED,
		"Inode(@In): MFT magic signature is corrupted.",
	},
	{ PR_MFT_SIZE_CORRUPTED,
		"Inode(@In:@Is): MFT allocated size is corrupted.",
	},
	{ PR_MFT_ATTR_OFFSET_CORRUPTED,
		"Inode(@In): MFT attribute offset is badly algined.",
	},
	{ PR_MFT_BIU_CORRUPTED,
		"Inode(@In): MFT byte-in-use field is corrupted.",
	},
	{ PR_IE_ZERO_LENGTH,
		"Directory(@In): Index entry length is zero, It should be at least size of IE header.",
	},
	{ PR_BOOT_SECTOR_INVALID,
		"Invalid boot sector,",
	},
	{ PR_MOUNT_LOAD_MFT_FAILURE,
		"Failed to load $MFT(0), recover from $MFTMirr",
	},
	{ PR_MOUNT_LOAD_MFTMIRR_FAILURE,
		"Failed to load $MFTMirr(1), recover from $MFTMirr",
	},
	{ PR_MOUNT_REPAIRED_MFTMIRR_CORRUPTED,
		"$MFT is corrupted, repair $MFT from $MFTMirr",
	},
	{ PR_IE_FLAG_SUB_NODE_CORRUPTED,
		"Directory(@In): Index entry have sub-node, buf flag is not set.",
	},
	{ PR_MOUNT_MFT_MFTMIRR_MISMATCH,
		"$MFT/$MFTMirr records do not match. Repair $MFTMirror",
	},
	{ PR_IE_END_FLAG_CORRUPTED,
		"Directory(@In): Index entry is empty, but did not set end flag.",
	},
	{ PR_IE_RESERVED_NOT_ZERO,
		"Inode(@In): Index entry reserved field is not zero. Clear it.",
	},
	{ PR_LOG_APPLY_RUNLIST_TO_DISK,
		"Inode(@In): Repaired runlist should be applied to disk",
		PR_PREEN_NOMSG,
	},
	{ PR_DIR_HAVE_RESIDENT_IA,
		"Directory(@In) has resident $INDEX_ALLOCATION.",
	},
	{ PR_ATTRLIST_LENGTH_CORRUPTED,
		"Inode(@In:@At): Attribute list length is corrupted.",
	},
	{ PR_ATTRLIST_REBUILD,
		"Inode(@In): Attribute list is corrupted. Rebuild it.",
	},
	{ PR_IDX_ENTRY_CORRUPTED,
		"Inode(@In:@IN): Index entry is corrupted, Remove it from parent(@Pn)",
	},
	{ PR_IDX_BITMAP_SIZE_MISMATCH,
		"Inode(@In): Bitmap of index allocation size are different.",
	},
	{ PR_IDX_BITMAP_MISMATCH,
		"Inode(@In): Checked index bitmap and on disk index bitmap are different.",
	},
	{ PR_CLUSTER_BITMAP_MISMATCH,
		"Inode(@In:@At): Cluster bitmap of fsck and disk are different. Apply to disk",
	},
	{ PR_ORPHANED_MFT_REPAIR,
		"Found an orphaned file(@In), try to add index entry",
	},
	{ PR_ROOT_MISSING_SYSTEM_FILE_ENTRY,
		"System file(@In) is missing from root directory(@Pn).",
	},
	{ PR_INDEX_INITIALIZE,
		"Initialize all index structure of inode(@In).",
	},
	{ PR_DIR_IDX_INITIALIZE,
		"Initialize all index structure of directory(@In).",
	},
	{ PR_BITMAP_MFT_SIZE_MISMATCH,
		"$Bitmap size(@Ad) is smaller than expected(@Sd).",
	},
	{ PR_MFTMIRR_SIZE_MISMATCH,
		"$MFTMirr size(@Ad) differs from expected(@Sd), restore the mirror.",
	},
	{ PR_MFT_SIZE_HIDES_RECORDS,
		"$MFT size(@Ad) hides in-use mft records, expected at least(@Sd).",
	},
	{ PR_MFT_SIZE_EXCEEDS_ALLOCATION,
		"$MFT size(@Ad) reaches past its allocation(@As).",
	},
	{ PR_DIR_EMPTY_IE_LENGTH_CORRUPTED,
		"Directory(@In): Length of empty entry of $INDEX_ROOT is not valid.",
	},
	{ PR_CLUSTER_DUPLICATION_FOUND,
		"Inode(@In:@At): Found cluster duplication.",
	},
	{ PR_EA_CHAIN_CORRUPTED,
		"Inode(@In): $EA chain is corrupted. Remove $EA and $EA_INFORMATION.",
	},
	{ PR_REPARSE_ATTR_CORRUPTED,
		"Inode(@In): $REPARSE_POINT data is corrupted. Remove reparse data and index.",
	},
	{ PR_REPARSE_RECALL_FLAG_MISSING,
		"Inode(@In): WSL special-file reparse point is missing the recall-on-open flag. Restore flag.",
	},
	{ PR_REPARSE_FLAG_MISMATCH,
		"Inode(@In): Reparse flag in $STANDARD_INFORMATION does not match $REPARSE_POINT presence.",
	},
	{ PR_REPARSE_ENTRY_MISSING,
		"Inode(@In): Reparse point is missing from the $Extend/$Reparse index. Add it.",
	},
	{ PR_REPARSE_ENTRY_STALE,
		"Inode(@In): $Extend/$Reparse entry is not backed by a valid reparse point. Remove it.",
	},
	{ PR_CLUSTER_BITMAP_CONSENSUS_FAIL,
		"$Bitmap: MFT scan is too unreliable to free a large number of clusters. Refusing mass-free and marking them in-use instead.",
		PR_NO_NOMSG,
	},
	{ PR_SECURE_SDS_ENTRY_CORRUPTED,
		"Inode(@In): $Secure $SDS entry header is inconsistent.",
		PR_NO_NOMSG,
	},
	{ PR_SECURE_SDS_HASH_MISMATCH,
		"Inode(@In): $Secure $SDS entry hash does not match its security descriptor.",
		PR_NO_NOMSG,
	},
	{ PR_SECURE_SDS_MIRROR_MISMATCH,
		"Inode(@In): $Secure $SDS entry differs from its backup copy.",
		PR_NO_NOMSG,
	},
	{ PR_SECURE_SII_MISMATCH,
		"Inode(@In): $Secure $SII index entry is missing or inconsistent with $SDS.",
		PR_NO_NOMSG,
	},
	{ PR_SECURE_SDH_MISMATCH,
		"Inode(@In): $Secure $SDH index entry is missing or inconsistent with $SDS.",
		PR_NO_NOMSG,
	},
	{ PR_COMPRESSED_UNIT_CORRUPTED,
		"Inode(@In): A compression unit failed to decompress.",
		PR_NO_NOMSG,
	},
	{ PR_COMPRESSED_UNIT_SPARSED,
		"Inode(@In): Replace the corrupted compression unit with a sparse hole to salvage the file?",
	},
	{ PR_ORPHANED_MFT_OPEN_FAILURE,
		"Inode(@In) open failed. Clear MFT bitmap of inode",
		PR_PREEN_NOMSG | PR_NO_NOMSG,
	},
	{ PR_ORPHANED_MFT_CHECK_FAILURE,
		"Inode(@In) check failed. Delete orphaned NFT candidiates",
		PR_PREEN_NOMSG,
	},
	{ PR_UPCASE_CORRUPTED,
		"$UpCase table is corrupted, regenerate the default table",
	},
	{ PR_ATTRDEF_CORRUPTED,
		"$AttrDef table is corrupted, regenerate the default table",
	},
	{ PR_ATTR_INITIALIZED_SIZE_MISMATCH,
		"Inode(@In:@At): Initialized size of non resident attribute is out of range.",
	},
	{ PR_ATTR_EMPTY_DATA_STALE_RUNS,
		"Inode(@In:@At): Empty $DATA still encodes cluster runs, truncate it and make it resident.",
	},
	{ PR_MFT_USA_CORRUPTED,
		"Inode(@In): MFT record fixup header is corrupted, salvage the record.",
	},
	{ PR_MFT_LINK_COUNT_MISMATCH,
		"Inode(@In): Hard link count of MFT record differs from the number of $FILE_NAME(@Sd), fix it.",
	},
	{ PR_MFT_BAAD_RECORD,
		"Inode(@In): MFT record is marked BAAD by a torn multi sector write, salvage what it holds.",
	},
	{ PR_MFT_SEQNO_ZERO,
		"Inode(@In): MFT record has sequence number zero, restore a valid one.",
	},
	{ PR_IDX_SEQNO_ZERO,
		"Inode(@In): Index entry carries sequence number zero, rebind it to the MFT record.",
	},
	{ PR_FN_PARENT_SEQNO_ZERO,
		"Inode(@In): Parent reference of $FILE_NAME carries sequence number zero, update it.",
	},
	{ PR_MFT_BITMAP_SIZE_MISMATCH,
		"$MFT/$BITMAP size(@Ad) doesn't cover all mft records, expected at least(@Sd). Extend it.",
	},
	{ PR_MFT_BITMAP_MISMATCH,
		"Inode(@In:@At): MFT bitmap of fsck and disk are different. Apply to disk",
	},
	{ PR_ATTR_SI_FLAG_MISMATCH,
		"Inode(@In): $STANDARD_INFORMATION flags disagree with the $DATA attribute flags. Sync them",
	},
	{ PR_ATTR_COMPRESSION_UNIT_CORRUPTED,
		"Inode(@In:@At): Compression unit of compressed attribute is invalid. Reset to standard",
	},
	{ PR_ATTR_COMPRESSED_SIZE_MISMATCH,
		"Inode(@In:@At): Compressed size of attribute doesn't match its runlist. Repair it",
	},
	{ PR_ATTR_DATA_FLAGS_CORRUPTED,
		"Inode(@In): $DATA attribute has an invalid flag combination. Normalize it",
	},
	{ PR_MFT_UNNAMED_DATA_MISSING,
		"Inode(@In): Unnamed $DATA attribute is missing. Add an empty one",
	},
	{ PR_DIR_HAVE_UNNAMED_DATA,
		"Inode(@In): Directory has an unnamed $DATA attribute. Remove it",
	},
	{ PR_MFT_SI_FIELDS_CORRUPTED,
		"Inode(@In): $STANDARD_INFORMATION fields are corrupted. Fix them",
	},
	{ PR_MFT_SI_MISSING,
		"Inode(@In): $STANDARD_INFORMATION is missing or too short. Rebuild it from $FILE_NAME",
	},
	{ PR_MFT_SECURITY_ID_DANGLING,
		"Inode(@In): security_id is not in $Secure's $SII index. Clear it",
	},
	{ PR_MFT_USN_INVALID,
		"Inode(@In): usn points beyond the $UsnJrnl journal. Clear it",
	},
	{ PR_ATTR_FN_CORRUPTED_REMOVE,
		"Inode(@In): a $FILE_NAME attribute is corrupted. Remove it",
	},
	{ PR_ORPHANED_MFT_NO_NAME,
		"Inode(@In): orphaned record has no $FILE_NAME. Recover it to lost+found",
	},
	{ PR_ATTR_FN_NAMESPACE_INVALID,
		"Inode(@In): $FILE_NAME namespace is out of range. Reset it to Win32",
	},
	{ PR_DELETED_ORPHAN_REMOVE,
		"Inode(@In) was left in $Extend/$Deleted by an interrupted delete. Remove it.",
	},
	{ PR_FN_INDEX_ENTRY_MISSING,
		"Inode(@In): $FILE_NAME has no matching entry in its parent directory. Add it.",
		PR_PREEN_NOMSG,
	},
	{ PR_ORPHANED_EXTENT_RECORD,
		"Inode(@In): extent record is not referenced by a valid base $ATTRIBUTE_LIST. Release it.",
		PR_PREEN_NOMSG,
	},
	{ PR_NAMESPACE_WALK_INCOMPLETE,
		"Directory namespace walk was incomplete. Refusing reachability-based deletion.",
		PR_NO_NOMSG,
	},
	{ PR_NAMESPACE_RECORD_UNREACHABLE,
		"Inode(@In): allocated base record is not reachable from the root directory.",
		PR_NO_NOMSG,
	},
	{ PR_NAMESPACE_LINK_COUNT_MISMATCH,
		"Inode(@In): hard link count differs from verified directory links(@Sd). Fix it.",
		PR_PREEN_NOMSG,
	},
	{ 0, },
};

static struct ntfs_problem *find_problem(problem_code_t code)
{
	int i;

	for (i = 0; problem_table[i].code; i++) {
		if (problem_table[i].code == code)
			return &problem_table[i];
	}

	return NULL;
}

static void expand_inode_expression(problem_context_t *pctx, char ch)
{
	ntfs_inode *ni = NULL;
	MFT_RECORD *m = NULL;

	if (pctx->ni)
		ni = pctx->ni;
	if (pctx->m)
		m = pctx->m;

	switch (ch) {
		case 'n':	/* inode number */
			fprintf(stderr, "%" PRIu64 "", ni ? ni->mft_no : pctx->inum);
			break;
		case 's':	/* inode allocated size ($FN allocated size) */
			fprintf(stderr, "%" PRIu64 "", ni ? ni->allocated_size :
					m ? le32_to_cpu(m->bytes_allocated) :
					pctx->asize);
			break;
		case 'd':	/* inode data size ($FN data size) */
			fprintf(stderr, "%" PRIu64 "", ni ? ni->data_size : pctx->dsize);
			break;
		case 'N':
			fprintf(stderr, "%s", pctx->filename);
			break;
		default:
			break;
	}
}

static void expand_attr_expression(problem_context_t *pctx, char ch)
{
	ntfs_attr *na = NULL;
	ATTR_RECORD *a = NULL;

	if (!pctx->na && !pctx->a)
		return;

	if (pctx->na)
		na = pctx->na;
	if (pctx->a)
		a = pctx->a;

	switch (ch) {
		case 't':	/* attribute type */
			fprintf(stderr, "%02x", na ? na->type: (int)le32_to_cpu(a->type));
			break;
		case 's':	/* attribute allocated size */
			fprintf(stderr, "%" PRIu64 "",
					na ?
					na->allocated_size :
					sle64_to_cpu(a->allocated_size));
			break;
		case 'd':	/* attribute data size */
			fprintf(stderr, "%" PRIu64 "",
					na ?
					na->data_size :
					sle64_to_cpu(a->data_size));
			break;
		default:
			break;
	}
}

static void expand_fn_expression(problem_context_t *pctx, char ch)
{
	FILE_NAME_ATTR *fn = NULL;

	if (!pctx->fn)
		return;
	fn = pctx->fn;

	switch (ch) {
		case 's':	/* index key ($FN) allocated size */
			fprintf(stderr, "%" PRIu64 "", le64_to_cpu(fn->allocated_size));
			break;
		case 'd':	/* index key ($FN) data size */
			fprintf(stderr, "%" PRIu64 "", le64_to_cpu(fn->data_size));
			break;
		default:
			break;
	}
}

static void expand_pinode_expression(problem_context_t *pctx, char ch)
{
	ntfs_index_context *ictx = NULL;

	if (!pctx->ictx)
		return;
	ictx = pctx->ictx;

	switch (ch) {
		case 'n':	/* parent inode number */
			fprintf(stderr, "%" PRIu64 "", ictx->ni->mft_no);
			break;
		default:
			break;
	}
}

static void expand_ib_expression(problem_context_t *pctx, char ch)
{
	switch (ch) {
		case 'v':	/* index block vcn */
			fprintf(stderr, "%" PRIu64 "", pctx->vcn);
			break;
		default:
			break;
	}
}

static void expand_sp_expression(problem_context_t *pctx, char ch)
{
	switch (ch) {
		case 'd':	/* related data */
			fprintf(stderr, "%" PRIu64 "", pctx->dsize);
			break;
		default:
			break;
	}
}

static void print_param_message(problem_context_t *pctx, const char *param)
{
	const char *cp;
	int i;

	if (!pctx)
		return;

	for (cp = param; *cp; cp++) {
		if (cp[0] != '@') {
			for (i = 1; cp[i]; i++)
				if (cp[i] == '@')
					break;
			fprintf(stderr, "%.*s", i, cp);
			cp += (i - 1);
			continue;
		}

		cp++;
		switch (cp[0]) {
			case 'I':	/* inode */
				cp++;
				expand_inode_expression(pctx, *cp);
				break;
			case 'A':	/* attribute */
				cp++;
				expand_attr_expression(pctx, *cp);
				break;
			case 'F':	/* index key filename */
				cp++;
				expand_fn_expression(pctx, *cp);
				break;
			case 'P':	/* parent inode */
				cp++;
				expand_pinode_expression(pctx, *cp);
				break;
			case 'a':	/* index block */
				cp++;
				expand_ib_expression(pctx, *cp);
				break;
			case 'S':	/* specific data */
				cp++;
				expand_sp_expression(pctx, *cp);
				break;
		}
	}
}

static void print_message(problem_context_t *pctx, const char *message)
{
	if (message && *message)
		print_param_message(pctx, message);
}

static void start_problem_message(void)
{
	if (fsck_step_header_open) {
		fputc('\n', stderr);
		fsck_step_header_open = FALSE;
	}
}

BOOL ntfs_ask_repair(const ntfs_volume *vol)
{
	BOOL repair = FALSE;
	char answer[8];

	if (NVolFsNoRepair(vol) || !NVolFsck(vol)) {
		ntfs_log_error("No\n");
		return FALSE;
	} else if (NVolFsYesRepair(vol) || NVolFsAutoRepair(vol)) {
		ntfs_log_error("Yes\n");
		return TRUE;
	} else if (NVolFsAskRepair(vol)) {
		do {
			ntfs_log_error(" (y/N) ");
			fflush(stderr);

			if (fgets(answer, sizeof(answer), stdin)) {
				if (strcasecmp(answer, "Y\n") == 0)
					return TRUE;
				else if (strcasecmp(answer, "\n") == 0 ||
						strcasecmp(answer, "N\n") == 0)
					return FALSE;
			}
		} while (1);
	}

	return repair;
}

void ntfs_print_problem(ntfs_volume *vol, problem_code_t code, problem_context_t *pctx)
{
	struct ntfs_problem *p;
	int suppress = 0;
	const char *message;


	p = find_problem(code);
	if (!p) {
		ntfs_log_error("Unhandled error code (0x%x)!\n", code);
		return;
	}

	if ((p->flags & PR_PREEN_NOMSG) &&
			(vol->option_flags & NTFS_MNT_FS_PREEN_REPAIR))
		suppress++;

	if ((p->flags & PR_NO_NOMSG) &&
			(vol->option_flags & NTFS_MNT_FS_NO_REPAIR))
		suppress++;

	if (suppress)
		return;

	message = p->desc;
	start_problem_message();
	print_message(pctx, message);
	fprintf(stderr, "\n");
	fflush(stderr);
}

void ntfs_init_problem_ctx(problem_context_t *pctx, ntfs_inode *ni,
		ntfs_attr *na, ntfs_attr_search_ctx *ctx, ntfs_index_context *ictx,
		MFT_RECORD *m, ATTR_RECORD *a, FILE_NAME_ATTR *fn)
{
	if (!pctx)
		return;

	pctx->ni = ni;
	pctx->na = na;
	pctx->ctx = ctx;
	pctx->ictx = ictx;
	pctx->m = m;
	pctx->a = a;
	pctx->fn = fn;
}

BOOL ntfs_fix_problem(ntfs_volume *vol, problem_code_t code, problem_context_t *pctx)
{
	struct ntfs_problem *p;
	int suppress = 0;
	int repair = FALSE;
	const char *message;

	p = find_problem(code);
	if (!p) {
		ntfs_log_error("Unhandled error code (0x%x)!\n", code);
		return FALSE;
	}

	if ((p->flags & PR_PREEN_NOMSG) &&
			(vol->option_flags & NTFS_MNT_FS_PREEN_REPAIR)) {
		suppress++;
		repair = TRUE;
	}
	if ((p->flags & PR_NO_NOMSG) &&
			(vol->option_flags & NTFS_MNT_FS_NO_REPAIR)) {
		suppress++;
		repair = FALSE;
	}

	if (suppress)
		return repair;

	if (pctx)
		pctx->err_code = code;

	message = p->desc;
	start_problem_message();
	print_message(pctx, message);
	fprintf(stderr, " Fix it? ");
	fflush(stderr);

	/* TODO: add flags and check about all errors */
	return ntfs_ask_repair(vol);
}
