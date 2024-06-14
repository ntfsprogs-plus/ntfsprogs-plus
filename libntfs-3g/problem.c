#include "problem.h"

static struct ntfs_problem problem_table[] = {
	/* Pre-scan MFT */
	{ PR_PRE_SCAN_MFT,
		"Scan all mft entries and apply those lcn bitmap to disk",
		PR_PREEN_NOMSG | PR_NO_NOMSG,
	},
	{ PR_RESET_LOG_FILE,
		"Reset logfile",
		PR_PREEN_NOMSG | PR_NO_NOMSG,
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

static void print_message(const char *message)
{
	if (*message)
		ntfs_log_error("%s", message);
}

BOOL ntfs_ask_repair(const ntfs_volume *vol)
{
	BOOL repair = FALSE;
	char answer[8];

	if (NVolFsNoRepair(vol) || !NVolFsck(vol)) {
		ntfs_log_error("? No\n");
		return FALSE;
	} else if (NVolFsYesRepair(vol) || NVolFsAutoRepair(vol)) {
		ntfs_log_error("? Yes\n");
		return TRUE;
	} else if (NVolFsAskRepair(vol)) {
		do {
			ntfs_log_error(" (y/N)? ");
			fflush(stdout);

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

void ntfs_print_problem(ntfs_volume *vol, problem_code_t code)
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
	print_message(message);
}

BOOL ntfs_fix_problem(ntfs_volume *vol, problem_code_t code)
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

	message = p->desc;
	print_message(message);

	/* TODO: add flags and check about all errors */
	return ntfs_ask_repair(vol);
}
