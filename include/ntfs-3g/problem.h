#ifndef PROBLEM_H
#define PROBLEM_H

#include "volume.h"

/* TODO: all fsck problem should be added */
typedef enum {
	PR_PRE_SCAN_MFT = 0x01,
	PR_RESET_LOG_FILE = 0x02,
} problem_code_t;

typedef enum {
	PR_PREEN_NOMSG = 0x000001,	/* Don't print a message if preening */
	PR_NO_NOMSG = 0x000002,
} problem_flag_t;

struct ntfs_problem {
	problem_code_t	code;
	const char *	desc;
	problem_flag_t	flags;
	int		log_level;
};

BOOL ntfs_fix_problem(ntfs_volume *vol, problem_code_t code);
BOOL ntfs_ask_repair(const ntfs_volume *vol);
#endif
