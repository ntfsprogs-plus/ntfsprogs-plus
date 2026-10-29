/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef NTFS_JOURNAL_REPLAY_H
#define NTFS_JOURNAL_REPLAY_H

#include "volume.h"

struct ntfs_journal_replay;

/* Prepare the complete recovery in memory: 0 clean, 1 pending, -1 error. */
int ntfs_journal_replay_prepare(ntfs_volume *vol, struct ntfs_journal_replay **result);
int ntfs_journal_replay_commit(struct ntfs_journal_replay *replay);
void ntfs_journal_replay_free(struct ntfs_journal_replay *replay);

#endif
