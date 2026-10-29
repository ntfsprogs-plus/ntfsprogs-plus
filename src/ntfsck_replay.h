/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef NTFSCK_REPLAY_H
#define NTFSCK_REPLAY_H

#include "volume.h"

struct ntfsck_replay;

/* Prepare the complete recovery in memory: 0 clean, 1 pending, -1 error. */
int ntfsck_replay_prepare(ntfs_volume *vol, struct ntfsck_replay **result);
int ntfsck_replay_commit(struct ntfsck_replay *replay);
void ntfsck_replay_free(struct ntfsck_replay *replay);

#endif
