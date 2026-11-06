// SPDX-License-Identifier: GPL-2.0-or-later
/* Exercise the production recovery engine without running later fsck repairs. */
#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "device_io.h"
#include "device.h"
#include "dir.h"
#include "logging.h"
#include "ntfsck_replay.h"
#include "unistr.h"

static struct ntfs_device_operations *original_ops;
static struct ntfs_device_operations fault_ops;
static unsigned int writes, syncs;

static unsigned long fault_at(const char *name)
{
	const char *value = getenv(name);

	return value ? strtoul(value, NULL, 10) : 0;
}

static BOOL fault_range(const char *name, s64 offset, s64 count)
{
	u64 point = fault_at(name);

	return point && (u64)offset <= point && point - offset < (u64)count;
}

/* Inject read errors after bootstrap, including the durable-tail discovery. */
static s64 fault_pread(struct ntfs_device *dev, void *buf, s64 count, s64 offset)
{
	if (fault_range("NTFSCK_REPLAY_FAIL_READ_AT", offset, count)) {
		errno = fault_at("NTFSCK_REPLAY_READ_ERRNO");
		if (!errno)
			errno = EIO;
		return -1;
	}
	if (fault_range("NTFSCK_REPLAY_SHORT_READ_AT", offset, count))
		return 0;
	return original_ops->pread(dev, buf, count, offset);
}

/* Commit faults start only after the read-only preparation has completed. */
static s64 fault_pwrite(struct ntfs_device *dev, const void *buf, s64 count, s64 offset)
{
	unsigned long fail = fault_at("NTFSCK_REPLAY_FAIL_WRITE");
	unsigned long torn = fault_at("NTFSCK_REPLAY_TORN_WRITE");
	unsigned long crash = fault_at("NTFSCK_REPLAY_CRASH_WRITE");
	BOOL restart_fail = FALSE;
	BOOL torn_target = fault_range("NTFSCK_REPLAY_TORN_TARGET_AT", offset, count);

	writes++;
	if (count >= 64 && !memcmp(buf, "RSTR", 4)) {
		le16 area, flags;

		memcpy(&area, (const u8 *)buf + 24, sizeof(area));
		if (le16_to_cpu(area) + 16 <= count) {
			memcpy(&flags, (const u8 *)buf + le16_to_cpu(area) + 14, sizeof(flags));
			restart_fail = fault_at(le16_to_cpu(flags) & 2 ?
					"NTFSCK_REPLAY_FAIL_CLEAN" : "NTFSCK_REPLAY_FAIL_DIRTY");
		}
	}
	if (crash && writes == crash)
		_exit(75);
	if ((torn && writes == torn) || torn_target)
		original_ops->pwrite(dev, buf, count / 2, offset);
	if ((fail && writes >= fail) || (torn && writes >= torn) || torn_target || restart_fail ||
			fault_range("NTFSCK_REPLAY_FAIL_TARGET_AT", offset, count)) {
		errno = EIO;
		return -1;
	}
	return original_ops->pwrite(dev, buf, count, offset);
}

static int fault_sync(struct ntfs_device *dev)
{
	unsigned long fail = fault_at("NTFSCK_REPLAY_FAIL_SYNC");

	if (fail && ++syncs >= fail) {
		errno = EIO;
		return -1;
	}
	return original_ops->sync(dev);
}

/* Build directory and hard-link fixtures with the normal library writers. */
static int fixture_name(int argc, char **argv)
{
	ntfs_volume *vol = ntfs_mount(argv[2], 0);
	ntfs_inode *dir = NULL, *ni = NULL;
	ntfschar *name = NULL;
	int length, ret = -1;
	BOOL create = !strcmp(argv[1], "--mkdir");

	if (!vol)
		return 2;
	length = ntfs_mbstoucs(argv[argc - 1], &name);
	if (length < 0)
		goto out;
	dir = ntfs_inode_open(vol, strtoull(argv[create ? 3 : 4], NULL, 10));
	if (!dir)
		goto out;
	if (create) {
		ni = ntfs_create(dir, const_cpu_to_le32(0), name, length, S_IFDIR);
		if (!ni)
			goto out;
		printf("%"PRIu64"\n", ni->mft_no);
		ret = 0;
	} else {
		ni = ntfs_inode_open(vol, strtoull(argv[3], NULL, 10));
		if (ni)
			ret = ntfs_link(ni, dir, name, length);
	}
out:
	free(name);
	if (ntfs_inode_close(ni))
		ret = -1;
	if (ntfs_inode_close(dir))
		ret = -1;
	errno = 0;
	if (ntfs_umount(vol, FALSE))
		ret = -1;
	return ret ? 1 : 0;
}

static int fixture_extent(char **argv)
{
	ntfs_volume *vol = ntfs_mount(argv[2], 0);
	ntfs_inode *ni = NULL, *extent;
	ntfs_attr_search_ctx *ctx = NULL;
	ATTR_TYPES type = cpu_to_le32(strtoul(argv[4], NULL, 0));
	int ret = -1;

	if (!vol)
		return 2;
	ni = ntfs_inode_open(vol, strtoull(argv[3], NULL, 10));
	if (!ni || (!NInoAttrList(ni) && ntfs_inode_add_attrlist(ni)))
		goto out;
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx || ntfs_attr_lookup(type, AT_UNNAMED, 0, CASE_SENSITIVE,
			0, NULL, 0, ctx))
		goto out;
	extent = ntfs_mft_record_alloc(vol, ni);
	if (!extent || ntfs_attr_record_move_to(ctx, extent))
		goto out;
	printf("%"PRIu64"\n", extent->mft_no);
	ret = 0;
out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (ntfs_inode_close(ni))
		ret = -1;
	errno = 0;
	if (ntfs_umount(vol, FALSE))
		ret = -1;
	return ret ? 1 : 0;
}

int main(int argc, char **argv)
{
	struct ntfs_device *dev;
	struct ntfsck_replay *plan = NULL;
	ntfs_volume *vol;
	int ret;

	if ((argc == 5 && !strcmp(argv[1], "--mkdir")) ||
			(argc == 6 && !strcmp(argv[1], "--link")))
		return fixture_name(argc, argv);
	if (argc == 5 && !strcmp(argv[1], "--extent"))
		return fixture_extent(argv);
	if (argc != 2)
		return 2;
	ntfs_log_set_handler(ntfs_log_handler_outerr);
	dev = ntfs_device_alloc(argv[1], 0, &ntfs_device_default_io_ops, NULL);
	if (!dev)
		return 2;
	vol = ntfs_volume_startup(dev, NTFS_MNT_RDONLY);
	if (!vol) {
		ntfs_device_free(dev);
		return 2;
	}
	original_ops = dev->d_ops;
	fault_ops = *original_ops;
	fault_ops.pread = fault_pread;
	fault_ops.pwrite = fault_pwrite;
	fault_ops.sync = fault_sync;
	dev->d_ops = &fault_ops;
	ret = ntfsck_replay_prepare(vol, &plan);
	if (ret == 1) {
		ret = dev->d_ops->close(dev);
		NDevClearReadOnly(dev);
		if (!ret)
			ret = (dev->d_ops->open)(dev, O_RDWR);
		if (!ret) {
			NVolClearReadOnly(vol);
			ret = ntfsck_replay_commit(plan);
		}
	}
	dev->d_ops = original_ops;
	ntfsck_replay_free(plan);
	errno = 0;
	if (ntfs_umount(vol, FALSE))
		ret = -1;
	return ret ? 1 : 0;
}
