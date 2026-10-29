// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Userspace NTFS journal recovery. The recovery ordering and operation
 * semantics follow ntfs-journal-work/logfile.c: analyze, redo, then undo active
 * transactions. All target changes are prepared in memory before any write.
 */
#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "attrib.h"
#include "device.h"
#include "dir.h"
#include "index.h"
#include "inode.h"
#include "logfile.h"
#include "logging.h"
#include "misc.h"
#include "mst.h"
#include "ntfsck_replay.h"
#include "runlist.h"

#define REPLAY_BUCKETS 4096
#define REPLAY_SECTOR 512
#define REPLAY_ALLOCATED 0xffffffffU
#define REPLAY_BATCH_MAGIC 0x54494d4d4f435442ULL
#define REPLAY_TRANSACTION_SLOTS ((65535U - 24 + 39) / 40)
#define REPLAY_TRANSACTION_BYTES ((REPLAY_TRANSACTION_SLOTS + 7) / 8)

enum replay_op {
	Noop, CompensationLogRecord, InitializeFileRecordSegment,
	DeallocateFileRecordSegment, WriteEndOfFileRecordSegment,
	CreateAttribute, DeleteAttribute, UpdateResidentValue,
	UpdateNonresidentValue, UpdateMappingPairs, DeleteDirtyClusters,
	SetNewAttributeSizes, AddIndexEntryRoot, DeleteIndexEntryRoot,
	AddIndexEntryAllocation, DeleteIndexEntryAllocation, WriteEndOfIndexBuffer,
	SetIndexEntryVcnRoot, SetIndexEntryVcnAllocation, UpdateFileNameRoot,
	UpdateFileNameAllocation, SetBitsInNonresidentBitMap,
	ClearBitsInNonresidentBitMap, HotFix, EndTopLevelAction, PrepareTransaction,
	CommitTransaction, ForgetTransaction, OpenNonresidentAttribute,
	OpenAttributeTableDump, AttributeNamesDump, DirtyPageTableDump,
	TransactionTableDump, UpdateRecordDataRoot, UpdateRecordDataAllocation,
	UpdateRelativeDataIndex, UpdateRelativeDataAllocation, ZeroEndOfFileRecord,
};

struct replay_record {
	struct replay_record *next;
	u64 lsn, previous, undo_next;
	u32 length, transaction, type;
	u16 flags;
	u8 data[];
};

struct replay_sector {
	struct replay_sector *next;
	s64 offset;
	u64 vcn;
	u16 slot;
	BOOL covered;
	u8 original[REPLAY_SECTOR];
	u8 data[REPLAY_SECTOR];
};

struct replay_attr {
	struct replay_attr *next;
	u32 slot, type, index_size;
	u16 name_bytes;
	u8 entry[44];
	u8 *name;
};

struct replay_image {
	struct replay_image *next;
	u64 physical;
	u32 size, offset;
	u16 raw_slot;
	BOOL mft;
	u8 log[];
};

struct replay_log_page {
	struct replay_log_page *next;
	u64 offset;
	u8 data[];
};

struct replay_dirty {
	struct replay_dirty *next;
	u32 slot, count;
	u64 vcn, oldest;
	u64 lcns[];
};

struct replay_transaction {
	struct replay_transaction *next;
	u32 slot;
	u8 state;
	u64 first_lsn, undo_next;
};

struct replay_filename {
	struct replay_filename *next;
	u64 mft_no;
};

struct replay_tail {
	u64 offset, lsn;
	u8 *page;
};

struct replay_logfile {
	runlist_element *runs;
	s64 allocated, data, initialized;
};

struct ntfsck_replay {
	ntfs_volume *vol;
	ntfs_inode *log_ni;
	ntfs_attr *log_na;
	struct replay_logfile log_initial, log_final;
	runlist_element *mft_rl;
	struct replay_sector *sectors[REPLAY_BUCKETS];
	struct replay_record *records;
	struct replay_attr *attrs;
	struct replay_dirty *dirty;
	struct replay_dirty **dirty_tail;
	struct replay_transaction *transactions;
	struct replay_filename *filenames;
	struct replay_image *images;
	struct replay_log_page *recovery_pages;
	struct replay_tail tails[32];
	u8 *restart_page;
	u32 restart_size;
	u32 tail_count, page_size, data_offset, header_size, file_bits;
	u32 last_data_length;
	u32 checkpoint_version, attr_size;
	u32 restart_first;
	u16 client, client_sequence;
	u64 log_size, first_page, mask, oldest, current, checkpoint;
	u64 retained;
	u64 mft_allocated;
	u64 log_record;
	u16 log_attr;
	u64 redo_count, undo_count;
	BOOL filename_changed;
	BOOL log_changed, log_moved, log_bootstrap;
};

/* Accessors also cover unaligned fields in log payloads and view indexes. */
static u16 r16(const void *p)
{
	le16 value;

	memcpy(&value, p, sizeof(value));
	return le16_to_cpu(value);
}

static u32 r32(const void *p)
{
	le32 value;

	memcpy(&value, p, sizeof(value));
	return le32_to_cpu(value);
}

static u64 r64(const void *p)
{
	le64 value;

	memcpy(&value, p, sizeof(value));
	return le64_to_cpu(value);
}

static void w16(void *p, u16 value)
{
	le16 encoded = cpu_to_le16(value);

	memcpy(p, &encoded, sizeof(encoded));
}

static void w32(void *p, u32 value)
{
	le32 encoded = cpu_to_le32(value);

	memcpy(p, &encoded, sizeof(encoded));
}

static void w64(void *p, u64 value)
{
	le64 encoded = cpu_to_le64(value);

	memcpy(p, &encoded, sizeof(encoded));
}

static int replay_invalid(void)
{
	errno = EINVAL;
	return -1;
}

static BOOL replay_power_of_two(u32 value)
{
	return value && !(value & (value - 1));
}

static u64 replay_next_page(struct ntfsck_replay *r, u64 pos)
{
	pos += r->page_size;
	return pos >= r->log_size ? r->first_page : pos;
}

static int replay_lsn_offset(struct ntfsck_replay *r, u64 lsn, u64 *pos)
{
	if ((lsn & r->mask) >= r->log_size / 8)
		return replay_invalid();
	*pos = (lsn & r->mask) << 3;
	if (!lsn || *pos < r->first_page || *pos >= r->log_size)
		return replay_invalid();
	return 0;
}

static int replay_log_page(struct ntfsck_replay *r, u64 pos, u8 *page)
{
	u32 i;
	u64 newest = 0;
	const u8 *tail = NULL;
	int ret;
	int error = EINVAL;
	s64 got;

	if (pos > r->log_size - r->page_size)
		return replay_invalid();
	got = ntfs_attr_pread(r->log_na, pos, r->page_size, page);
	if (got != r->page_size) {
		error = got < 0 && errno ? errno : EIO;
		ret = -1;
	} else
		ret = memcmp(page, "RCRD", 4) ||
			ntfs_mst_post_read_fixup((NTFS_RECORD *)page, r->page_size);
	if (!ret)
		newest = r64(page + 8);
	for (i = 0; i < r->tail_count; i++)
		if (r->tails[i].offset == pos && (ret || r->tails[i].lsn > newest)) {
			newest = r->tails[i].lsn;
			tail = r->tails[i].page;
			ret = 0;
		}
	if (tail)
		memcpy(page, tail, r->page_size);
	if (ret) {
		errno = error;
		return -1;
	}
	return 0;
}

/* Tail copies are read through an overlay; the original log stays intact. */
static int replay_load_tails(struct ntfsck_replay *r, unsigned int major)
{
	u32 i, count = major >= 2 ? 32 : 2;

	for (i = 0; i < count; i++) {
		u8 *page = ntfs_malloc(r->page_size);
		u64 pos, lsn;
		s64 got;

		if (!page)
			return -1;
		got = ntfs_attr_pread(r->log_na, (u64)(i + 2) * r->page_size,
				r->page_size, page);
		if (got != r->page_size) {
			int error = got < 0 && errno ? errno : EIO;

			free(page);
			errno = error;
			return -1;
		}
		if (memcmp(page, "RCRD", 4) ||
				ntfs_mst_post_read_fixup((NTFS_RECORD *)page, r->page_size)) {
			free(page);
			continue;
		}
		lsn = r64(page + 32);
		if (replay_lsn_offset(r, lsn, &pos)) {
			free(page);
			continue;
		}
		pos &= ~((u64)r->page_size - 1);
		/* Tail headers use this field for their destination file offset. */
		if (r64(page + 8) >= r->first_page &&
				r64(page + 8) < r->log_size &&
				!(r64(page + 8) & (r->page_size - 1)))
			pos = r64(page + 8);
		w64(page + 8, lsn);
		r->tails[r->tail_count++] = (struct replay_tail) {
			.offset = pos, .lsn = lsn, .page = page,
		};
	}
	return 0;
}

static struct replay_record *replay_read_record(struct ntfsck_replay *r,
		u64 lsn, u64 *next)
{
	struct replay_record *rec = NULL;
	u8 *page = NULL;
	u64 pos, start, sequence;
	u32 offset, length, copied = 0, chunk;

	if (lsn < r->oldest || lsn > r->current)
		goto invalid;
	if (replay_lsn_offset(r, lsn, &pos))
		goto fail;
	start = pos;
	offset = pos & (r->page_size - 1);
	pos -= offset;
	if (offset < r->data_offset || offset > r->page_size - r->header_size)
		goto invalid;
	page = ntfs_malloc(r->page_size);
	if (!page)
		return NULL;
	if (replay_log_page(r, pos, page))
		goto fail;
	if (r64(page + offset) != lsn ||
			r16(page + offset + 28) != r->client_sequence ||
			r16(page + offset + 30) != r->client)
		goto invalid;
	length = r32(page + offset + 24);
	if (!length || length >= r->log_size - r->first_page)
		goto invalid;
	rec = ntfs_malloc(sizeof(*rec) + length);
	if (!rec)
		goto fail;
	*rec = (struct replay_record) {
		.lsn = lsn, .previous = r64(page + offset + 8),
		.undo_next = r64(page + offset + 16), .length = length,
		.transaction = r32(page + offset + 36),
		.type = r32(page + offset + 32), .flags = r16(page + offset + 40),
	};
	offset += r->header_size;
	if (!(rec->flags & 1) && length > r->page_size - offset)
		goto invalid;
	while (copied < length) {
		if (r64(page + 8) < lsn)
			goto invalid;
		chunk = min(length - copied, r->page_size - offset);
		memcpy(rec->data + copied, page + offset, chunk);
		copied += chunk;
		offset += chunk;
		if (copied == length) {
			if (!(r32(page + 16) & 1) || r64(page + 32) < lsn)
				goto invalid;
			break;
		}
		if (r64(page + 8) == r64(page + 32))
			goto invalid;
		pos = replay_next_page(r, pos);
		if (replay_log_page(r, pos, page))
			goto fail;
		offset = r->data_offset;
	}
	if (next) {
		sequence = lsn >> r->file_bits;
		if (pos + offset <= start)
			sequence++;
		if (r64(page + 8) == lsn ||
				((offset + 7) & ~7U) > r->page_size - r->header_size) {
			pos = replay_next_page(r, pos);
			if (pos == r->first_page)
				sequence++;
			offset = r->data_offset;
		}
		*next = (sequence << r->file_bits) | ((pos + ((offset + 7) & ~7U)) >> 3);
		if (*next <= lsn)
			goto invalid;
		if (*next > r->current)
			*next = 0;
	}
	if (!r->retained || lsn < r->retained)
		r->retained = lsn;
	free(page);
	return rec;
invalid:
	replay_invalid();
fail:
	free(rec);
	free(page);
	return NULL;
}

/* The overlay gives overlapping operations one coherent view of each sector. */
static int replay_io(struct ntfsck_replay *r, u64 pos, void *buffer,
		u32 length, BOOL write, const u8 *log, u64 vcn)
{
	u8 *data = buffer;
	u64 limit = (u64)r->vol->nr_clusters << r->vol->cluster_size_bits;

	if (pos > limit || length > limit - pos)
		return replay_invalid();
	while (length) {
		u64 base = pos & ~(u64)(REPLAY_SECTOR - 1);
		u32 offset = pos - base, count = min(length, REPLAY_SECTOR - offset);
		u32 bucket = (base / REPLAY_SECTOR) % REPLAY_BUCKETS;
		struct replay_sector *sector;

		for (sector = r->sectors[bucket]; sector; sector = sector->next)
			if ((u64)sector->offset == base)
				break;
		if (!sector) {
			sector = ntfs_calloc(sizeof(*sector));
			if (!sector)
				return -1;
			if (ntfs_pread(r->vol->dev, base, REPLAY_SECTOR,
					sector->original) != REPLAY_SECTOR) {
				free(sector);
				return -1;
			}
			memcpy(sector->data, sector->original, REPLAY_SECTOR);
			sector->offset = base;
			sector->next = r->sectors[bucket];
			r->sectors[bucket] = sector;
		}
		if (write) {
			memcpy(sector->data + offset, data, count);
			sector->slot = r16(log + 12);
			sector->vcn = vcn;
		} else
			memcpy(data, sector->data + offset, count);
		pos += count;
		data += count;
		length -= count;
	}
	return 0;
}

static int replay_lcns(struct ntfsck_replay *r, const u8 *log,
		u64 pos, void *buffer, u32 length, BOOL write)
{
	u32 count = r16(log + 14), cluster_size = r->vol->cluster_size;
	u8 *data = buffer;
	u64 coverage = (u64)count * cluster_size;

	pos += (u64)r16(log + 20) << 9;
	if (pos > coverage || length > coverage - pos)
		return replay_invalid();
	while (length) {
		u64 lcn = r64(log + 32 + (pos / cluster_size) * 8);
		u32 offset = pos & (cluster_size - 1);
		u32 chunk = min(length, cluster_size - offset);

		if (lcn >= (u64)r->vol->nr_clusters)
			return replay_invalid();
		if (replay_io(r, (lcn << r->vol->cluster_size_bits) + offset,
				data, chunk, write, log, r64(log + 24) + pos / cluster_size))
			return -1;
		pos += chunk;
		data += chunk;
		length -= chunk;
	}
	return 0;
}

static int replay_init_mft(struct ntfsck_replay *r)
{
	u32 count = 0;
	runlist_element *runs;

	if (ntfs_attr_map_whole_runlist(r->vol->mft_na))
		return -1;
	while (r->vol->mft_na->rl[count].length)
		count++;
	runs = ntfs_malloc((size_t)(count + 1) * sizeof(*runs));
	if (!runs)
		return -1;
	memcpy(runs, r->vol->mft_na->rl, (size_t)(count + 1) * sizeof(*runs));
	free(r->mft_rl);
	r->mft_rl = runs;
	return 0;
}

/* MFT operations address a logical record, even after its old LCN was freed. */
static u8 *replay_mft_target(struct ntfsck_replay *r, const u8 *log)
{
	u64 vcn = r64(log + 24), pos;
	u32 size = r->vol->cluster_size, count, i;
	u8 *target;

	if (vcn > ((u64)INT64_MAX >> r->vol->cluster_size_bits))
		goto invalid;
	pos = vcn << r->vol->cluster_size_bits;
	if (((u64)r16(log + 20) << 9) > INT64_MAX - pos)
		goto invalid;
	pos += (u64)r16(log + 20) << 9;
	pos &= ~((u64)r->vol->mft_record_size - 1);
	vcn = pos >> r->vol->cluster_size_bits;
	count = ((pos & (size - 1)) + r->vol->mft_record_size + size - 1) / size;
	target = ntfs_malloc(32ULL + count * 8);
	if (!target)
		return NULL;
	memcpy(target, log, 32);
	w16(target + 14, count);
	w16(target + 20, (pos & (size - 1)) / REPLAY_SECTOR);
	w64(target + 24, vcn);
	for (i = 0; i < count; i++) {
		LCN lcn = ntfs_rl_vcn_to_lcn(r->mft_rl, vcn + i);

		if (lcn <= 0 || lcn >= r->vol->nr_clusters) {
			free(target);
			goto invalid;
		}
		w64(target + 32 + i * 8, lcn);
	}
	return target;
invalid:
	replay_invalid();
	return NULL;
}

static struct replay_attr *replay_attr_slot(struct ntfsck_replay *r, u32 slot)
{
	struct replay_attr *a;

	for (a = r->attrs; a; a = a->next)
		if (a->slot == slot)
			return a;
	a = ntfs_calloc(sizeof(*a));
	if (a) {
		a->slot = slot;
		a->next = r->attrs;
		r->attrs = a;
	}
	return a;
}

static struct replay_transaction *replay_transaction_slot(struct ntfsck_replay *r,
		u32 slot)
{
	struct replay_transaction *t;

	for (t = r->transactions; t; t = t->next)
		if (t->slot == slot)
			return t;
	t = ntfs_calloc(sizeof(*t));
	if (t) {
		t->slot = slot;
		t->next = r->transactions;
		r->transactions = t;
	}
	return t;
}

static int replay_open_attr(struct ntfsck_replay *r, u32 slot, const u8 *data)
{
	struct replay_attr *a = replay_attr_slot(r, slot);

	if (!a)
		return -1;
	a->index_size = r32(data + (r->checkpoint_version ? 4 : 40));
	a->type = r32(data + (r->checkpoint_version ? 8 : 28));
	memcpy(a->entry, data, r->attr_size);
	free(a->name);
	a->name = NULL;
	a->name_bytes = 0;
	return 0;
}

static int replay_attr_name(struct replay_attr *a, const u8 *data, u32 length)
{
	u8 *name;

	if (!length || (length & 1) || length > 510)
		return replay_invalid();
	name = ntfs_malloc(length);
	if (!name)
		return -1;
	memcpy(name, data, length);
	free(a->name);
	a->name = name;
	a->name_bytes = length;
	return 0;
}

static int replay_names(struct ntfsck_replay *r, const u8 *data, u32 length)
{
	u32 off = 0;

	while (off < length) {
		u16 slot, bytes;
		struct replay_attr *a;

		/* Some producers pad the names dump with zeroes to an eight-byte boundary. */
		if (!data[off]) {
			u32 i;

			for (i = off; i < length && !data[i]; i++)
				;
			if (i == length)
				break;
		}
		if (length - off < 4)
			return replay_invalid();
		slot = r16(data + off);
		bytes = r16(data + off + 2);
		off += 4;
		if (!slot || length - off < 2 || bytes > length - off - 2 ||
				r16(data + off + bytes))
			return replay_invalid();
		a = replay_attr_slot(r, slot);
		if (!a || replay_attr_name(a, data + off, bytes))
			return -1;
		off += bytes + 2;
	}
	return 0;
}

static struct replay_dirty *replay_find_dirty(struct ntfsck_replay *r,
		u32 slot, u64 vcn, u32 count)
{
	struct replay_dirty *d;

	for (d = r->dirty; d; d = d->next)
		if (d->slot == slot && vcn >= d->vcn &&
				vcn - d->vcn < d->count && count <= d->count - (vcn - d->vcn))
			return d;
	return NULL;
}

static int replay_new_dirty(struct ntfsck_replay *r, u32 slot, u64 vcn,
		u64 oldest, u32 count, const u8 *lcns)
{
	struct replay_dirty *d;
	u32 i;

	if (vcn > UINT64_MAX - count)
		return replay_invalid();
	d = ntfs_malloc(sizeof(*d) + (size_t)count * sizeof(*d->lcns));
	if (!d)
		return -1;
	*d = (struct replay_dirty) {
		.slot = slot, .count = count,
		.vcn = vcn, .oldest = oldest,
	};
	for (i = 0; i < count; i++)
		d->lcns[i] = r64(lcns + i * 8);
	*r->dirty_tail = d;
	r->dirty_tail = &d->next;
	return 0;
}

static int replay_add_dirty(struct ntfsck_replay *r, u32 slot, u64 vcn,
		u64 oldest, u32 count, const u8 *lcns, BOOL initializing)
{
	struct replay_dirty *d;
	u32 i;

	if (!count)
		return 0;
	if (vcn > UINT64_MAX - count)
		return replay_invalid();
	d = replay_find_dirty(r, slot, vcn, count);
	if (!d)
		return replay_new_dirty(r, slot, vcn, oldest, count, lcns);
	for (i = 0; i < count; i++)
		d->lcns[vcn - d->vcn + i] = r64(lcns + i * 8);
	if (initializing && oldest < d->oldest)
		d->oldest = oldest;
	return 0;
}

static int replay_validate_record(struct ntfsck_replay *r, struct replay_record *rec)
{
	const u8 *p = rec->data;
	u32 i, minimum;
	u16 redo, undo, offset, length;

	if (rec->type == 2)
		return rec->length < 64 ? replay_invalid() : 0;
	if (rec->type != 1 || rec->length < 40 || rec->transaction < 24 ||
			(rec->transaction - 24) % 40)
		return replay_invalid();
	redo = r16(p);
	undo = r16(p + 2);
	minimum = 32 + r16(p + 14) * 8;
	if (minimum == 32)
		minimum += 8;
	if (redo > ZeroEndOfFileRecord || undo > ZeroEndOfFileRecord ||
			minimum > rec->length ||
			(r16(p + 12) && (r16(p + 12) < 24 ||
			 (r16(p + 12) - 24) % r->attr_size)))
		return replay_invalid();
	if (!r16(p + 12) &&
			((redo >= InitializeFileRecordSegment &&
			  redo <= ClearBitsInNonresidentBitMap &&
			  redo != DeleteDirtyClusters) || redo >= UpdateRecordDataRoot ||
			 (undo >= InitializeFileRecordSegment &&
			  undo <= ClearBitsInNonresidentBitMap &&
			  undo != DeleteDirtyClusters) || undo >= UpdateRecordDataRoot ||
			 redo == OpenNonresidentAttribute))
		return replay_invalid();
	for (i = 0; i < r16(p + 14); i++)
		if (r64(p + 32 + i * 8) >= (u64)r->vol->nr_clusters)
			return replay_invalid();
	for (i = 0; i < 2; i++) {
		offset = r16(p + 4 + i * 4);
		length = r16(p + 6 + i * 4);
		if (offset > rec->length || (offset & 7))
			return replay_invalid();
		if ((i ? undo <= CompensationLogRecord : redo == ZeroEndOfFileRecord) ||
				(rec->flags & (2U << i)))
			continue;
		if ((length && offset < minimum) || length > rec->length - offset)
			return replay_invalid();
	}
	return 0;
}

static int replay_table(struct ntfsck_replay *r, u16 op, const u8 *data, u32 length)
{
	u32 size, count, off;

	if (op == AttributeNamesDump)
		return replay_names(r, data, length);
	if (length < 24)
		return replay_invalid();
	size = r16(data);
	count = r16(data + 2);
	if (size < 4 || (size & 3) || (u64)size * count + 24 != length)
		return replay_invalid();
	if ((op == OpenAttributeTableDump && size < r->attr_size) ||
			(op == DirtyPageTableDump && size < (r->checkpoint_version ? 32U : 36U)) ||
			(op == TransactionTableDump && size < 40))
		return replay_invalid();
	for (off = 24; off < length; off += size) {
		const u8 *p = data + off;

		if (r32(p) != REPLAY_ALLOCATED)
			continue;
		if (op == OpenAttributeTableDump) {
			if (size < r->attr_size || replay_open_attr(r, off, p))
				return replay_invalid();
		} else if (op == DirtyPageTableDump) {
			u32 header = r->checkpoint_version ? 32 : 36;
			u32 n = r32(p + 12);
			u32 vcn_offset = r->checkpoint_version ? 16 : 20;

			if (size < header || n > (size - header) / 8 ||
					replay_new_dirty(r, r32(p + 4), r64(p + vcn_offset),
						r64(p + vcn_offset + 8), n, p + header))
				return replay_invalid();
		} else if (op == TransactionTableDump) {
			struct replay_transaction *t;

			if (size < 40 || p[4] > 3)
				return replay_invalid();
			t = replay_transaction_slot(r, off);
			if (!t)
				return -1;
			t->state = p[4];
			t->first_lsn = r64(p + 8);
			t->undo_next = r64(p + 24);
		}
	}
	return 0;
}

static int replay_load_dump(struct ntfsck_replay *r, u64 lsn, u32 length, u16 op)
{
	struct replay_record *rec;
	u32 offset;
	int ret;

	if (!lsn && !length)
		return 0;
	if (!lsn || !length)
		return replay_invalid();
	rec = replay_read_record(r, lsn, NULL);
	if (!rec)
		return -1;
	if (replay_validate_record(r, rec) || rec->type != 1) {
		free(rec);
		return replay_invalid();
	}
	offset = r16(rec->data + 4);
	ret = r16(rec->data) != op || offset > rec->length ||
		length > rec->length - offset ||
		rec->length - offset - length > 7 ||
		r16(rec->data + 6) != min(length, 65535U);
	if (!ret)
		ret = replay_table(r, op, rec->data + offset, length);
	free(rec);
	return ret ? replay_invalid() : 0;
}

/* ntfs-journal-work uses backwards-compatible Noop payloads as batch fences. */
static int replay_batch(struct replay_record *rec, const u8 **batch)
{
	const u8 *p = rec->data, *b;
	u32 offset, length, bits = 0, i;
	u16 version;

	*batch = NULL;
	if (rec->type != 1 || rec->length < 40 || r16(p) || r16(p + 2) ||
			r16(p + 12) || r16(p + 14) || r16(p + 10))
		return 0;
	offset = r16(p + 4);
	length = r16(p + 6);
	if (length < 56 || offset > rec->length || length > rec->length - offset)
		return 0;
	b = p + offset;
	if (r64(b) != REPLAY_BATCH_MAGIC)
		return 0;
	if (r64(b + 8) != ~REPLAY_BATCH_MAGIC || !r64(b + 16) ||
			r64(b + 24) != ~r64(b + 16) || !r64(b + 32) ||
			!r64(b + 40) || !r32(b + 48))
		return -1;
	version = r16(b + 52);
	if (version == 1) {
		if (length != 56 || r16(b + 54))
			return -1;
	} else if (version == 2) {
		if (length != 64 + REPLAY_TRANSACTION_BYTES ||
				(r16(b + 54) & ~1U) ||
				r16(b + 56) != REPLAY_TRANSACTION_BYTES ||
				r16(b + 58) != REPLAY_TRANSACTION_SLOTS)
			return -1;
		for (i = 0; i < REPLAY_TRANSACTION_BYTES * 8; i++)
			if (b[64 + i / 8] & (1U << (i & 7))) {
				if (i >= REPLAY_TRANSACTION_SLOTS)
					return -1;
				bits++;
			}
		if (bits != r32(b + 60))
			return -1;
	} else
		return -1;
	*batch = b;
	return 1;
}

static BOOL replay_needs_filename(const u8 *log, u16 op)
{
	return op == SetNewAttributeSizes ||
		(op == UpdateResidentValue && r16(log + 6) != r16(log + 10));
}

static int replay_note_filename(struct ntfsck_replay *r, const u8 *log)
{
	struct replay_filename *f;
	u64 vcn = r64(log + 24), pos, number;

	if (vcn > ((u64)INT64_MAX >> r->vol->cluster_size_bits))
		return replay_invalid();
	pos = vcn << r->vol->cluster_size_bits;
	if (((u64)r16(log + 20) << 9) > INT64_MAX - pos)
		return replay_invalid();
	number = (pos + ((u64)r16(log + 20) << 9)) / r->vol->mft_record_size;
	if (number < FILE_first_user)
		return 0;
	for (f = r->filenames; f; f = f->next)
		if (f->mft_no == number)
			return 0;
	f = ntfs_malloc(sizeof(*f));
	if (!f)
		return -1;
	*f = (struct replay_filename) { .next = r->filenames, .mft_no = number };
	r->filenames = f;
	return 0;
}

static int replay_prepass(struct ntfsck_replay *r, struct replay_record *rec)
{
	const u8 *p = rec->data, *data;
	u16 op = r16(p), count = r16(p + 14), slot = r16(p + 12);
	u16 length = r16(p + 6);
	struct replay_transaction *t;
	struct replay_dirty *d;
	struct replay_attr *a;
	const u8 *batch;
	u32 i, j;

	if (rec->type != 1 || (op >= OpenAttributeTableDump && op <= TransactionTableDump))
		return 0;
	if (replay_batch(rec, &batch) > 0) {
		for (t = r->transactions; t; t = t->next) {
			u32 index = (t->slot - 24) / 40;

			if (r16(batch + 52) == 1 ? t->state == 3 :
					(index < REPLAY_TRANSACTION_SLOTS &&
					 (batch[64 + index / 8] & (1U << (index & 7)))))
				t->state = 0;
		}
		return 0;
	}
	if (count && replay_needs_filename(p, op) && replay_note_filename(r, p))
		return -1;
	t = replay_transaction_slot(r, rec->transaction);
	if (!t)
		return -1;
	if (!t->state) {
		t->state = 1;
		t->first_lsn = rec->lsn;
	}
	t->undo_next = rec->lsn;
	if (r16(p + 2) == CompensationLogRecord || op == EndTopLevelAction)
		t->undo_next = rec->undo_next;
	if (op == PrepareTransaction)
		t->state = 2;
	if (op == CommitTransaction)
		t->state = 3;
	if (op == ForgetTransaction)
		t->state = 0;
	data = p + r16(p + 4);
	if ((op == OpenNonresidentAttribute || op == DeleteDirtyClusters) &&
			length > rec->length - r16(p + 4))
		return replay_invalid();
	if (op == OpenNonresidentAttribute) {
		u32 name_off = r16(p + 8), name_len = r16(p + 10);

		if (length < r->attr_size)
			return replay_invalid();
		if (replay_open_attr(r, slot, data))
			return -1;
		if (!name_len)
			return 0;
		if (name_off > rec->length || name_len > rec->length - name_off)
			return replay_invalid();
		return replay_attr_name(replay_attr_slot(r, slot), p + name_off, name_len);
	}
	if (op == DeleteDirtyClusters) {
		if (length & 15)
			return replay_invalid();
		for (i = 0; i < length; i += 16) {
			u64 lcn = r64(data + i), n = r64(data + i + 8);

			for (d = r->dirty; d; d = d->next)
				for (j = 0; j < d->count; j++)
					if (d->lcns[j] >= lcn && d->lcns[j] - lcn < n)
						d->lcns[j] = 0;
		}
		return 0;
	}
	if (op == HotFix) {
		d = replay_find_dirty(r, slot, r64(p + 24), count);
		if (d && count && d->lcns[r64(p + 24) - d->vcn])
			d->lcns[r64(p + 24) - d->vcn] = r64(p + 32);
		return 0;
	}
	if (count && ((op >= InitializeFileRecordSegment && op <= ClearBitsInNonresidentBitMap) ||
			op >= UpdateRecordDataRoot)) {
		a = replay_attr_slot(r, slot);
		if (!a)
			return -1;
		return replay_add_dirty(r, slot, r64(p + 24), rec->lsn, count, p + 32,
				op == InitializeFileRecordSegment ||
				(op == UpdateNonresidentValue && r16(p + 2) == Noop &&
				 a->type == 0xa0 && a->index_size && length == a->index_size));
	}
	return 0;
}

static int replay_geometry(struct ntfsck_replay *r, const RESTART_PAGE_HEADER *rp)
{
	const u8 *ra = (const u8 *)rp + le16_to_cpu(rp->restart_area_offset);
	const u8 *client;
	u32 bits = r32(ra + 16), major = le16_to_cpu(rp->major_ver);

	if ((major != 1 && major != 2) ||
			(major == 1 && le16_to_cpu(rp->minor_ver) > 1) ||
			(major == 2 && le16_to_cpu(rp->minor_ver))) {
		errno = EOPNOTSUPP;
		return -1;
	}
	r->page_size = le32_to_cpu(rp->log_page_size);
	r->log_size = r64(ra + 24);
	r->data_offset = r16(ra + 38);
	r->header_size = r16(ra + 36);
	r->first_page = (major == 2 ? 34ULL : 4ULL) * r->page_size;
	r->client = r16(ra + 12);
	if (!replay_power_of_two(r->page_size) || r->page_size < 512 ||
			r->page_size > 65536 || !bits || bits >= 64 ||
			r->log_size > (u64)r->log_na->data_size ||
			r->log_size <= r->first_page || (r->log_size & (r->page_size - 1)) ||
			r->data_offset < 40 || (r->data_offset & 7) ||
			r->header_size < 48 || (r->header_size & 7) ||
			r->data_offset + r->header_size >= r->page_size ||
			r->client >= r16(ra + 8))
		return replay_invalid();
	r->file_bits = 64 - bits;
	r->mask = (1ULL << r->file_bits) - 1;
	client = ra + r16(ra + 22) + r->client * sizeof(LOG_CLIENT_RECORD);
	r->client_sequence = r16(client + 20);
	r->current = r64(ra);
	r->oldest = r64(client);
	r->checkpoint = r64(client + 8);
	if (!r->checkpoint || r->checkpoint > r->current || r->oldest > r->current)
		return replay_invalid();
	return replay_load_tails(r, major);
}

/* Discover complete records and honor the writer's durable batch boundary. */
static int replay_discover_tail(struct ntfsck_replay *r)
{
	u64 saved = r->current, committed = saved, last = 0, next, lsn, steps = 0;
	BOOL marker_protocol = FALSE;

	r->current = UINT64_MAX;
	for (lsn = r->checkpoint; lsn; lsn = next) {
		struct replay_record *rec;
		const u8 *batch;
		int marker;

		if (++steps > (r->log_size - r->first_page) / 8)
			goto invalid;
		rec = replay_read_record(r, lsn, &next);
		if (!rec) {
			if (!last || lsn <= saved ||
					(errno != EINVAL && errno != EOPNOTSUPP))
				goto fail;
			break;
		}
		marker = replay_batch(rec, &batch);
		if (marker) {
			marker_protocol = TRUE;
			if (marker < 0 || !last || r64(batch + 40) != last ||
					r64(batch + 32) > last ||
					((r16(batch + 54) & 1) && lsn > saved)) {
				free(rec);
				if (lsn <= saved)
					goto invalid;
				break;
			}
			if (lsn > committed)
				committed = lsn;
		}
		last = lsn;
		free(rec);
	}
	r->current = marker_protocol ? committed : max(saved, last);
	return 0;
invalid:
	replay_invalid();
fail:
	r->current = saved;
	return -1;
}

static int replay_restart_durable(struct ntfsck_replay *r)
{
	struct replay_record *cp, *last;
	BOOL valid;

	cp = replay_read_record(r, r->checkpoint, NULL);
	if (!cp)
		return errno == EINVAL || errno == EOPNOTSUPP ? 0 : -1;
	last = replay_read_record(r, r->current, NULL);
	if (!last) {
		free(cp);
		return errno == EINVAL || errno == EOPNOTSUPP ? 0 : -1;
	}
	valid = cp && cp->length >= 64 && last;
	free(cp);
	free(last);
	return valid;
}

/* A newer restart page may name a checkpoint that never reached the device. */
static int replay_choose_restart(struct ntfsck_replay *r, RESTART_PAGE_HEADER **rp)
{
	u32 i, j, size = le32_to_cpu((*rp)->system_page_size);
	u64 newest;
	BOOL geometry_valid;
	int durable;

	geometry_valid = !replay_geometry(r, *rp);
	if (!geometry_valid && ntfs_is_rstr_record((*rp)->magic))
		return -1;
	if (geometry_valid && ntfs_is_rstr_record((*rp)->magic)) {
		durable = replay_restart_durable(r);
		if (durable)
			return durable > 0 ? 0 : -1;
	}
	newest = r64((u8 *)*rp + le16_to_cpu((*rp)->restart_area_offset));
	for (i = 0; i < 2; i++) {
		u8 *page = ntfs_malloc(size);
		u8 *ra;
		u32 offset, clients, client_offset;

		if (!page)
			return -1;
		if (ntfs_attr_pread(r->log_na, (u64)i * size, size, page) != size ||
				memcmp(page, "RSTR", 4) || r32(page + 16) != size ||
				ntfs_mst_post_read_fixup((NTFS_RECORD *)page, size))
			goto next;
		offset = r16(page + 24);
		if (offset < 32 || (offset & 7) || offset > size - 48)
			goto next;
		ra = page + offset;
		clients = r16(ra + 8);
		client_offset = r16(ra + 22);
		if (client_offset < 48 || client_offset > size - offset ||
				clients > (size - offset - client_offset) /
					sizeof(LOG_CLIENT_RECORD) ||
				r64(ra) > newest)
			goto next;
		for (j = 0; j < r->tail_count; j++)
			free(r->tails[j].page);
		r->tail_count = 0;
		if (r16(ra + 12) == LOGFILE_NO_CLIENT_CPU || (r16(ra + 14) & 2)) {
			free(*rp);
			*rp = (RESTART_PAGE_HEADER *)page;
			return 0;
		}
		if (!replay_geometry(r, (RESTART_PAGE_HEADER *)page)) {
			durable = replay_restart_durable(r);
			if (durable < 0) {
				free(page);
				return -1;
			}
			if (!durable)
				goto next;
			if (r64(ra) < newest)
				ntfs_log_warning("Using the older durable LogFile restart page.\n");
			else
				ntfs_log_warning("Using the alternate valid LogFile restart page.\n");
			free(*rp);
			*rp = (RESTART_PAGE_HEADER *)page;
			return 0;
		}
next:
		free(page);
	}
	return replay_invalid();
}

static BOOL replay_dirty_live(const struct replay_dirty *d)
{
	u32 i;

	for (i = 0; i < d->count; i++)
		if (d->lcns[i])
			return TRUE;
	return FALSE;
}

static int replay_analyze(struct ntfsck_replay *r)
{
	struct replay_record *cp, *rec, **tail = &r->records;
	u64 start, next, lsn, steps = 0;
	u32 i;
	int ret = -1;

	if (replay_discover_tail(r))
		return -1;
	cp = replay_read_record(r, r->checkpoint, NULL);
	if (!cp)
		return -1;
	if (cp->length < 64 || (cp->type != 1 && cp->type != 2))
		goto out;
	r->checkpoint_version = r32(cp->data);
	if (r->checkpoint_version > 1) {
		errno = EOPNOTSUPP;
		goto out;
	}
	r->attr_size = r->checkpoint_version ? 40 : 44;
	start = r64(cp->data + 8);
	if (!start)
		start = r->checkpoint;
	for (i = 0; i < 4; i++)
		if (replay_load_dump(r, r64(cp->data + 16 + i * 8),
				r32(cp->data + 48 + i * 4), OpenAttributeTableDump + i))
			goto out;
	/* Rebuild current state before choosing the history that still needs redo. */
	for (lsn = start; lsn; lsn = next) {
		if (++steps > (r->log_size - r->first_page) / 8) {
			replay_invalid();
			goto out;
		}
		rec = replay_read_record(r, lsn, &next);
		if (!rec)
			goto out;
		if (rec->lsn == r->current)
			r->last_data_length = rec->length;
		if (replay_validate_record(r, rec) || replay_prepass(r, rec)) {
			free(rec);
			goto out;
		}
		free(rec);
	}
	/* A transaction's initialization may precede its last undo record. */
	for (struct replay_dirty *d = r->dirty; d; d = d->next)
		if (replay_dirty_live(d) && d->oldest && d->oldest < start)
			start = d->oldest;
	for (struct replay_transaction *t = r->transactions; t; t = t->next)
		if (t->state && t->first_lsn && t->first_lsn < start)
			start = t->first_lsn;
	steps = 0;
	for (lsn = start; lsn; lsn = next) {
		if (++steps > (r->log_size - r->first_page) / 8)
			goto out;
		rec = replay_read_record(r, lsn, &next);
		if (!rec)
			goto out;
		*tail = rec;
		tail = &rec->next;
		if (rec->lsn == r->current)
			r->last_data_length = rec->length;
		if (replay_validate_record(r, rec))
			goto out;
	}
	ret = 0;
out:
	free(cp);
	return ret;
}

static u8 *replay_mft_attr(u8 *mft, u32 size, u32 offset, BOOL end_allowed)
{
	u32 pos = r16(mft + 20), used = r32(mft + 24), length;

	if (used > size || pos < 48 || pos > used)
		return NULL;
	while (pos <= used && used - pos >= 8) {
		u8 *a = mft + pos;

		if (r32(a) == 0xffffffff)
			return end_allowed && offset == pos ? a : NULL;
		length = r32(a + 4);
		if (length < 24 || (length & 7) || length > used - pos)
			return NULL;
		if (pos == offset)
			return a;
		pos += length;
	}
	return NULL;
}

static int replay_resize_attr(u8 *mft, u32 size, u8 *a, u32 length)
{
	u32 used = r32(mft + 24), old = r32(a + 4), offset = a - mft;

	length = (length + 7) & ~7U;
	if (used > size || offset > used || old > used - offset ||
			length < 24 || length > size - (used - old))
		return replay_invalid();
	memmove(a + length, a + old, used - offset - old);
	if (length > old)
		memset(a + old, 0, length - old);
	w32(mft + 24, used - old + length);
	w32(a + 4, length);
	return 0;
}

static int replay_highest_vcn(u8 *a)
{
	u32 offset = r16(a + 32), end = r32(a + 4);
	u64 vcn = r64(a + 16), length;
	u32 n, d, i;

	if (vcn > INT64_MAX)
		return replay_invalid();
	while (offset < end && a[offset]) {
		n = a[offset] & 15;
		d = a[offset++] >> 4;
		if (!n || n > 8 || d > 8 || n + d > end - offset)
			return replay_invalid();
		length = 0;
		for (i = 0; i < n; i++)
			length |= (u64)a[offset + i] << (i * 8);
		if (!length || length > INT64_MAX - vcn)
			return replay_invalid();
		vcn += length;
		offset += n + d;
	}
	if (offset == end)
		return replay_invalid();
	w64(a + 24, vcn - 1);
	return 0;
}

/* Root and allocation indexes use the same entry operations and offset rules. */
static int replay_index(u8 *buffer, u32 capacity, u32 base, u32 offset,
		u16 op, const u8 *data, u32 length, BOOL root)
{
	u8 *h = buffer + base, *ie;
	u32 used, total, first, end, entry_length, payload;

	if (base > capacity || capacity - base < 16)
		return replay_invalid();
	used = r32(h + 4);
	total = r32(h + 8);
	first = r32(h);
	if (used < 16 || used > total || total > capacity - base ||
			first < 16 || first > used || offset < base + first ||
			offset > base + (op == WriteEndOfIndexBuffer ? total : used))
		return replay_invalid();
	end = base + used;
	ie = buffer + offset;
	if (op == AddIndexEntryRoot || op == AddIndexEntryAllocation) {
		if (length < 16 || r16(data + 8) < 16 || r16(data + 8) > length ||
				(r16(data + 8) & 7))
			return replay_invalid();
		entry_length = r16(data + 8);
		if (entry_length > capacity - end || (!root && entry_length > total - used))
			return replay_invalid();
		memmove(ie + entry_length, ie, end - offset);
		memcpy(ie, data, entry_length);
		w32(h + 4, used + entry_length);
		if (root)
			w32(h + 8, total + entry_length);
		return 0;
	}
	if (op == WriteEndOfIndexBuffer) {
		if (length < 16 || length > base + total - offset)
			return replay_invalid();
		memcpy(ie, data, length);
		w32(h + 4, offset + length - base);
		return 0;
	}
	if (end - offset < 16 || r16(ie + 8) < 16 || r16(ie + 8) > end - offset)
		return replay_invalid();
	entry_length = r16(ie + 8);
	switch (op) {
	case DeleteIndexEntryRoot:
	case DeleteIndexEntryAllocation:
		memmove(ie, ie + entry_length, end - offset - entry_length);
		w32(h + 4, used - entry_length);
		if (root)
			w32(h + 8, total - entry_length);
		return 0;
	case SetIndexEntryVcnRoot:
	case SetIndexEntryVcnAllocation:
		if (length != 8 || !(r16(ie + 12) & 1) || entry_length < 24)
			return replay_invalid();
		memcpy(ie + entry_length - 8, data, 8);
		return 0;
	case UpdateFileNameRoot:
	case UpdateFileNameAllocation:
		/* The FILE_NAME duplicated-information block follows parent_directory. */
		if (length != 56 || entry_length < 16 + 8 + length)
			return replay_invalid();
		memcpy(ie + 24, data, length);
		return 0;
	case UpdateRecordDataRoot:
	case UpdateRecordDataAllocation:
	case UpdateRelativeDataIndex:
	case UpdateRelativeDataAllocation:
		payload = r16(ie);
		if (!payload || payload > entry_length || length > entry_length - payload)
			return replay_invalid();
		if (op == UpdateRelativeDataIndex || op == UpdateRelativeDataAllocation) {
			if (length == 4)
				w32(ie + payload, r32(ie + payload) + r32(data));
			else if (length == 8)
				w64(ie + payload, r64(ie + payload) + r64(data));
			else
				return replay_invalid();
		} else
			memcpy(ie + payload, data, length);
		return 0;
	default:
		return replay_invalid();
	}
}

static BOOL replay_root_op(u16 op)
{
	return op == AddIndexEntryRoot || op == DeleteIndexEntryRoot ||
		op == SetIndexEntryVcnRoot || op == UpdateFileNameRoot ||
		op == UpdateRecordDataRoot || op == UpdateRelativeDataIndex;
}

static int replay_note_image(struct ntfsck_replay *r, const u8 *log,
		u32 offset, u32 size, BOOL mft)
{
	struct replay_image *image;
	u32 header = 32 + r16(log + 14) * 8;
	u64 pos = ((u64)r16(log + 20) << 9) + offset;
	u64 physical = (r64(log + 32 + (pos >> r->vol->cluster_size_bits) * 8) <<
			r->vol->cluster_size_bits) + (pos & (r->vol->cluster_size - 1));

	for (image = r->images; image; image = image->next)
		if (image->physical == physical && image->size == size && image->mft == mft)
			return 0;
	image = ntfs_malloc(sizeof(*image) + header);
	if (!image)
		return -1;
	*image = (struct replay_image) {
		.next = r->images, .physical = physical, .size = size, .offset = offset,
		.mft = mft,
	};
	memcpy(image->log, log, header);
	r->images = image;
	return 0;
}

/* A historical prefix must not drop later MFT growth needed by redo or undo. */
static int replay_refresh_mft(struct ntfsck_replay *r, const u8 *a)
{
	u64 highest = r64(a + 24), end;
	u32 length = r32(a + 4), head = 0, old_count = 0, used, i;
	runlist_element *source, *merged = NULL;
	u8 *copy;
	int ret = -1;

	if (!a[8] || length < 64 || r64(a + 16) ||
			highest >= ((u64)INT64_MAX >> r->vol->cluster_size_bits))
		return replay_invalid();
	copy = ntfs_malloc(length);
	if (!copy)
		return -1;
	memcpy(copy, a, length);
	w64(copy + 40, max(r64(a + 40), (highest + 1) << r->vol->cluster_size_bits));
	source = ntfs_mapping_pairs_decompress(r->vol, (ATTR_RECORD *)copy, NULL);
	free(copy);
	if (!source)
		return -1;
	end = 0;
	while (source[head].length && source[head].lcn >= 0) {
		if ((u64)source[head].vcn != end || source[head].length < 0 ||
				(u64)source[head].length > highest + 1 - end)
			goto invalid;
		end += source[head++].length;
		if (end == highest + 1)
			break;
	}
	if (!head || end != highest + 1)
		goto invalid;
	while (r->mft_rl[old_count].length)
		old_count++;
	merged = ntfs_malloc((size_t)(head + old_count + 1) * sizeof(*merged));
	if (!merged)
		goto out;
	memcpy(merged, source, head * sizeof(*merged));
	used = head;
	for (i = 0; i < old_count; i++) {
		runlist_element tail = r->mft_rl[i];
		u64 stop = tail.vcn + tail.length;

		if (stop <= end)
			continue;
		if ((u64)tail.vcn > end || tail.lcn < 0)
			goto invalid;
		tail.lcn += end - tail.vcn;
		tail.length = stop - end;
		tail.vcn = end;
		merged[used++] = tail;
		end = stop;
	}
	merged[used] = (runlist_element) { .vcn = end, .lcn = LCN_ENOENT };
	free(r->mft_rl);
	r->mft_rl = merged;
	merged = NULL;
	ret = 0;
	goto out;
invalid:
	replay_invalid();
out:
	free(merged);
	free(source);
	return ret;
}

static u8 *replay_mft_data(u8 *mft, u32 size)
{
	u32 offset = r16(mft + 20);
	u8 *a;

	while ((a = replay_mft_attr(mft, size, offset, FALSE))) {
		if (r32(a) == 0x80 && !a[9])
			return a;
		offset += r32(a + 4);
	}
	return NULL;
}

static int replay_mft(struct ntfsck_replay *r, const u8 *log, u16 op,
		const u8 *data, u32 length, u64 lsn)
{
	u32 size = r->vol->mft_record_size, used, offset = r16(log + 16);
	u32 attr_offset = r16(log + 18), attr_length, new_length, base;
	u8 *mft = ntfs_malloc(size), *a = NULL;
	u8 *target = replay_mft_target(r, log);
	BOOL valid;
	int ret = -1;

	if (!mft || !target)
		goto out;
	log = target;
	if (replay_lcns(r, log, 0, mft, size, FALSE))
		goto out;
	valid = !memcmp(mft, "FILE", 4) &&
		!ntfs_mst_post_read_fixup((NTFS_RECORD *)mft, size);
	if (!valid && op == DeallocateFileRecordSegment) {
		ret = 0;
		goto out;
	}
	if (!valid && op != InitializeFileRecordSegment)
		goto out;
	if (valid && lsn && r64(mft + 8) >= lsn && r64(mft + 8) <= r->current) {
		ret = 0;
		goto out;
	}
	used = r32(mft + 24);
	if (op != InitializeFileRecordSegment && (used > size || used < 48))
		goto out;
	if (offset > size || attr_offset > size - offset)
		goto out;
	switch (op) {
	case InitializeFileRecordSegment:
		if (!data || length > size - offset)
			goto out;
		memcpy(mft + offset, data, length);
		break;
	case DeallocateFileRecordSegment:
		if (r16(mft + 22) & 1) {
			u16 sequence = r16(mft + 16) + 1;

			w16(mft + 22, r16(mft + 22) & ~1U);
			w16(mft + 16, sequence ? sequence : 1);
		}
		break;
	case WriteEndOfFileRecordSegment:
		if (!data || length > size - offset ||
				!replay_mft_attr(mft, size, offset, TRUE))
			goto out;
		memcpy(mft + offset, data, length);
		w32(mft + 24, (offset + length + 7) & ~7U);
		break;
	case CreateAttribute:
		if (!data || length < 24 || !replay_mft_attr(mft, size, offset, TRUE))
			goto out;
		attr_length = r32(data + 4);
		if (attr_length < 24 || (attr_length & 7) ||
				attr_length > length || attr_length > size - used)
			goto out;
		memmove(mft + offset + attr_length, mft + offset, used - offset);
		memcpy(mft + offset, data, attr_length);
		w32(mft + 24, used + attr_length);
		if (r16(mft + 40) <= r16(data + 14))
			w16(mft + 40, r16(data + 14) + 1);
		if (!data[8] && (data[22] & RESIDENT_ATTR_IS_INDEXED))
			w16(mft + 18, r16(mft + 18) + 1);
		break;
	case ZeroEndOfFileRecord:
		if (length != size - offset - attr_offset)
			goto out;
		memset(mft + offset + attr_offset, 0, length);
		break;
	default:
		a = replay_mft_attr(mft, size, offset, FALSE);
		if (!a) {
			if (op == DeleteAttribute)
				ret = 0;
			goto out;
		}
		attr_length = r32(a + 4);
		if (op == DeleteAttribute) {
			if (!a[8] && (a[22] & RESIDENT_ATTR_IS_INDEXED))
				w16(mft + 18, r16(mft + 18) - 1);
			memmove(a, a + attr_length, used - offset - attr_length);
			w32(mft + 24, used - attr_length);
		} else if (op == UpdateResidentValue) {
			if (a[8] || attr_offset < r16(a + 20))
				goto out;
			if (r16(log + 6) != r16(log + 10)) {
				if (replay_resize_attr(mft, size, a, attr_offset + length))
					goto out;
				w32(a + 16, attr_offset + length - r16(a + 20));
			} else if (attr_offset > attr_length || length > attr_length - attr_offset)
				goto out;
			if (data)
				memcpy(a + attr_offset, data, length);
			else
				memset(a + attr_offset, 0, length);
		} else if (op == SetNewAttributeSizes) {
			if (!a[8] || attr_length < 64 || !data || (length != 24 && length != 32) ||
					r64(data) > INT64_MAX || r64(data + 16) > INT64_MAX ||
					r64(data + 8) > r64(data + 16) ||
					(length == 32 &&
					 (r16(a + 32) < 72 || r64(data + 24) > INT64_MAX)))
				goto out;
			/* The log stores alloc/valid/data; attributes store alloc/data/valid. */
			w64(a + 40, r64(data));
			w64(a + 48, r64(data + 16));
			w64(a + 56, r64(data + 8));
			if (length == 32)
				w64(a + 64, r64(data + 24));
		} else if (op == UpdateMappingPairs) {
			if (!a[8] || attr_length < 64 || !data ||
					attr_offset < r16(a + 32) || attr_offset > attr_length ||
					replay_resize_attr(mft, size, a, attr_offset + length))
				goto out;
			memcpy(a + attr_offset, data, length);
			if (replay_highest_vcn(a))
				goto out;
		} else if (replay_root_op(op)) {
			int delta = 0;

			if (a[8] || r32(a) != 0x90 || r16(a + 20) > attr_length ||
					r32(a + 16) > attr_length - r16(a + 20) || r32(a + 16) < 32)
				goto out;
			base = r16(a + 20) + 16;
			if (op == AddIndexEntryRoot) {
				if (!data || length < 16)
					goto out;
				delta = r16(data + 8);
				if (replay_resize_attr(mft, size, a, attr_length + delta))
					goto out;
			} else if (op == DeleteIndexEntryRoot) {
				if (attr_offset > attr_length || attr_length - attr_offset < 16)
					goto out;
				delta = -(int)r16(a + attr_offset + 8);
			}
			new_length = r32(a + 4);
			if (replay_index(a, new_length, base, attr_offset, op, data, length, TRUE))
				goto out;
			w32(a + 16, r32(a + 16) + delta);
			if (delta < 0 && replay_resize_attr(mft, size, a, attr_length + delta))
				goto out;
		} else
			goto out;
	}
	if (memcmp(mft, "FILE", 4) || r32(mft + 24) > size)
		goto out;
	if (!r64(log + 24) && !r16(log + 20) &&
			(op == InitializeFileRecordSegment || op == UpdateMappingPairs)) {
		a = replay_mft_data(mft, size);
		if (!a || replay_refresh_mft(r, a))
			goto out;
	}
	if (lsn)
		w64(mft + 8, lsn);
	if (ntfs_mst_pre_write_fixup((NTFS_RECORD *)mft, size))
		goto out;
	ret = replay_lcns(r, log, 0, mft, size, TRUE);
	if (!ret)
		ret = replay_note_image(r, log, 0, size, TRUE);
out:
	free(target);
	free(mft);
	return ret ? replay_invalid() : 0;
}

static int replay_allocation(struct ntfsck_replay *r, const u8 *log,
		struct replay_attr *a, u16 op, const u8 *data, u32 length, u64 lsn)
{
	u32 size, offset = r16(log + 16);
	u8 *buffer;
	int ret = -1;
	BOOL full_image;

	if (!a || !replay_power_of_two(a->index_size) || a->index_size < 512 ||
			a->index_size > 65536)
		return replay_invalid();
	size = a->index_size;
	buffer = ntfs_malloc(size);
	if (!buffer)
		return -1;
	if (replay_lcns(r, log, offset, buffer, size, FALSE))
		goto out;
	/* New indexes log the complete used area, leaving uninitialized slack out. */
	full_image = op == UpdateNonresidentValue && data && length >= 40 &&
		!memcmp(data, "INDX", 4) && r32(data + 32) == size - 24 &&
		r32(data + 28) <= length - 24 && r32(data + 28) >= 16;
	if (memcmp(buffer, "INDX", 4) ||
			ntfs_mst_post_read_fixup((NTFS_RECORD *)buffer, size)) {
		if (!full_image)
			goto out;
		memset(buffer, 0, size);
	} else if (lsn && r64(buffer + 8) >= lsn && r64(buffer + 8) <= r->current) {
		ret = 0;
		goto out;
	}
	if (op == UpdateNonresidentValue) {
		if (!data || length > size)
			goto out;
		memcpy(buffer, data, length);
	} else if (replay_index(buffer, size, 24, r16(log + 18), op, data, length, FALSE))
		goto out;
	if (lsn)
		w64(buffer + 8, lsn);
	if (ntfs_mst_pre_write_fixup((NTFS_RECORD *)buffer, size))
		goto out;
	ret = replay_lcns(r, log, offset, buffer, size, TRUE);
	if (!ret)
		ret = replay_note_image(r, log, offset, size, FALSE);
out:
	free(buffer);
	return ret ? replay_invalid() : 0;
}

static BOOL replay_skip(u16 op)
{
	return op <= CompensationLogRecord || op == DeleteDirtyClusters ||
		(op >= HotFix && op <= TransactionTableDump);
}

static BOOL replay_raw_value(const struct replay_attr *attr)
{
	return attr->type != 0xa0 || !attr->index_size;
}

/* Raw streams can retain live clusters on either side of a deallocated range. */
static int replay_write_live(struct ntfsck_replay *r, const u8 *log,
		const struct replay_dirty *d, u64 pos, void *buffer, u32 length)
{
	u32 size = r->vol->cluster_size;
	u64 start = (u64)r16(log + 20) << 9;
	u8 *data = buffer;

	while (length) {
		u64 index = (start + pos) >> r->vol->cluster_size_bits;
		u32 chunk = min(length, size - ((start + pos) & (size - 1)));

		if ((!d || d->lcns[r64(log + 24) - d->vcn + index]) &&
				replay_lcns(r, log, pos, data, chunk, TRUE))
			return -1;
		pos += chunk;
		data += chunk;
		length -= chunk;
	}
	return 0;
}

static int replay_target_live(struct ntfsck_replay *r, const struct replay_dirty *d,
		const u8 *log, struct replay_attr *a, u16 op, const u8 *data, u32 length)
{
	u64 start = (u64)r16(log + 20) << 9;
	u64 bytes = r->vol->mft_record_size;
	u64 coverage = (u64)r16(log + 14) * r->vol->cluster_size;
	u64 first, last, i;
	BOOL partial = FALSE, live = FALSE;

	if (op == UpdateNonresidentValue && replay_raw_value(a)) {
		if (!a->type)
			return replay_invalid();
		start += r16(log + 16);
		bytes = length;
		partial = TRUE;
	} else if (op == SetBitsInNonresidentBitMap || op == ClearBitsInNonresidentBitMap) {
		if (!data || length < 8)
			return replay_invalid();
		start += r16(log + 16) + r32(data) / 8;
		bytes = ((u64)(r32(data) & 7) + r32(data + 4) + 7) / 8;
		partial = TRUE;
	} else if (op == UpdateNonresidentValue || op == AddIndexEntryAllocation ||
			op == DeleteIndexEntryAllocation || op == WriteEndOfIndexBuffer ||
			op == SetIndexEntryVcnAllocation || op == UpdateFileNameAllocation ||
			op == UpdateRecordDataAllocation || op == UpdateRelativeDataAllocation) {
		start += r16(log + 16);
		bytes = a->index_size;
	}
	if (start > coverage || bytes > coverage - start)
		return replay_invalid();
	if (!bytes)
		return 1;
	first = start >> r->vol->cluster_size_bits;
	last = (start + bytes - 1) >> r->vol->cluster_size_bits;
	for (i = first; i <= last; i++) {
		if (d->lcns[r64(log + 24) - d->vcn + i])
			live = TRUE;
		else if (!partial)
			return 0;
	}
	return live;
}

static int replay_apply(struct ntfsck_replay *r, struct replay_record *rec, BOOL undo)
{
	const u8 *log = rec->data;
	u16 op = r16(log + (undo ? 2 : 0));
	u32 offset = r16(log + (undo ? 8 : 4)), length = r16(log + (undo ? 10 : 6));
	u32 count = r16(log + 14);
	u64 lsn = undo ? 0 : rec->lsn;
	const u8 *data = offset <= rec->length && length <= rec->length - offset ?
		log + offset : NULL;
	struct replay_attr *a;
	struct replay_dirty *d = NULL;
	int ret = 0;

	if (rec->type != 1 || replay_skip(op) || (undo && op == ZeroEndOfFileRecord))
		return 0;
	if (!count)
		return undo ? replay_invalid() : 0;
	if (replay_needs_filename(log, op) && replay_note_filename(r, log))
		return -1;
	a = replay_attr_slot(r, r16(log + 12));
	if (!a)
		return -1;
	if (!undo) {
		int live;

		d = replay_find_dirty(r, r16(log + 12), r64(log + 24), count);
		if (!d || (rec->lsn < d->oldest && op != InitializeFileRecordSegment))
			return 0;
		live = replay_target_live(r, d, log, a, op, data, length);
		if (live <= 0)
			return live;
	}
	if (!data && op != UpdateResidentValue && op != ZeroEndOfFileRecord)
		return undo ? replay_invalid() : 0;
	if (op == UpdateNonresidentValue && replay_raw_value(a)) {
		ret = replay_write_live(r, log, d, r16(log + 16), rec->data + offset, length);
	} else if (op == SetBitsInNonresidentBitMap || op == ClearBitsInNonresidentBitMap) {
		u64 first, bits, bytes, bit;
		u8 *bitmap;

		if (!data || length < 8) {
			ret = replay_invalid();
			goto out;
		}
		first = r32(data);
		bits = r32(data + 4);
		bytes = (first + bits + 7) / 8;
		if (bytes > (u64)count * r->vol->cluster_size || bytes > UINT32_MAX) {
			ret = replay_invalid();
			goto out;
		}
		bitmap = ntfs_malloc(bytes ? bytes : 1);
		if (!bitmap) {
			ret = -1;
			goto out;
		}
		ret = replay_lcns(r, log, r16(log + 16), bitmap, bytes, FALSE);
		if (!ret) {
			for (bit = first; bit < first + bits; bit++) {
				if (op == SetBitsInNonresidentBitMap)
					bitmap[bit / 8] |= 1U << (bit & 7);
				else
					bitmap[bit / 8] &= ~(1U << (bit & 7));
			}
			ret = replay_write_live(r, log, d, r16(log + 16), bitmap, bytes);
		}
		free(bitmap);
	} else if (op == UpdateNonresidentValue || op == AddIndexEntryAllocation ||
			op == DeleteIndexEntryAllocation || op == WriteEndOfIndexBuffer ||
			op == SetIndexEntryVcnAllocation || op == UpdateFileNameAllocation ||
			op == UpdateRecordDataAllocation || op == UpdateRelativeDataAllocation) {
		ret = replay_allocation(r, log, a, op, data, length, lsn);
	} else
		ret = replay_mft(r, log, op, data, length, lsn);
	if (!ret) {
		if (undo)
			r->undo_count++;
		else
			r->redo_count++;
	}
out:
	return ret;
}

static int replay_redo_undo(struct ntfsck_replay *r)
{
	struct replay_record *rec;
	struct replay_transaction *t;
	u64 lsn, steps, next;

	for (rec = r->records; rec; rec = rec->next)
		if (replay_apply(r, rec, FALSE)) {
			ntfs_log_error("LogFile: redo failed at LSN %"PRIu64" (operation 0x%x).\n",
					rec->lsn, r16(rec->data));
			return -1;
		}
	for (t = r->transactions; t; t = t->next) {
		if (t->state != 1)
			continue;
		steps = 0;
		for (lsn = t->undo_next; lsn; lsn = next) {
			if (++steps > (r->log_size - r->first_page) / 8)
				return replay_invalid();
			rec = replay_read_record(r, lsn, NULL);
			if (!rec)
				return -1;
			next = rec->undo_next;
			if (rec->type != 1 || rec->transaction != t->slot ||
					replay_validate_record(r, rec) ||
					(next && (next >= lsn || next < r->oldest)) ||
					replay_apply(r, rec, TRUE)) {
				ntfs_log_error("LogFile: undo failed at LSN %"PRIu64".\n", lsn);
				free(rec);
				return replay_invalid();
			}
			free(rec);
		}
	}
	return 0;
}

/* The final MFT must be readable before any target write or clean restart. */
static int replay_finalize_mft(struct ntfsck_replay *r)
{
	u8 template[32] = { 0 };
	u8 *log = replay_mft_target(r, template);
	u8 *mft = ntfs_malloc(r->vol->mft_record_size), *a;
	u64 allocated, data, valid, end = 0, clusters;
	u32 i;
	int ret = -1;

	if (!log || !mft)
		goto out;
	if (replay_lcns(r, log, 0, mft, r->vol->mft_record_size, FALSE))
		goto out;
	if (memcmp(mft, "FILE", 4) ||
			ntfs_mst_post_read_fixup((NTFS_RECORD *)mft, r->vol->mft_record_size))
		goto invalid;
	a = replay_mft_data(mft, r->vol->mft_record_size);
	if (!a || !a[8] || r32(a + 4) < 64 || r64(a + 16))
		goto invalid;
	allocated = r64(a + 40);
	data = r64(a + 48);
	valid = r64(a + 56);
	if (!allocated || allocated > INT64_MAX || valid > data || data > allocated ||
			(allocated & (r->vol->cluster_size - 1)))
		goto invalid;
	clusters = allocated >> r->vol->cluster_size_bits;
	for (i = 0; r->mft_rl[i].length && end < clusters; i++) {
		const runlist_element *run = r->mft_rl + i;

		if ((u64)run->vcn != end || run->lcn <= 0 || run->length <= 0 ||
				run->lcn >= r->vol->nr_clusters ||
				run->length > r->vol->nr_clusters - run->lcn ||
				(u64)run->length > (u64)r->vol->nr_clusters - end)
			goto invalid;
		end += run->length;
	}
	if (end < clusters)
		goto invalid;
	r->mft_allocated = allocated;
	ret = 0;
	goto out;
invalid:
	replay_invalid();
out:
	free(log);
	free(mft);
	return ret;
}

/* Library lookups see the recovered metadata, without gaining a write path. */
struct replay_view {
	struct ntfsck_replay *replay;
	s64 position;
	int read_error;
};

static int replay_view_open(struct ntfs_device *dev, int flags)
{
	if ((flags & O_ACCMODE) != O_RDONLY) {
		errno = EROFS;
		return -1;
	}
	NDevSetOpen(dev);
	NDevSetReadOnly(dev);
	return 0;
}

static int replay_view_close(struct ntfs_device *dev)
{
	NDevClearOpen(dev);
	return 0;
}

static s64 replay_view_seek(struct ntfs_device *dev, s64 offset, int whence)
{
	struct replay_view *v = dev->d_private;
	struct ntfs_device *source = v->replay->vol->dev;
	s64 position;

	if (whence == SEEK_CUR) {
		if (offset < -v->position || offset > INT64_MAX - v->position)
			return replay_invalid();
		offset += v->position;
		whence = SEEK_SET;
	}
	position = source->d_ops->seek(source, offset, whence);
	if (position >= 0)
		v->position = position;
	return position;
}

static s64 replay_view_pread(struct ntfs_device *dev, void *buf, s64 count, s64 offset)
{
	struct replay_view *v = dev->d_private;
	struct ntfsck_replay *r = v->replay;
	u64 limit = (u64)r->vol->nr_clusters << r->vol->cluster_size_bits;

	if (offset < 0 || count < 0 || count > UINT32_MAX)
		return replay_invalid();
	/* Bootstrap can also read the backup boot sector beyond the cluster area. */
	if ((u64)offset > limit || (u64)count > limit - offset)
		return ntfs_pread(r->vol->dev, offset, count, buf);
	if (replay_io(r, offset, buf, count, FALSE, NULL, 0)) {
		v->read_error = errno ? errno : EIO;
		return -1;
	}
	return count;
}

static s64 replay_view_read(struct ntfs_device *dev, void *buf, s64 count)
{
	struct replay_view *v = dev->d_private;
	s64 got = replay_view_pread(dev, buf, count, v->position);

	if (got > 0)
		v->position += got;
	return got;
}

static int replay_view_sync(struct ntfs_device *dev)
{
	(void)dev;
	return 0;
}

static int replay_view_stat(struct ntfs_device *dev, struct stat *buf)
{
	struct replay_view *v = dev->d_private;
	struct ntfs_device *source = v->replay->vol->dev;

	return source->d_ops->stat(source, buf);
}

static int replay_view_ioctl(struct ntfs_device *dev, unsigned long request, void *arg)
{
	struct replay_view *v = dev->d_private;
	struct ntfs_device *source = v->replay->vol->dev;

	return source->d_ops->ioctl(source, request, arg);
}

static struct ntfs_device_operations replay_view_ops = {
	.open = replay_view_open, .close = replay_view_close,
	.seek = replay_view_seek, .read = replay_view_read, .pread = replay_view_pread,
	.sync = replay_view_sync, .stat = replay_view_stat, .ioctl = replay_view_ioctl,
};

static ntfs_volume *replay_view_volume(struct replay_view *view)
{
	struct ntfs_device *dev;
	ntfs_volume *vol;

	dev = ntfs_device_alloc(view->replay->vol->dev->d_name, 0, &replay_view_ops, view);
	if (!dev)
		return NULL;
	vol = ntfs_volume_startup(dev, NTFS_MNT_RDONLY | NTFS_MNT_FS_NO_REPAIR);
	if (!vol)
		ntfs_device_free(dev);
	return vol;
}

static int replay_copy_logfile(struct ntfsck_replay *r, ntfs_attr *na,
		struct replay_logfile *file)
{
	u64 end = 0;
	u32 count = 0;

	if (!NAttrNonResident(na) ||
			(na->data_flags &
			 (ATTR_IS_COMPRESSED | ATTR_IS_ENCRYPTED | ATTR_IS_SPARSE)) ||
			na->allocated_size <= 0 || na->data_size < 0 || na->initialized_size < 0 ||
			na->initialized_size > na->data_size || na->data_size > na->allocated_size)
		return replay_invalid();
	if (ntfs_attr_map_whole_runlist(na))
		return -1;
	for (; na->rl[count].length; count++) {
		const runlist_element *run = na->rl + count;

		if ((u64)run->vcn != end || run->length < 0 || run->lcn < 0 ||
				run->lcn >= r->vol->nr_clusters ||
				run->length > r->vol->nr_clusters - run->lcn ||
				(u64)run->length > (u64)r->vol->nr_clusters - end)
			return replay_invalid();
		end += run->length;
	}
	if ((u64)na->data_size > (end << r->vol->cluster_size_bits))
		return replay_invalid();
	file->runs = ntfs_malloc((size_t)(count + 1) * sizeof(*file->runs));
	if (!file->runs)
		return -1;
	memcpy(file->runs, na->rl, (size_t)(count + 1) * sizeof(*file->runs));
	file->allocated = na->allocated_size;
	file->data = na->data_size;
	file->initialized = na->initialized_size;
	return 0;
}

/* Shared clusters must have the same logical address in both journal views. */
static int replay_check_logfiles(struct ntfsck_replay *r)
{
	u64 clusters = (r->log_size + r->vol->cluster_size - 1) >> r->vol->cluster_size_bits;
	const runlist_element *a, *b;

	if (r->log_initial.initialized < (s64)r->log_size ||
			r->log_final.initialized < (s64)r->log_size)
		return replay_invalid();
	for (a = r->log_initial.runs; a->length && (u64)a->vcn < clusters; a++) {
		if (ntfs_rl_vcn_to_lcn(r->log_final.runs, a->vcn) != a->lcn)
			r->log_moved = TRUE;
		for (b = r->log_final.runs; b->length && (u64)b->vcn < clusters; b++) {
			u64 start = max(a->lcn, b->lcn);
			u64 a_end = a->lcn + min((u64)a->length, clusters - a->vcn);
			u64 b_end = b->lcn + min((u64)b->length, clusters - b->vcn);

			if (start < min(a_end, b_end) &&
					(u64)a->vcn + start - a->lcn !=
					(u64)b->vcn + start - b->lcn)
				return replay_invalid();
		}
	}
	for (b = r->log_final.runs; b->length && (u64)b->vcn < clusters; b++)
		if (ntfs_rl_vcn_to_lcn(r->log_initial.runs, b->vcn) != b->lcn)
			r->log_moved = TRUE;
	r->log_changed = r->log_moved || r->log_initial.allocated != r->log_final.allocated ||
		r->log_initial.data != r->log_final.data ||
		r->log_initial.initialized != r->log_final.initialized;
	return 0;
}

static int replay_final_logfile(struct ntfsck_replay *r)
{
	struct replay_view view = { .replay = r };
	ntfs_volume *vol = replay_view_volume(&view);
	ntfs_inode *ni = NULL;
	ntfs_attr *na = NULL;
	ntfs_attr_search_ctx *ctx = NULL;
	int ret = -1, error;

	if (!vol)
		return -1;
	ni = ntfs_inode_open(vol, FILE_LogFile);
	if (!ni)
		goto out;
	na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
	if (!na || replay_copy_logfile(r, na, &r->log_final))
		goto out;
	ret = replay_check_logfiles(r);
	if (!ret && r->log_changed) {
		ret = -1;
		ctx = ntfs_attr_get_search_ctx(ni, NULL);
		if (!ctx || ntfs_attr_lookup(AT_DATA, AT_UNNAMED, 0, CASE_SENSITIVE,
				0, NULL, 0, ctx))
			goto out;
		r->log_record = ctx->ntfs_ino->mft_no;
		r->log_attr = (u8 *)ctx->attr - (u8 *)ctx->mrec;
		ret = 0;
	}
out:
	error = view.read_error ? view.read_error : errno;
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (na)
		ntfs_attr_close(na);
	ntfs_inode_close(ni);
	errno = 0;
	if (ntfs_umount(vol, FALSE))
		ret = -1;
	errno = error;
	return view.read_error ? -1 : ret;
}

/* Write through immutable runlists, without a stale inode or size side effects. */
static int replay_logfile_write(struct ntfsck_replay *r, const struct replay_logfile *file,
		u64 offset, u32 length, void *data)
{
	if (offset > r->log_size || length > r->log_size - offset)
		return replay_invalid();
	return ntfs_rl_pwrite(r->vol, file->runs, 0, offset, length, data) == length ? 0 : -1;
}

static int replay_logfile_targets(struct ntfsck_replay *r, const struct replay_logfile *file)
{
	const runlist_element *run;
	u32 i;

	for (run = file->runs; run->length; run++) {
		u64 logical = (u64)run->vcn << r->vol->cluster_size_bits;
		u64 physical = (u64)run->lcn << r->vol->cluster_size_bits;
		u64 bytes;

		if (logical >= r->log_size)
			break;
		bytes = min((u64)run->length << r->vol->cluster_size_bits, r->log_size - logical);
		for (i = 0; i < REPLAY_BUCKETS; i++)
			for (struct replay_sector *s = r->sectors[i]; s; s = s->next)
				if ((u64)s->offset >= physical &&
						(u64)s->offset - physical < bytes &&
						memcmp(s->data, s->original, REPLAY_SECTOR))
					return replay_invalid();
	}
	return 0;
}

/* Derived filename changes need native stream descriptors for retry snapshots. */
static struct replay_attr *replay_filename_attr(struct ntfsck_replay *r,
		u64 mref, u32 type, u32 index_size, const ntfschar *name, u16 name_bytes)
{
	struct replay_attr *a;
	u32 slot;

	for (a = r->attrs; a; a = a->next)
		if (a->type == type && a->index_size == index_size &&
				MREF(r64(a->entry + (r->checkpoint_version ? 16 : 8))) ==
				MREF(mref) &&
				a->name_bytes == name_bytes &&
				(!name_bytes || !memcmp(a->name, name, name_bytes)))
			return a;
	for (slot = 24; slot <= 65535; slot += r->attr_size) {
		for (a = r->attrs; a && a->slot != slot; a = a->next)
			;
		if (!a)
			break;
	}
	if (slot > 65535) {
		errno = ENOSPC;
		return NULL;
	}
	a = replay_attr_slot(r, slot);
	if (!a || (name_bytes && replay_attr_name(a, (const u8 *)name, name_bytes)))
		return NULL;
	a->type = type;
	a->index_size = index_size;
	w32(a->entry, REPLAY_ALLOCATED);
	w32(a->entry + (r->checkpoint_version ? 4 : 40), index_size);
	w32(a->entry + (r->checkpoint_version ? 8 : 28), type);
	w64(a->entry + (r->checkpoint_version ? 16 : 8), mref);
	a->entry[r->checkpoint_version ? 12 : 24] = 1;
	a->entry[r->checkpoint_version ? 13 : 25] = !!name_bytes;
	a->entry[r->checkpoint_version ? 14 : 32] = name_bytes / 2;
	return a;
}

static u8 *replay_logfile_record_target(struct ntfsck_replay *r, u64 number, u16 slot)
{
	u64 pos = number * r->vol->mft_record_size;
	u8 log[32] = { 0 };

	w16(log + 12, slot);
	w16(log + 20, (pos & (r->vol->cluster_size - 1)) / REPLAY_SECTOR);
	w64(log + 24, pos >> r->vol->cluster_size_bits);
	return replay_mft_target(r, log);
}

/* A torn LogFile record can still reach a published checkpoint via its mirror. */
static ntfs_inode *replay_logfile_from_mirror(struct ntfsck_replay *r)
{
	ntfs_inode *ni = NULL;
	ntfs_attr_search_ctx *ctx = NULL;
	u32 size = r->vol->mft_record_size;
	u64 offset = ((u64)r->vol->mftmirr_lcn << r->vol->cluster_size_bits) +
		(u64)FILE_LogFile * size;
	u8 *raw = ntfs_malloc(size), *target = NULL;
	s64 length;

	if (!raw || r->vol->mftmirr_size <= FILE_LogFile)
		goto fail;
	ni = ntfs_inode_allocate(r->vol);
	if (!ni)
		goto fail;
	ni->mft_no = FILE_LogFile;
	ni->mrec = ntfs_malloc(size);
	if (!ni->mrec || ntfs_pread(r->vol->dev, offset, size, raw) != size)
		goto fail;
	memcpy(ni->mrec, raw, size);
	if (memcmp(ni->mrec, "FILE", 4) ||
			ntfs_mst_post_read_fixup((NTFS_RECORD *)ni->mrec, size) ||
			!(ni->mrec->flags & MFT_RECORD_IN_USE) || ni->mrec->base_mft_record ||
			le32_to_cpu(ni->mrec->bytes_allocated) != size ||
			le32_to_cpu(ni->mrec->bytes_in_use) > size)
		goto fail;
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx)
		goto fail;
	if (!ntfs_attr_lookup(AT_ATTRIBUTE_LIST, AT_UNNAMED, 0, CASE_SENSITIVE,
			0, NULL, 0, ctx)) {
		length = ntfs_get_attribute_value_length(ctx->attr);
		if (length <= 0 || length > 0x40000)
			goto fail;
		ni->attr_list = ntfs_malloc(length);
		if (!ni->attr_list || ntfs_get_attribute_value(r->vol,
				ctx->attr, ni->attr_list) != length)
			goto fail;
		ni->attr_list_size = length;
		NInoSetAttrList(ni);
	} else if (errno != ENOENT)
		goto fail;
	ntfs_attr_put_search_ctx(ctx);
	ctx = NULL;
	if (replay_init_mft(r))
		goto fail;
	target = replay_logfile_record_target(r, FILE_LogFile, 0);
	if (!target || replay_lcns(r, target, 0, raw, size, TRUE))
		goto fail;
	r->log_bootstrap = TRUE;
	free(raw);
	free(target);
	return ni;
fail:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	ntfs_inode_close(ni);
	free(raw);
	free(target);
	return NULL;
}

static int replay_logfile_image(struct ntfsck_replay *r, u64 number)
{
	struct replay_attr *attr;
	u8 *target, *data = ntfs_malloc(r->vol->mft_record_size);
	int ret = -1;

	attr = replay_filename_attr(r, MK_MREF(FILE_MFT,
			le16_to_cpu(r->vol->mft_ni->mrec->sequence_number)), 0x80, 0, NULL, 0);
	if (!attr) {
		free(data);
		return -1;
	}
	target = replay_logfile_record_target(r, number, attr->slot);
	if (data && target &&
			!replay_lcns(r, target, 0, data, r->vol->mft_record_size, FALSE) &&
			!replay_lcns(r, target, 0, data, r->vol->mft_record_size, TRUE))
		ret = replay_note_image(r, target, 0, r->vol->mft_record_size, TRUE);
	free(data);
	free(target);
	return ret;
}

static int replay_filename_store(struct ntfsck_replay *r, const u8 *log,
		const void *buffer, u32 size, BOOL mft)
{
	u8 *data = ntfs_malloc(size);
	int ret = -1;

	if (!data)
		return -1;
	memcpy(data, buffer, size);
	w64(data + 8, r->current);
	if (ntfs_mst_pre_write_fixup((NTFS_RECORD *)data, size) ||
			replay_lcns(r, log, 0, data, size, TRUE) ||
			replay_note_image(r, log, 0, size, mft))
		goto out;
	r->filename_changed = TRUE;
	ret = 0;
out:
	free(data);
	return ret;
}

static int replay_filename_mft(struct ntfsck_replay *r, ntfs_inode *ni)
{
	struct replay_attr *a = replay_filename_attr(r, 0, 0x80, 0, NULL, 0);
	u8 template[32] = { 0 }, *log;
	u64 pos = ni->mft_no * r->vol->mft_record_size;
	int ret;

	if (!a)
		return -1;
	w16(template + 12, a->slot);
	w16(template + 20, (pos & (r->vol->cluster_size - 1)) / REPLAY_SECTOR);
	w64(template + 24, pos >> r->vol->cluster_size_bits);
	log = replay_mft_target(r, template);
	if (!log)
		return -1;
	ret = replay_filename_store(r, log, ni->mrec, r->vol->mft_record_size, TRUE);
	free(log);
	return ret;
}

static int replay_filename_index(struct ntfsck_replay *r, ntfs_index_context *icx)
{
	struct replay_attr *a;
	ntfs_attr *na = icx->ia_na;
	u64 pos, vcn;
	u32 size = r->vol->cluster_size, count, i;
	u8 *log;
	int ret = -1;

	if (icx->is_in_root)
		return replay_filename_mft(r, icx->actx->ntfs_ino);
	pos = ntfs_ib_vcn_to_pos(icx, sle64_to_cpu(icx->ib->index_block_vcn));
	if (pos > INT64_MAX || !na || pos > (u64)na->data_size ||
			icx->block_size > (u64)na->data_size - pos)
		return replay_invalid();
	if (ntfs_attr_map_whole_runlist(na))
		return -1;
	a = replay_filename_attr(r, MK_MREF(icx->ni->mft_no,
			le16_to_cpu(icx->ni->mrec->sequence_number)), 0xa0,
			icx->block_size, NTFS_INDEX_I30, 8);
	if (!a)
		return -1;
	vcn = pos >> r->vol->cluster_size_bits;
	count = ((pos & (size - 1)) + icx->block_size + size - 1) / size;
	log = ntfs_calloc(32ULL + count * 8);
	if (!log)
		return -1;
	w16(log + 12, a->slot);
	w16(log + 14, count);
	w16(log + 20, (pos & (size - 1)) / REPLAY_SECTOR);
	w64(log + 24, vcn);
	for (i = 0; i < count; i++) {
		LCN lcn = ntfs_rl_vcn_to_lcn(na->rl, vcn + i);

		if (lcn <= 0 || lcn >= r->vol->nr_clusters) {
			replay_invalid();
			goto out;
		}
		w64(log + 32 + i * 8, lcn);
	}
	ret = replay_filename_store(r, log, icx->ib, icx->block_size, FALSE);
out:
	free(log);
	return ret;
}

/* Extent size updates belong to the live base inode and all of its names. */
static ntfs_inode *replay_filename_base(ntfs_volume *vol, u64 number)
{
	MFT_RECORD *m = NULL;
	u64 reference;
	BOOL extent;

	if (number >= (u64)vol->mft_na->data_size / vol->mft_record_size) {
		errno = ENOENT;
		return NULL;
	}
	if (ntfs_file_record_read(vol, number, &m, NULL))
		return NULL;
	if (!(m->flags & MFT_RECORD_IN_USE) || (!m->base_mft_record && !m->link_count)) {
		free(m);
		errno = ENOENT;
		return NULL;
	}
	extent = !!m->base_mft_record;
	reference = extent ? le64_to_cpu(m->base_mft_record) :
		MK_MREF(number, le16_to_cpu(m->sequence_number));
	free(m);
	if (MREF(reference) < FILE_first_user) {
		errno = ENOENT;
		return NULL;
	}
	if (extent) {
		m = NULL;
		if (ntfs_file_record_read(vol, MREF(reference), &m, NULL))
			return NULL;
		if (!(m->flags & MFT_RECORD_IN_USE) || !m->link_count) {
			free(m);
			errno = ENOENT;
			return NULL;
		}
		if (m->base_mft_record || MSEQNO(reference) != le16_to_cpu(m->sequence_number)) {
			free(m);
			replay_invalid();
			return NULL;
		}
		free(m);
	}
	return ntfs_inode_open(vol, reference);
}

/* Incomplete directory links are repaired by the later filesystem scan. */
static int replay_filename_deferred(ntfs_volume *vol, u64 number)
{
	struct replay_view *view = vol->dev->d_private;

	if (view->read_error || errno == ENOMEM)
		return -1;
	ntfs_log_warning("Filename recovery deferred for MFT record %"PRIu64".\n", number);
	return 0;
}

static int replay_filename_tag(ntfs_inode *ni, u32 *tag)
{
	ntfs_attr *na;
	le32 value;
	s64 got;

	*tag = 0;
	if (!(ni->flags & FILE_ATTR_REPARSE_POINT))
		return 0;
	na = ntfs_attr_open(ni, AT_REPARSE_POINT, AT_UNNAMED, 0);
	if (!na)
		return errno == ENOENT ? 0 : -1;
	if (na->data_size < (s64)sizeof(value)) {
		ntfs_attr_close(na);
		return replay_invalid();
	}
	got = ntfs_attr_pread(na, 0, sizeof(value), &value);
	ntfs_attr_close(na);
	if (got != (s64)sizeof(value))
		return -1;
	*tag = le32_to_cpu(value);
	return 0;
}

static int replay_filename_links(struct ntfsck_replay *r, ntfs_inode *ni)
{
	ntfs_attr_search_ctx *ctx = ntfs_attr_get_search_ctx(ni, NULL);
	u64 allocated = ni->allocated_size, data = ni->data_size;
	u32 tag, mask = le32_to_cpu(FILE_ATTR_VALID_FLAGS);
	int ret = -1;

	if (!ctx)
		return -1;
	if (replay_filename_tag(ni, &tag)) {
		ret = replay_filename_deferred(ni->vol, ni->mft_no);
		goto out;
	}
	if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY)
		allocated = data = 0;
	else if (ni->allocated_size < 0 || ni->data_size < 0)
		goto invalid;
	while (!ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, CASE_SENSITIVE,
			0, NULL, 0, ctx)) {
		ATTR_RECORD *attr = ctx->attr;
		u32 offset = le16_to_cpu(attr->value_offset);
		u32 length = le32_to_cpu(attr->value_length);
		FILE_NAME_ATTR *fn, *indexed;
		FILE_NAME_ATTR updated;
		ntfs_inode *parent;
		ntfs_index_context *icx;
		BOOL own_changed, index_changed;

		if (attr->non_resident || offset > le32_to_cpu(attr->length) ||
				length > le32_to_cpu(attr->length) - offset ||
				length < sizeof(*fn))
			goto invalid;
		fn = (FILE_NAME_ATTR *)((u8 *)attr + offset);
		if (fn->file_name_length > (length - sizeof(*fn)) / sizeof(ntfschar))
			goto invalid;
		if (MREF_LE(fn->parent_directory) == ni->mft_no)
			continue;
		parent = ntfs_inode_open(ni->vol, le64_to_cpu(fn->parent_directory));
		if (!parent) {
			ret = replay_filename_deferred(ni->vol, ni->mft_no);
			if (ret)
				goto out;
			continue;
		}
		icx = ntfs_index_ctx_get(parent, NTFS_INDEX_I30, 4);
		if (!icx) {
			int error = errno;

			ntfs_inode_close(parent);
			errno = error;
			ret = -1;
			goto out;
		}
		ret = ntfs_index_lookup(fn, sizeof(*fn), icx);
		if (!ret && (icx->data_len < sizeof(*fn) ||
				le64_to_cpu(icx->entry->indexed_file) !=
				MK_MREF(ni->mft_no, le16_to_cpu(ni->mrec->sequence_number))))
			ret = replay_invalid();
		if (ret) {
			int error = errno;

			ntfs_index_ctx_put(icx);
			ntfs_inode_close(parent);
			errno = error;
			ret = replay_filename_deferred(ni->vol, ni->mft_no);
			if (ret)
				goto out;
			continue;
		}
		if (!ret) {
			indexed = icx->data;
			own_changed = r64(&fn->allocated_size) != allocated ||
				r64(&fn->data_size) != data;
			updated = *indexed;
			w64(&updated.allocated_size, allocated);
			w64(&updated.data_size, data);
			w32(&updated.file_attributes, (r32(&indexed->file_attributes) & ~mask) |
					(le32_to_cpu(ni->flags) & mask));
			w32(&updated.reparse_point_tag, tag);
			updated.creation_time = fn->creation_time;
			updated.last_data_change_time = fn->last_data_change_time;
			updated.last_mft_change_time = fn->last_mft_change_time;
			updated.last_access_time = fn->last_access_time;
			index_changed = memcmp(indexed, &updated, sizeof(updated));
			w64(&fn->allocated_size, allocated);
			w64(&fn->data_size, data);
			memcpy(indexed, &updated, sizeof(updated));
			if (index_changed)
				ret = replay_filename_index(r, icx);
			if (!ret && own_changed)
				ret = replay_filename_mft(r, ctx->ntfs_ino);
		}
		ntfs_index_ctx_put(icx);
		ntfs_inode_close(parent);
		if (ret)
			goto out;
	}
	ret = errno == ENOENT ? 0 : replay_filename_deferred(ni->vol, ni->mft_no);
	goto out;
invalid:
	replay_invalid();
	ret = replay_filename_deferred(ni->vol, ni->mft_no);
out:
	ntfs_attr_put_search_ctx(ctx);
	return ret;
}

static int replay_sync_filenames(struct ntfsck_replay *r)
{
	struct replay_view view = { .replay = r };
	struct replay_filename *f;
	struct ntfs_device *dev;
	ntfs_volume *vol;
	ntfs_inode *ni;
	ntfs_attr *na;
	u8 *upcase;
	s64 length, got;
	int ret = -1, error, status;

	if (!r->filenames)
		return 0;
	dev = ntfs_device_alloc(r->vol->dev->d_name, 0, &replay_view_ops, &view);
	if (!dev)
		return -1;
	vol = ntfs_volume_startup(dev, NTFS_MNT_RDONLY | NTFS_MNT_FS_NO_REPAIR);
	if (!vol) {
		ntfs_device_free(dev);
		return -1;
	}
	ni = ntfs_inode_open(vol, FILE_UpCase);
	if (!ni)
		goto out;
	na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
	if (!na) {
		ntfs_inode_close(ni);
		goto out;
	}
	length = na->data_size;
	if (length <= 0 || (length & 1) || length > 131072) {
		ntfs_attr_close(na);
		ntfs_inode_close(ni);
		replay_invalid();
		goto out;
	}
	upcase = ntfs_malloc(length);
	got = upcase ? ntfs_attr_pread(na, 0, length, upcase) : -1;
	ntfs_attr_close(na);
	ntfs_inode_close(ni);
	if (got != length) {
		free(upcase);
		goto out;
	}
	free(vol->upcase);
	vol->upcase = (ntfschar *)upcase;
	vol->upcase_len = length / sizeof(ntfschar);
	for (f = r->filenames; f; f = f->next) {
		ni = replay_filename_base(vol, f->mft_no);
		if (!ni) {
			if (view.read_error || errno == ENOMEM)
				goto out;
			if (errno != ENOENT)
				replay_filename_deferred(vol, f->mft_no);
			continue;
		}
		status = replay_filename_links(r, ni);
		error = errno;
		ntfs_inode_close(ni);
		errno = error;
		if (status || view.read_error)
			goto out;
	}
	ret = 0;
out:
	error = view.read_error ? view.read_error : errno;
	errno = 0;
	if (ntfs_umount(vol, FALSE))
		ret = -1;
	errno = error;
	return ret;
}

struct replay_writer {
	struct ntfsck_replay *replay;
	struct replay_log_page **tail;
	struct replay_dirty *dirty;
	struct replay_dirty **dirty_tail;
	u64 pos, sequence, available;
	u64 first_zero_undo, last_zero_undo;
	u32 dirty_count, max_lcns;
};

static u64 replay_writer_lsn(struct replay_writer *w)
{
	struct ntfsck_replay *r = w->replay;

	return (w->sequence << r->file_bits) | ((w->pos + r->data_offset) >> 3);
}

static int replay_writer_page(struct replay_writer *w, const u8 *data)
{
	struct ntfsck_replay *r = w->replay;
	struct replay_log_page *page;

	if (!w->available) {
		errno = ENOSPC;
		return -1;
	}
	page = ntfs_malloc(sizeof(*page) + r->page_size);
	if (!page)
		return -1;
	page->next = NULL;
	page->offset = w->pos;
	memcpy(page->data, data, r->page_size);
	*w->tail = page;
	w->tail = &page->next;
	w->available--;
	w->pos = replay_next_page(r, w->pos);
	if (w->pos == r->first_page && !++w->sequence)
		return replay_invalid();
	if (w->sequence > (UINT64_MAX >> r->file_bits))
		return replay_invalid();
	return 0;
}

/* One record per page (or page group) keeps restart discovery unambiguous. */
static int replay_writer_record(struct replay_writer *w, const u8 *data,
		u32 length, u32 type, u32 transaction, u64 undo_next, u64 *lsn)
{
	struct ntfsck_replay *r = w->replay;
	u32 capacity = r->page_size - r->data_offset;
	u32 bytes, pages, i, copied = 0;
	u8 *record, *page;
	int ret = -1;

	if (length > UINT32_MAX - r->header_size - 7)
		return replay_invalid();
	bytes = r->header_size + ((length + 7) & ~7U);
	pages = ((u64)bytes + capacity - 1) / capacity;
	if (pages > 65535)
		return replay_invalid();
	*lsn = replay_writer_lsn(w);
	record = ntfs_calloc(bytes);
	page = ntfs_calloc(r->page_size);
	if (!record || !page)
		goto out;
	w64(record, *lsn);
	w64(record + 16, undo_next);
	w32(record + 24, length);
	w16(record + 28, r->client_sequence);
	w16(record + 30, r->client);
	w32(record + 32, type);
	w32(record + 36, transaction);
	w16(record + 40, pages > 1);
	memcpy(record + r->header_size, data, length);
	for (i = 0; i < pages; i++) {
		u32 chunk = min(bytes - copied, capacity);

		memset(page, 0, r->page_size);
		memcpy(page, "RCRD", 4);
		w16(page + 4, 40);
		w16(page + 6, r->page_size / REPLAY_SECTOR + 1);
		w64(page + 8, *lsn);
		w32(page + 16, i == pages - 1);
		w16(page + 20, pages);
		w16(page + 22, i);
		/* A full 64 KiB page has no next record; its offset wraps to zero. */
		w16(page + 24, (r->data_offset + chunk) & 65535U);
		w64(page + 32, i == pages - 1 ? *lsn : 0);
		memcpy(page + r->data_offset, record + copied, chunk);
		if (ntfs_mst_pre_write_fixup((NTFS_RECORD *)page, r->page_size) ||
				replay_writer_page(w, page))
			goto out;
		copied += chunk;
	}
	ret = 0;
out:
	free(record);
	free(page);
	return ret;
}

static int replay_writer_dump(struct replay_writer *w, u16 op, const u8 *data,
		u32 length, u64 *lsn)
{
	u8 *payload = ntfs_calloc(40ULL + length);
	int ret;

	if (!payload)
		return -1;
	w16(payload, op);
	w16(payload + 4, 40);
	w16(payload + 6, min(length, 65535U));
	w16(payload + 8, 40);
	if (length)
		memcpy(payload + 40, data, length);
	ret = replay_writer_record(w, payload, 40 + length, 1, 64, 0, lsn);
	free(payload);
	return ret;
}

static void replay_table_header(u8 *data, u32 size, u32 used, u32 total)
{
	w16(data, size);
	w16(data + 2, used);
	w16(data + 4, total);
}

static int replay_writer_attrs(struct replay_writer *w, u64 *lsns, u32 *lengths)
{
	struct ntfsck_replay *r = w->replay;
	struct replay_attr *a;
	u32 slots = 0, total = 0, names = 0, off = 0;
	u8 *table, *name;
	int ret = -1;

	for (a = r->attrs; a; a = a->next) {
		if (!a->type || a->slot < 24 || (a->slot - 24) % r->attr_size)
			return replay_invalid();
		slots = max(slots, (a->slot - 24) / r->attr_size + 1);
		total++;
		if (a->name_bytes)
			names += 6 + a->name_bytes;
		else if (a->entry[r->checkpoint_version ? 13 : 25])
			return replay_invalid();
	}
	lengths[0] = 24 + slots * r->attr_size;
	lengths[1] = names;
	table = ntfs_calloc(lengths[0]);
	name = ntfs_calloc(names ? names : 1);
	if (!table || !name)
		goto out;
	replay_table_header(table, r->attr_size, slots, total);
	for (a = r->attrs; a; a = a->next) {
		u8 *entry = table + a->slot;

		memcpy(entry, a->entry, r->attr_size);
		w32(entry, REPLAY_ALLOCATED);
		/* Names are in the new dump; no old log or memory pointers survive. */
		w64(entry + (r->checkpoint_version ? 24 : 16), 0);
		if (r->checkpoint_version)
			w64(entry + 32, 0);
		else {
			w32(entry + 4, 0);
			w32(entry + 36, 0);
		}
		entry[r->checkpoint_version ? 12 : 24] = 1;
		entry[r->checkpoint_version ? 13 : 25] = !!a->name_bytes;
		entry[r->checkpoint_version ? 14 : 32] = a->name_bytes / 2;
		if (a->name_bytes) {
			w16(name + off, a->slot);
			w16(name + off + 2, a->name_bytes);
			memcpy(name + off + 4, a->name, a->name_bytes);
			off += 6 + a->name_bytes;
		}
	}
	if (replay_writer_dump(w, OpenAttributeTableDump, table, lengths[0], lsns))
		goto out;
	if (names && replay_writer_dump(w, AttributeNamesDump, name, names, lsns + 1))
		goto out;
	ret = 0;
out:
	free(table);
	free(name);
	return ret;
}

static int replay_writer_snapshot(struct replay_writer *w, const u8 *log,
		const u8 *data, u32 size)
{
	u32 count = r16(log + 14), header = 32 + count * 8;
	u8 *payload;
	struct replay_dirty *d;
	u64 lsn;
	u32 i;
	int ret;
	BOOL zero_lcn = count == 1 && !r64(log + 32);

	if (header > 65535 || size > 65535 || w->dirty_count == 65535)
		return replay_invalid();
	payload = ntfs_calloc((size_t)header + size);
	d = ntfs_malloc(sizeof(*d) + (size_t)count * 8);
	if (!payload || !d) {
		free(payload);
		free(d);
		return -1;
	}
	memcpy(payload, log, header);
	w16(payload + 2, Noop);
	w16(payload + 4, header);
	w16(payload + 6, size);
	w16(payload + 8, 0);
	w16(payload + 10, 0);
	memcpy(payload + header, data, size);
	/*
	 * Zero denotes a freed cluster in dirty-page tables, so redo cannot
	 * replay a snapshot of physical LCN 0. Keep absolute undo images in a
	 * separate active transaction instead; repeating them is idempotent.
	 */
	if (zero_lcn) {
		w16(payload, Noop);
		w16(payload + 2, UpdateNonresidentValue);
		w16(payload + 6, 0);
		w16(payload + 8, header);
		w16(payload + 10, size);
	}
	ret = replay_writer_record(w, payload, header + size, 1,
			zero_lcn ? 24 : 64, zero_lcn ? w->last_zero_undo : 0, &lsn);
	free(payload);
	if (ret) {
		free(d);
		return ret;
	}
	if (zero_lcn) {
		if (!w->first_zero_undo)
			w->first_zero_undo = lsn;
		w->last_zero_undo = lsn;
		free(d);
		return 0;
	}
	*d = (struct replay_dirty) {
		.slot = r16(log + 12), .count = count,
		.vcn = r64(log + 24), .oldest = lsn,
	};
	for (i = 0; i < count; i++)
		d->lcns[i] = r64(log + 32 + i * 8);
	*w->dirty_tail = d;
	w->dirty_tail = &d->next;
	w->dirty_count++;
	w->max_lcns = max(w->max_lcns, count);
	return 0;
}

/* A zero index-size hint selects the native raw-stream replay path. */
static int replay_large_image_attrs(struct ntfsck_replay *r)
{
	struct replay_image *image;

	for (image = r->images; image; image = image->next) {
		struct replay_attr *attr, *raw;

		if (image->size <= 65535)
			continue;
		if (image->mft || image->size != 65536)
			return replay_invalid();
		attr = replay_attr_slot(r, r16(image->log + 12));
		if (!attr)
			return -1;
		raw = replay_filename_attr(r,
				r64(attr->entry + (r->checkpoint_version ? 16 : 8)),
				attr->type, 0, (const ntfschar *)attr->name, attr->name_bytes);
		if (!raw)
			return -1;
		image->raw_slot = raw->slot;
	}
	return 0;
}

/* Store already-protected large indexes as absolute, sector-aligned chunks. */
static int replay_writer_chunks(struct replay_writer *w, const u8 *source,
		const u8 *data, u32 length, u16 slot)
{
	struct ntfsck_replay *r = w->replay;
	u32 size = r->vol->cluster_size, offset;

	for (offset = 0; offset < length; offset += 32768) {
		u64 start = ((u64)r16(source + 20) << 9) + offset;
		u32 bytes = min(length - offset, 32768U);
		u32 first = start / size;
		u32 count = ((start & (size - 1)) + bytes + size - 1) / size;
		u8 *log = ntfs_calloc(32ULL + count * 8);
		int ret;

		if (!log)
			return -1;
		w16(log, UpdateNonresidentValue);
		w16(log + 12, slot);
		w16(log + 14, count);
		w16(log + 20, (start & (size - 1)) / REPLAY_SECTOR);
		w64(log + 24, r64(source + 24) + first);
		memcpy(log + 32, source + 32 + first * 8, count * 8);
		ret = replay_writer_snapshot(w, log, data + offset, bytes);
		free(log);
		if (ret)
			return -1;
	}
	return 0;
}

static int replay_cover_image(struct ntfsck_replay *r, const u8 *log,
		u32 size, u16 steps, u16 *sequence)
{
	u64 pos = (u64)r16(log + 20) << 9;
	u16 tails[128];
	u32 i, count = 0;

	for (i = 0; i < size; i += REPLAY_SECTOR, pos += REPLAY_SECTOR) {
		u64 physical = (r64(log + 32 + (pos >> r->vol->cluster_size_bits) * 8) <<
				r->vol->cluster_size_bits) + (pos & (r->vol->cluster_size - 1));
		u32 bucket = (physical / REPLAY_SECTOR) % REPLAY_BUCKETS;
		struct replay_sector *s;

		for (s = r->sectors[bucket]; s && (u64)s->offset != physical; s = s->next)
			;
		if (!s || s->covered)
			return replay_invalid();
		s->covered = TRUE;
		tails[count++] = r16(s->original + REPLAY_SECTOR - 2);
	}
	/* A partial new image must never pass fixups with an old sector tail. */
	for (*sequence = 1 + steps; ; (*sequence)++) {
		for (i = 0; i < count && (tails[i] > *sequence ||
				tails[i] + steps <= *sequence); i++)
			;
		if (i == count)
			break;
	}
	return 0;
}

/* A native replay must also refresh the LogFile inode pinned at mount. */
static int replay_writer_logfile_image(struct replay_writer *w, u8 *log,
		u8 *data, u32 size, u16 sequence)
{
	struct ntfsck_replay *r = w->replay;
	u8 sizes[24];
	u64 lsn;

	w64(data + 8, replay_writer_lsn(w));
	w16(data + r16(data + 4), sequence - 2);
	if (replay_writer_snapshot(w, log, data, size))
		return -1;
	w16(log, SetNewAttributeSizes);
	w16(log + 16, r->log_attr);
	w64(sizes, r->log_final.allocated);
	w64(sizes + 8, r->log_final.initialized);
	w64(sizes + 16, r->log_final.data);
	lsn = replay_writer_lsn(w);
	if (replay_writer_snapshot(w, log, sizes, sizeof(sizes)))
		return -1;
	/* Initialize and SetNewAttributeSizes each increment the fixup sequence. */
	w64(data + 8, lsn);
	w16(data + r16(data + 4), sequence - 1);
	w16(log + 16, 0);
	if (ntfs_mst_pre_write_fixup((NTFS_RECORD *)data, size))
		return -1;
	return replay_lcns(r, log, 0, data, size, TRUE);
}

static int replay_writer_images(struct replay_writer *w)
{
	struct ntfsck_replay *r = w->replay;
	struct replay_image *image;
	u32 size = r->vol->cluster_size, i, pass;

	/* Restore the MFT first and refresh the LogFile inode after all its extents. */
	for (pass = 0; pass < 3; pass++) {
		for (image = r->images; image; image = image->next) {
			const u8 *source = image->log;
			u64 start;
			u32 first, count;
			u8 *mapped = NULL, *log = NULL, *data = NULL;
			u16 sequence = 0;
			int ret = -1;
			BOOL mft_zero = image->mft && !r64(source + 24) && !r16(source + 20);
			BOOL logfile = image->mft && r->log_changed &&
				((r64(source + 24) << r->vol->cluster_size_bits) +
				 ((u64)r16(source + 20) << 9)) / image->size == r->log_record;

			if (pass != (mft_zero ? 0U : (logfile ? 2U : 1U)))
				continue;
			if (image->mft) {
				u64 pos = (r64(source + 24) << r->vol->cluster_size_bits) +
					((u64)r16(source + 20) << 9);

				/* Old, unmapped copies use absolute sector snapshots below. */
				if (pos >= r->mft_allocated || image->size > r->mft_allocated - pos)
					continue;
				mapped = replay_mft_target(r, source);
				if (!mapped)
					goto image_out;
				if ((r64(mapped + 32) << r->vol->cluster_size_bits) +
						((u64)r16(mapped + 20) << 9) != image->physical) {
					free(mapped);
					continue;
				}
				source = mapped;
			}
			start = ((u64)r16(source + 20) << 9) + image->offset;
			first = start / size;
			count = ((start & (size - 1)) + image->size + size - 1) / size;
			log = ntfs_calloc(32ULL + count * 8);
			data = ntfs_malloc(image->size);
			if (!log || !data)
				goto image_out;
			if ((start & (REPLAY_SECTOR - 1)) ||
					(image->size > 65535 && !image->raw_slot))
				goto image_out;
			w16(log + 12, r16(source + 12));
			w16(log + 14, count);
			w16(log + 20, (start & (size - 1)) / REPLAY_SECTOR);
			w64(log + 24, r64(source + 24) + first);
			memcpy(log + 32, source + 32 + first * 8, count * 8);
			if (replay_lcns(r, log, 0, data, image->size, FALSE) ||
					ntfs_mst_post_read_fixup((NTFS_RECORD *)data,
						image->size) ||
					replay_cover_image(r, log, image->size,
						logfile ? 2 : 1, &sequence))
				goto image_out;
			w16(log, !memcmp(data, "FILE", 4) ?
					InitializeFileRecordSegment : UpdateNonresidentValue);
			if (logfile) {
				ret = replay_writer_logfile_image(w, log, data,
						image->size, sequence);
				goto image_out;
			}
			w64(data + 8, replay_writer_lsn(w));
			w16(data + r16(data + 4), sequence - 1);
			/* First execution and retries use the same page LSN and complete image. */
			if (ntfs_mst_pre_write_fixup((NTFS_RECORD *)data, image->size) ||
					replay_lcns(r, log, 0, data, image->size, TRUE))
				goto image_out;
			if (image->raw_slot) {
				ret = replay_writer_chunks(w, log, data,
						image->size, image->raw_slot);
				goto image_out;
			}
			if (ntfs_mst_post_read_fixup((NTFS_RECORD *)data, image->size))
				goto image_out;
			/* Redo applies fixups once, producing the same protected image. */
			w16(data + r16(data + 4), sequence - 1);
			ret = replay_writer_snapshot(w, log, data, image->size);
image_out:
			free(mapped);
			free(log);
			free(data);
			if (ret)
				return -1;
		}
	}
	for (i = 0; i < REPLAY_BUCKETS; i++)
		for (struct replay_sector *s = r->sectors[i]; s; s = s->next) {
			u8 log[40] = { 0 };

			if (s->covered || !memcmp(s->data, s->original, REPLAY_SECTOR))
				continue;
			w16(log, UpdateNonresidentValue);
			w16(log + 12, s->slot);
			w16(log + 14, 1);
			w16(log + 20, (s->offset & (size - 1)) / REPLAY_SECTOR);
			w64(log + 24, s->vcn);
			w64(log + 32, (u64)s->offset >> r->vol->cluster_size_bits);
			if (replay_writer_snapshot(w, log, s->data, REPLAY_SECTOR))
				return -1;
		}
	return 0;
}

static int replay_writer_dirty(struct replay_writer *w, u64 *lsn, u32 *length)
{
	struct ntfsck_replay *r = w->replay;
	u32 header = r->checkpoint_version ? 32 : 36;
	u32 stride = header + w->max_lcns * 8, off = 24;
	struct replay_dirty *d;
	u8 *data;
	int ret;

	if (!w->dirty_count) {
		*lsn = 0;
		*length = 0;
		return 0;
	}
	if (stride > 65535 || (u64)stride * w->dirty_count + 24 > UINT32_MAX)
		return replay_invalid();
	*length = 24 + stride * w->dirty_count;
	data = ntfs_calloc(*length);
	if (!data)
		return -1;
	replay_table_header(data, stride, w->dirty_count, w->dirty_count);
	for (d = w->dirty; d; d = d->next, off += stride) {
		u32 i;

		w32(data + off, REPLAY_ALLOCATED);
		w32(data + off + 4, d->slot);
		w32(data + off + 8, d->count * r->vol->cluster_size);
		w32(data + off + 12, d->count);
		w64(data + off + header - 16, d->vcn);
		w64(data + off + header - 8, d->oldest);
		for (i = 0; i < d->count; i++)
			w64(data + off + header + i * 8, d->lcns[i]);
	}
	ret = replay_writer_dump(w, DirtyPageTableDump, data, *length, lsn);
	free(data);
	return ret;
}

static int replay_writer_transactions(struct replay_writer *w, u64 *lsn, u32 *length)
{
	u8 table[64] = { 0 };

	if (!w->last_zero_undo)
		return 0;
	replay_table_header(table, 40, 1, 1);
	w32(table + 24, REPLAY_ALLOCATED);
	table[28] = 1;
	w64(table + 32, w->first_zero_undo);
	w64(table + 40, w->last_zero_undo);
	w64(table + 48, w->last_zero_undo);
	*length = sizeof(table);
	return replay_writer_dump(w, TransactionTableDump, table, *length, lsn);
}

/*
 * Undo is not generally idempotent. Before changing any target, replace the
 * active undo chains with a durable checkpoint of absolute final images.
 * LCN 0 uses absolute undo; other images use redo and dirty-page entries.
 * Until its restart page is published, the original live log stays untouched.
 * A failed write or process restart can then repeat absolute image writes.
 */
static int replay_build_recovery(struct ntfsck_replay *r)
{
	struct replay_writer w = { .replay = r, .tail = &r->recovery_pages };
	u64 end, oldest, cp, ignored, lsns[4] = { 0 };
	u32 offset, remaining, lengths[4] = { 0 }, i;
	u8 checkpoint[64] = { 0 }, *page, *ra, *client;
	int ret = -1;

	if (!r->undo_count && !r->filename_changed && !r->log_changed && !r->log_bootstrap)
		return 0;
	if (replay_large_image_attrs(r))
		return -1;
	w.dirty_tail = &w.dirty;
	if (replay_lsn_offset(r, r->oldest ? r->oldest : r->retained, &oldest) ||
			replay_lsn_offset(r, r->current, &end))
		return replay_invalid();
	if (40 + 2 * (r->page_size / REPLAY_SECTOR + 1) > r->data_offset)
		return replay_invalid();
	page = ntfs_malloc(max(r->page_size, r->restart_size));
	if (!page)
		return -1;
	/* Publish the other restart copy first, retaining the selected durable one. */
	r->restart_first = 0;
	for (i = 0; i < 2; i++)
		if (ntfs_attr_pread(r->log_na, (u64)i * r->restart_size,
				r->restart_size, page) == r->restart_size &&
				!ntfs_mst_post_read_fixup((NTFS_RECORD *)page, r->restart_size) &&
				!memcmp(page, r->restart_page, r->restart_size)) {
			r->restart_first = 1 - i;
			break;
		}
	if (i == 2)
		goto out;
	offset = end & (r->page_size - 1);
	end -= offset;
	remaining = r->header_size + r->last_data_length;
	while (remaining > r->page_size - offset) {
		remaining -= r->page_size - offset;
		end = replay_next_page(r, end);
		offset = r->data_offset;
	}
	w.pos = replay_next_page(r, end);
	w.sequence = r->current >> r->file_bits;
	/* A multi-page last record may have crossed the end of the log. */
	if (w.pos <= ((r->current & r->mask) << 3))
		w.sequence++;
	oldest &= ~((u64)r->page_size - 1);
	for (end = w.pos; end != oldest; end = replay_next_page(r, end))
		if (++w.available >= (r->log_size - r->first_page) / r->page_size)
			goto out;
	/* Stop the old restart's tail discovery before the unpublished new log. */
	memset(page, 0xff, r->page_size);
	if (replay_writer_page(&w, page) || replay_writer_attrs(&w, lsns, lengths) ||
			replay_writer_images(&w) ||
			replay_writer_dirty(&w, lsns + 2, lengths + 2) ||
			replay_writer_dump(&w, ForgetTransaction, NULL, 0, &ignored) ||
			replay_writer_transactions(&w, lsns + 3, lengths + 3))
		goto out;
	w32(checkpoint, r->checkpoint_version);
	w64(checkpoint + 8, lsns[0]);
	for (i = 0; i < 4; i++) {
		w64(checkpoint + 16 + i * 8, lsns[i]);
		w32(checkpoint + 48 + i * 4, lengths[i]);
	}
	if (replay_writer_record(&w, checkpoint, sizeof(checkpoint), 2, 0, 0, &cp))
		goto out;
	ra = r->restart_page + r16(r->restart_page + 24);
	client = ra + r16(ra + 22) + r->client * sizeof(LOG_CLIENT_RECORD);
	w64(ra, cp);
	w32(ra + 32, sizeof(checkpoint));
	w64(client, lsns[0]);
	w64(client + 8, cp);
	r->current = cp;
	r->last_data_length = sizeof(checkpoint);
	ret = 0;
out:
	while (w.dirty) {
		struct replay_dirty *next = w.dirty->next;

		free(w.dirty);
		w.dirty = next;
	}
	free(page);
	return ret;
}

void ntfsck_replay_free(struct ntfsck_replay *r)
{
	u32 i;

	if (!r)
		return;
	for (i = 0; i < REPLAY_BUCKETS; i++) {
		struct replay_sector *s = r->sectors[i];

		while (s) {
			struct replay_sector *next = s->next;

			free(s);
			s = next;
		}
	}
	while (r->records) {
		struct replay_record *next = r->records->next;

		free(r->records);
		r->records = next;
	}
	while (r->attrs) {
		struct replay_attr *next = r->attrs->next;

		free(r->attrs->name);
		free(r->attrs);
		r->attrs = next;
	}
	while (r->dirty) {
		struct replay_dirty *next = r->dirty->next;

		free(r->dirty);
		r->dirty = next;
	}
	while (r->transactions) {
		struct replay_transaction *next = r->transactions->next;

		free(r->transactions);
		r->transactions = next;
	}
	while (r->filenames) {
		struct replay_filename *next = r->filenames->next;

		free(r->filenames);
		r->filenames = next;
	}
	while (r->images) {
		struct replay_image *next = r->images->next;

		free(r->images);
		r->images = next;
	}
	while (r->recovery_pages) {
		struct replay_log_page *next = r->recovery_pages->next;

		free(r->recovery_pages);
		r->recovery_pages = next;
	}
	for (i = 0; i < r->tail_count; i++)
		free(r->tails[i].page);
	free(r->mft_rl);
	free(r->restart_page);
	if (r->log_na)
		ntfs_attr_close(r->log_na);
	if (r->log_ni)
		ntfs_inode_close(r->log_ni);
	free(r->log_initial.runs);
	free(r->log_final.runs);
	free(r);
}

int ntfsck_replay_prepare(ntfs_volume *vol, struct ntfsck_replay **result)
{
	struct ntfsck_replay *r;
	RESTART_PAGE_HEADER *rp = NULL;
	const u8 *ra;
	const char *stage = "opening the journal";
	int ret = -1;

	*result = NULL;
	r = ntfs_calloc(sizeof(*r));
	if (!r)
		return -1;
	r->vol = vol;
	r->dirty_tail = &r->dirty;
	r->log_ni = ntfs_inode_open(vol, FILE_LogFile);
	if (!r->log_ni && (errno == EIO || errno == EINVAL || errno == ENOENT))
		r->log_ni = replay_logfile_from_mirror(r);
	if (!r->log_ni)
		goto out;
	r->log_na = ntfs_attr_open(r->log_ni, AT_DATA, AT_UNNAMED, 0);
	if (!r->log_na)
		goto out;
	if (replay_copy_logfile(r, r->log_na, &r->log_initial))
		goto out;
	stage = "checking restart pages";
	if (!ntfs_check_logfile(r->log_na, &rp))
		goto out;
	if (rp && ntfs_is_chkd_record(rp->magic)) {
		ret = r->log_bootstrap ? replay_invalid() : 0;
		goto out;
	}
	ra = rp ? (const u8 *)rp + le16_to_cpu(rp->restart_area_offset) : NULL;
	if (!rp || (ntfs_is_rstr_record(rp->magic) &&
			(r16(ra + 12) == LOGFILE_NO_CLIENT_CPU || (r16(ra + 14) & 2)))) {
		ret = r->log_bootstrap ? replay_invalid() : 0;
		goto out;
	}
	stage = "selecting a durable restart";
	if (replay_choose_restart(r, &rp))
		goto out;
	ra = (const u8 *)rp + le16_to_cpu(rp->restart_area_offset);
	if (r16(ra + 12) == LOGFILE_NO_CLIENT_CPU || (r16(ra + 14) & 2)) {
		ret = r->log_bootstrap ? replay_invalid() : 0;
		goto out;
	}
	stage = "analyzing the checkpoint and log records";
	if (replay_analyze(r))
		goto out;
	stage = "preparing redo and undo";
	if (replay_init_mft(r) ||
			(r->log_bootstrap && replay_logfile_image(r, FILE_LogFile)) ||
			replay_redo_undo(r))
		goto out;
	stage = "checking the recovered MFT";
	if (replay_finalize_mft(r))
		goto out;
	stage = "refreshing recovered filename sizes";
	if (replay_sync_filenames(r))
		goto out;
	stage = "checking the recovered journal mapping";
	if (replay_final_logfile(r) ||
			(r->log_changed && replay_logfile_image(r, r->log_record)))
		goto out;
	r->restart_size = le32_to_cpu(rp->system_page_size);
	r->restart_page = (u8 *)rp;
	rp = NULL;
	stage = "preparing a restartable undo checkpoint";
	if (replay_build_recovery(r))
		goto out;
	ntfs_log_info("LogFile: recovery prepared: %"PRIu64" redo, %"PRIu64" undo operations.\n",
			r->redo_count, r->undo_count);
	*result = r;
	return 1;
out:
	if (ret < 0)
		ntfs_log_error("LogFile recovery failed while %s (errno %d).\n", stage, errno);
	free(rp);
	ntfsck_replay_free(r);
	return ret;
}

static int replay_write_restart(struct ntfsck_replay *r, BOOL clean)
{
	u32 i, version;
	u8 *page, *ra;

	page = ntfs_malloc(r->restart_size);
	if (!page)
		return -1;
	for (version = 0; version < (r->log_moved ? 2U : 1U); version++) {
		const struct replay_logfile *file = version ? &r->log_initial : &r->log_final;

		for (i = 0; i < 2; i++) {
			u64 pos = (u64)(i ^ r->restart_first) * r->restart_size;

			memcpy(page, r->restart_page, r->restart_size);
			ra = page + r16(page + 24);
			w16(ra + 14, clean ? r16(ra + 14) | 2 : r16(ra + 14) & ~2U);
			w64(ra, r->current);
			w32(ra + 32, r->last_data_length);
			if (ntfs_mst_pre_write_fixup((NTFS_RECORD *)page, r->restart_size) ||
					replay_logfile_write(r, file, pos, r->restart_size, page) ||
					r->vol->dev->d_ops->sync(r->vol->dev)) {
				free(page);
				return -1;
			}
		}
	}
	free(page);
	return 0;
}

int ntfsck_replay_commit(struct ntfsck_replay *r)
{
	u32 i;
	u8 check[REPLAY_SECTOR];
	struct replay_log_page *page;
	u32 version;

	if (!r || NVolReadOnly(r->vol)) {
		errno = EROFS;
		return -1;
	}
	/* Verify the entire input before publishing recovery or changing a target. */
	for (i = 0; i < REPLAY_BUCKETS; i++)
		for (struct replay_sector *s = r->sectors[i]; s; s = s->next)
			if (ntfs_pread(r->vol->dev, s->offset,
					sizeof(check), check) != sizeof(check) ||
					memcmp(check, s->original, sizeof(check)))
				return replay_invalid();
	if (r->recovery_pages) {
		if (replay_logfile_targets(r, &r->log_initial) ||
				replay_logfile_targets(r, &r->log_final))
			return -1;
		/* Publish both copies before any mapping or relative undo reaches disk. */
		for (version = 0; version < (r->log_moved ? 2U : 1U); version++) {
			const struct replay_logfile *file = version ?
				&r->log_initial : &r->log_final;

			for (page = r->recovery_pages; page; page = page->next)
				if (replay_logfile_write(r, file, page->offset,
						r->page_size, page->data))
					return -1;
		}
		if (r->vol->dev->d_ops->sync(r->vol->dev) || replay_write_restart(r, FALSE))
			return -1;
	}
	for (i = 0; i < REPLAY_BUCKETS; i++)
		for (struct replay_sector *s = r->sectors[i]; s; s = s->next)
			if (memcmp(s->data, s->original, sizeof(s->data)) &&
					ntfs_pwrite(r->vol->dev, s->offset,
						sizeof(s->data), s->data) != sizeof(s->data))
				return -1;
	if (r->vol->dev->d_ops->sync(r->vol->dev))
		return -1;
	/* Preserve the LSN epoch. Emptying the log would make old page LSNs stale. */
	return replay_write_restart(r, TRUE);
}
