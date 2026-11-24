// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Index entry bounds and allocation sizes taken from the disk.
 *
 * The entry table of an index has two numbers in its header (entries_offset,
 * index_length) and each entry carries its own length; the index root also
 * carries index_block_size. All of them are read from the volume and all of
 * them address memory: a walk that trusts them reads outside the buffer that
 * holds the index, and an index block buffer is allocated with the size the
 * root names. The sizes of $MFT, its bitmap and $Bitmap are used the same way,
 * and the number of clusters in the boot sector sizes the cluster bitmaps of
 * the mount. An entry's key_length sizes the copy of the key that is kept to
 * remove the entry later, and in an MFT record the attrs_offset and an
 * attribute's name_offset address memory in the same way.
 *
 * Two cases damage how the runlist of $MFT/$DATA is mapped: a second extent
 * whose runs overlap the runs already mapped must fail to merge without the
 * caller's runlist being freed under it.
 *
 * Each case damages one of those numbers in a fresh image and runs the ntfsck
 * of the build tree with -n and with -a: ntfsck must report the damage and
 * stop, neither crashing nor looping, and must not ask for a buffer sized from
 * a value that does not fit the volume. When -a repairs the damage (exit 1),
 * a -n run afterwards must find the volume clean.
 *
 * A crash, a fatal signal or a run that does not end fails a case in any build.
 * An out-of-bounds read that does not crash is caught only when the build tree
 * is built with AddressSanitizer: its report in the output fails the case.
 *
 * Build: cc -o test_index_entry_bounds test_index_entry_bounds.c
 * Usage: test_index_entry_bounds --build-dir DIR --temp-dir DIR
 *
 * Every offset is taken from the boot sector and the $MFT of the image the
 * test creates, so the test does not depend on the geometry mkntfs happens to
 * choose.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#define IMAGE_SIZE		(2LL * 1024 * 1024)
#define FILE_root_record	5	/* $Root: its $I30 index is a real tree */
#define FILE_MFT_record		0
#define FILE_Bitmap_record	6
#define FILE_Secure_record	9	/* $Secure: named $SDH, $SII roots */
#define FILE_Extend_record	11	/* $Extend: $I30 held in its root */
#define FILE_reserved_record	12	/* in use, reached by the record scan */
#define RUN_TIMEOUT		120
#define OUTPUT_MAX		(1 << 20)

#define AT_DATA			0x80
#define AT_INDEX_ROOT		0x90
#define AT_BITMAP		0xB0
#define AT_END			0xFFFFFFFF

/* Offsets inside a resident INDEX_ROOT. */
#define IROOT_INDEX		16	/* INDEX_HEADER after the fixed part */
#define IH_ENTRIES_OFFSET	0
#define IH_INDEX_LENGTH		4
/* Offsets inside an INDEX_ENTRY. */
#define IE_LENGTH		8
#define IE_KEY_LENGTH		10
/* Offsets inside an attribute record and an MFT record header. */
#define AR_NAME_OFFSET		10
#define MR_ATTRS_OFFSET		20
/* Offsets inside a non-resident attribute record. */
#define AR_ALLOCATED_SIZE	0x28
#define AR_DATA_SIZE		0x30
#define AR_VALUE_OFFSET		20

static char build_dir[PATH_MAX], temp_root[PATH_MAX], work[PATH_MAX];
static char pristine[PATH_MAX], ntfsck[PATH_MAX], mkntfs[PATH_MAX];
static char output[OUTPUT_MAX];
static int failures, passes, case_failed;
static const char *current;

struct layout {
	unsigned int sector_size, cluster_size, record_size;
	unsigned long long mft_offset;
	unsigned long long root_record;	/* image offset of record 5 */
	unsigned long long root_value;	/* image offset of the $I30 INDEX_ROOT */
	unsigned long long root_entry;	/* image offset of its first entry */
	unsigned int root_entries_offset;
	unsigned long long extend_entry;	/* image offset of the first
						 * entry of $Extend's $I30 */
	unsigned int extend_entry_length;
	unsigned long long secure_named_root;	/* image offset of a named
						 * $Secure INDEX_ROOT record */
	unsigned long long mft_data_size;	/* image offset of $MFT/$DATA data_size */
	unsigned long long mft_data_alloc;	/* value of $MFT/$DATA allocated_size */
	unsigned long long mft_bitmap_size;	/* image offset of $MFT/$BITMAP data_size */
	unsigned long long lcn_bitmap_size;	/* image offset of $Bitmap/$DATA data_size */
};

static int check(int ok, const char *what)
{
	if (!ok) {
		if (!case_failed) {
			case_failed = 1;
			failures++;
		}
		printf("FAIL %s: %s\n", current, what);
		printf("---- output ----\n%s---- end ----\n", output);
	}
	return ok;
}

static void require(int ok, const char *what)
{
	if (!ok) {
		fprintf(stderr, "setup failed: %s (%s)\n", what, strerror(errno));
		exit(2);
	}
}

/*
 * Read what is available into output[]. When the buffer is full, the older
 * half is dropped so the newest text is kept.
 */
static ssize_t read_output(int fd, size_t *used)
{
	ssize_t n;

	if (*used == sizeof(output) - 1) {
		size_t keep = *used / 2;

		memmove(output, output + *used - keep, keep);
		*used = keep;
	}
	n = read(fd, output + *used, sizeof(output) - 1 - *used);
	if (n > 0)
		*used += n;
	return n;
}

/* Run argv with stdin closed; output[] gets stdout and stderr. */
static int run(char *const argv[])
{
	int pipefd[2], status, devnull;
	size_t used = 0;
	time_t start = time(NULL);
	pid_t pid;

	require(!pipe(pipefd), "pipe");
	pid = fork();
	require(pid >= 0, "fork");
	if (!pid) {
		devnull = open("/dev/null", O_RDONLY);
		if (devnull < 0 || dup2(devnull, 0) < 0 ||
		    dup2(pipefd[1], 1) < 0 || dup2(pipefd[1], 2) < 0)
			_exit(127);
		close(pipefd[0]);
		setenv("LC_ALL", "C", 1);
		execv(argv[0], argv);
		_exit(127);
	}
	close(pipefd[1]);
	fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
	for (;;) {
		ssize_t n;

		/* Checked on every pass, so steady output cannot hold the test. */
		if (time(NULL) - start > RUN_TIMEOUT) {
			kill(pid, SIGKILL);
			waitpid(pid, &status, 0);
			close(pipefd[0]);
			output[used] = '\0';
			return -1;
		}
		n = read_output(pipefd[0], &used);
		if (n > 0)
			continue;
		if (waitpid(pid, &status, WNOHANG) == pid)
			break;
		usleep(10000);
	}
	/* Collect what was written just before the exit. */
	while (read_output(pipefd[0], &used) > 0)
		;
	close(pipefd[0]);
	output[used] = '\0';
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 128 + WTERMSIG(status);
}

static void path_in(char *dst, const char *dir, const char *name)
{
	require(snprintf(dst, PATH_MAX, "%s/%s", dir, name) < PATH_MAX, "path length");
}

static void copy_file(const char *src, const char *dst)
{
	char buf[4096], zero[4096] = { 0 };
	int in = open(src, O_RDONLY), out;
	off_t size = 0;
	ssize_t n;

	require(in >= 0, src);
	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	require(out >= 0, dst);
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		if (n == (ssize_t)sizeof(buf) && !memcmp(buf, zero, n))
			require(lseek(out, n, SEEK_CUR) >= 0, "seek");
		else
			require(write(out, buf, n) == n, "write copy");
		size += n;
	}
	require(n == 0, "read copy");
	require(!ftruncate(out, size), "truncate copy");
	close(in);
	close(out);
}

static unsigned int le16(const unsigned char *p)
{
	return p[0] | p[1] << 8;
}

static unsigned int le32(const unsigned char *p)
{
	return p[0] | p[1] << 8 | p[2] << 16 | (unsigned int)p[3] << 24;
}

static unsigned long long le64(const unsigned char *p)
{
	unsigned long long v = 0;
	int i;

	for (i = 7; i >= 0; i--)
		v = v << 8 | p[i];
	return v;
}

static void put16(unsigned char *p, unsigned int v)
{
	p[0] = v & 0xff;
	p[1] = v >> 8;
}

static void put32(unsigned char *p, unsigned int v)
{
	p[0] = v & 0xff;
	p[1] = v >> 8;
	p[2] = v >> 16;
	p[3] = v >> 24;
}

static void put64(unsigned char *p, unsigned long long v)
{
	int i;

	for (i = 0; i < 8; i++)
		p[i] = v >> (8 * i);
}

/*
 * Read one MFT record and undo the update sequence fixup, so the attribute
 * offsets inside it can be walked. The fixup is written into the last two
 * bytes of every sector, so no field the test patches sits there.
 */
static void read_record(int fd, const struct layout *L, unsigned int n,
		unsigned char *rec)
{
	unsigned char raw[4096];
	unsigned int usa, count, i;
	off_t base = L->mft_offset + (off_t)n * L->record_size;

	require(L->record_size <= sizeof(raw), "record size");
	require(pread(fd, raw, L->record_size, base) == (ssize_t)L->record_size,
		"read record");
	memcpy(rec, raw, L->record_size);
	usa = le16(raw + 4);
	count = le16(raw + 6);
	require(count == L->record_size / L->sector_size + 1 &&
	       usa + count * 2 <= L->record_size, "update sequence bounds");
	for (i = 1; i < count; i++) {
		unsigned int tail = i * L->sector_size - 2;

		require(!memcmp(raw + tail, raw + usa, 2), "update sequence tail");
		memcpy(rec + tail, raw + usa + 2 * i, 2);
	}
}

/*
 * Image offset of the data_size field of the first non-resident attribute of
 * @type, or 0 when the record has none.
 */
static unsigned long long data_size_offset(const unsigned char *rec,
		const struct layout *L, unsigned int n, unsigned int type)
{
	unsigned int pos = le16(rec + 20), used = le32(rec + 24);
	unsigned long long base = L->mft_offset + (unsigned long long)n *
		L->record_size;

	while (pos + 24 <= used) {
		unsigned int kind = le32(rec + pos), len = le32(rec + pos + 4);
		unsigned int off;

		if (kind == AT_END)
			break;
		require(len >= 24 && len <= used - pos, "attribute length");
		if (kind == type && rec[pos + 8]) {
			off = pos + AR_DATA_SIZE;
			require(off % L->sector_size < L->sector_size - 8,
				"data_size on a sector tail");
			return base + off;
		}
		pos += len;
	}
	return 0;
}

static const unsigned char i30_name[8] = { '$', 0, 'I', 0, '3', 0, '0', 0 };

/* Locate every field the cases patch, from the image itself. */
static void find_layout(int fd, struct layout *L)
{
	unsigned char boot[512], rec[4096];
	unsigned int sector, cluster, pos, used, eo;
	unsigned long long base;
	signed char code;

	require(pread(fd, boot, 512, 0) == 512, "read boot sector");
	require(!memcmp(boot + 3, "NTFS    ", 8), "missing NTFS signature");
	sector = le16(boot + 11);
	cluster = sector * boot[13];
	code = (signed char)boot[64];
	L->sector_size = sector;
	L->cluster_size = cluster;
	L->record_size = code < 0 ? 1u << -code : (unsigned int)code * cluster;
	require(L->record_size >= 512 && L->record_size <= sizeof(rec),
		"record size");
	L->mft_offset = le64(boot + 48) * cluster;
	base = L->mft_offset + (unsigned long long)FILE_root_record *
		L->record_size;
	L->root_record = base;

	read_record(fd, L, FILE_root_record, rec);
	pos = le16(rec + 20);
	used = le32(rec + 24);
	L->root_value = 0;
	while (pos + 24 <= used) {
		unsigned int kind = le32(rec + pos), len = le32(rec + pos + 4);
		unsigned int name_len = rec[pos + 9], off, value;

		if (kind == AT_END)
			break;
		require(len >= 24 && len <= used - pos, "attribute length");
		off = le16(rec + pos + 10);
		value = pos + le16(rec + pos + AR_VALUE_OFFSET);
		/* Attribute names are UTF-16LE: "$I30" is eight bytes on disk. */
		if (kind == AT_INDEX_ROOT && name_len == 4 &&
		    off + sizeof(i30_name) <= len &&
		    !memcmp(rec + pos + off, i30_name, sizeof(i30_name))) {
			require(value + IROOT_INDEX + 16 <= used,
				"index root bounds");
			eo = le32(rec + value + IROOT_INDEX + IH_ENTRIES_OFFSET);
			L->root_value = base + value;
			L->root_entries_offset = eo;
			L->root_entry = base + value + IROOT_INDEX + eo;
		}
		pos += len;
	}
	require(L->root_value, "missing $I30 index root");

	/*
	 * $Extend's index is small enough to live in its root, so its first
	 * entry is a real file name entry the walk checks without first
	 * descending into an index block.
	 */
	read_record(fd, L, FILE_Extend_record, rec);
	pos = le16(rec + 20);
	used = le32(rec + 24);
	L->extend_entry = 0;
	while (pos + 24 <= used) {
		unsigned int kind = le32(rec + pos), len = le32(rec + pos + 4);
		unsigned int value = pos + le16(rec + pos + AR_VALUE_OFFSET);

		if (kind == AT_END)
			break;
		require(len >= 24 && len <= used - pos, "attribute length");
		if (kind == AT_INDEX_ROOT && rec[pos + 9] == 4 &&
		    le16(rec + pos + 10) + sizeof(i30_name) <= len &&
		    !memcmp(rec + pos + le16(rec + pos + 10), i30_name,
			    sizeof(i30_name))) {
			require(value + IROOT_INDEX + 16 <= used,
				"index root bounds");
			eo = le32(rec + value + IROOT_INDEX +
				  IH_ENTRIES_OFFSET);
			require(value + IROOT_INDEX + eo + 16 <= used,
				"first entry bounds");
			L->extend_entry = L->mft_offset +
				(unsigned long long)FILE_Extend_record *
				L->record_size + value + IROOT_INDEX + eo;
			L->extend_entry_length = le16(rec + value +
						      IROOT_INDEX + eo +
						      IE_LENGTH);
			/* A leaf entry with a key, not the end entry. */
			require(!(rec[value + IROOT_INDEX + eo + 12] & 3),
				"$Extend first entry is not a leaf entry");
		}
		pos += len;
	}
	require(L->extend_entry, "missing $Extend $I30 index root");

	read_record(fd, L, FILE_Secure_record, rec);
	pos = le16(rec + 20);
	used = le32(rec + 24);
	L->secure_named_root = 0;
	while (pos + 24 <= used) {
		unsigned int kind = le32(rec + pos), len = le32(rec + pos + 4);

		if (kind == AT_END)
			break;
		require(len >= 24 && len <= used - pos, "attribute length");
		if (kind == AT_INDEX_ROOT && rec[pos + 9] && !rec[pos + 8]) {
			L->secure_named_root = L->mft_offset +
				(unsigned long long)FILE_Secure_record *
				L->record_size + pos;
			break;
		}
		pos += len;
	}
	require(L->secure_named_root, "missing named $Secure index root");

	read_record(fd, L, FILE_MFT_record, rec);
	L->mft_data_size = data_size_offset(rec, L, FILE_MFT_record, AT_DATA);
	L->mft_bitmap_size = data_size_offset(rec, L, FILE_MFT_record, AT_BITMAP);
	require(L->mft_data_size && L->mft_bitmap_size, "missing $MFT attributes");
	L->mft_data_alloc = le64(rec + (L->mft_data_size - L->mft_offset -
			AR_DATA_SIZE + AR_ALLOCATED_SIZE));

	read_record(fd, L, FILE_Bitmap_record, rec);
	L->lcn_bitmap_size = data_size_offset(rec, L, FILE_Bitmap_record, AT_DATA);
	require(L->lcn_bitmap_size, "missing $Bitmap data attribute");
}

enum damage {
	ROOT_ENTRY_LENGTH_BEYOND_ROOT,
	ROOT_ENTRY_LENGTH_ZERO,
	ROOT_ENTRIES_OFFSET_BEYOND_ROOT,
	ROOT_ENTRIES_OFFSET_MISALIGNED,
	ROOT_INDEX_BLOCK_SIZE_HUGE,
	MFT_BITMAP_SIZE_HUGE,
	BITMAP_SIZE_HUGE,
	BOOT_SECTORS_BEYOND_NTFS_LIMIT,
	MFT_DATA_ALLOCATED_SIZE_PARTIAL,
	MFT_BITMAP_TYPE_DATA,
	ROOT_INDEX_HEADER_BEYOND_RECORD,
	RECORD_ATTRS_OFFSET_AT_END,
	ATTR_NAME_OFFSET_BEYOND_RECORD,
	EXTEND_ENTRY_KEY_LENGTH_BEYOND_ENTRY,
};

static const struct {
	const char *name;
	enum damage kind;
	const char *what;
	int status_n;	/* -n: damage found, nothing repaired */
	int status_a;	/* -a: what the repair pass makes of it */
} cases[] = {
	{ "root_entry_length_beyond_root", ROOT_ENTRY_LENGTH_BEYOND_ROOT,
	  "an entry whose length runs past the entry table", 4, 1 },
	{ "root_entry_length_zero", ROOT_ENTRY_LENGTH_ZERO,
	  "an entry of length zero, which the walk cannot step over", 4, 1 },
	{ "root_entries_offset_beyond_root", ROOT_ENTRIES_OFFSET_BEYOND_ROOT,
	  "an entries_offset past the entry table", 4, 1 },
	{ "root_entries_offset_misaligned", ROOT_ENTRIES_OFFSET_MISALIGNED,
	  "an entries_offset that lands inside the first entry", 4, 1 },
	{ "root_index_block_size_huge", ROOT_INDEX_BLOCK_SIZE_HUGE,
	  "an index_block_size the block buffers would be sized from", 4, 1 },
	{ "mft_bitmap_size_huge", MFT_BITMAP_SIZE_HUGE,
	  "a $MFT/$BITMAP size larger than the volume", 4, 4 },
	{ "bitmap_size_huge", BITMAP_SIZE_HUGE,
	  "a $Bitmap size larger than the volume", 4, 4 },
	{ "boot_sectors_beyond_ntfs_limit", BOOT_SECTORS_BEYOND_NTFS_LIMIT,
	  "a boot sector describing more clusters than an NTFS volume can have",
	  4, 4 },
	{ "mft_data_allocated_size_partial", MFT_DATA_ALLOCATED_SIZE_PARTIAL,
	  "a $MFT/$DATA allocated_size half a cluster past its runs", 4, 1 },
	{ "mft_bitmap_type_data", MFT_BITMAP_TYPE_DATA,
	  "a second $MFT/$DATA extent overlapping the first", 4, 1 },
	{ "root_index_header_beyond_record", ROOT_INDEX_HEADER_BEYOND_RECORD,
	  "an index root entry table gigabytes past the record, read by the "
	  "hiberfil.sys lookup at mount", 4, 1 },
	{ "record_attrs_offset_at_end", RECORD_ATTRS_OFFSET_AT_END,
	  "an attrs_offset equal to the record size", 4, 4 },
	{ "attr_name_offset_beyond_record", ATTR_NAME_OFFSET_BEYOND_RECORD,
	  "a resident attribute name_offset of 0xffff", 4, 4 },
	{ "extend_entry_key_length_beyond_entry",
	  EXTEND_ENTRY_KEY_LENGTH_BEYOND_ENTRY,
	  "an entry of a missing inode whose key_length runs past the entry",
	  4, 1 },
};

/*
 * Write the damage of one case. Every field is written where the layout put
 * it, with the values the fuzzer found: the largest encodings of the width the
 * field has, or the smallest ones that break the walk.
 */
static void damage(const struct layout *L, enum damage kind, off_t *off,
		unsigned char *bytes, size_t *len)
{
	memset(bytes, 0, 16);
	*len = 0;
	*off = 0;
	switch (kind) {
	case ROOT_ENTRY_LENGTH_BEYOND_ROOT:
		*off = L->root_entry + IE_LENGTH;
		put16(bytes, 0xffff);
		*len = 2;
		break;
	case ROOT_ENTRY_LENGTH_ZERO:
		*off = L->root_entry + IE_LENGTH;
		*len = 2;
		break;
	case ROOT_ENTRIES_OFFSET_BEYOND_ROOT:
		*off = L->root_value + IROOT_INDEX + IH_ENTRIES_OFFSET;
		put32(bytes, 0xffff);
		*len = 4;
		break;
	case ROOT_ENTRIES_OFFSET_MISALIGNED:
		/* One 4-byte step into the first entry: still inside the table. */
		*off = L->root_value + IROOT_INDEX + IH_ENTRIES_OFFSET;
		put32(bytes, L->root_entries_offset + 4);
		*len = 4;
		break;
	case ROOT_INDEX_BLOCK_SIZE_HUGE:
		*off = L->root_value + 8;
		put32(bytes, 0xff001000);
		*len = 4;
		break;
	case MFT_BITMAP_SIZE_HUGE:
		*off = L->mft_bitmap_size;
		put64(bytes, 0xff00000000000008ULL);
		*len = 8;
		break;
	case BITMAP_SIZE_HUGE:
		*off = L->lcn_bitmap_size;
		put64(bytes, 0xffffff0000000040ULL);
		*len = 8;
		break;
	case BOOT_SECTORS_BEYOND_NTFS_LIMIT:
		/* number_of_sectors: the top byte, so the count is astronomic. */
		*off = 0x2f;
		bytes[0] = 0x1a;
		*len = 1;
		break;
	case MFT_DATA_ALLOCATED_SIZE_PARTIAL:
		/*
		 * The mount rounds allocated_size down to clusters and finds
		 * the single extent complete; the runlist decoder rounds it up
		 * and ends the runlist with one unmapped cluster. Reading the
		 * last $MFT records maps that cluster again from the same
		 * extent, whose runs overlap the mapped ones: the merge fails
		 * and the runlist of $MFT/$DATA must stay valid.
		 */
		*off = L->mft_data_size - AR_DATA_SIZE + AR_ALLOCATED_SIZE;
		put64(bytes, L->mft_data_alloc + L->cluster_size / 2);
		*len = 8;
		break;
	case MFT_BITMAP_TYPE_DATA:
		/*
		 * $MFT/$BITMAP retyped as $DATA: the mount reads it as a
		 * second unnamed $DATA extent at vcn 0, which overlaps the
		 * first, and must fail without freeing the mapped runlist.
		 */
		*off = L->mft_bitmap_size - AR_DATA_SIZE;
		put32(bytes, AT_DATA);
		*len = 4;
		break;
	case ROOT_INDEX_HEADER_BEYOND_RECORD:
		/* entries_offset and index_length, both near 4 GiB. */
		*off = L->root_value + IROOT_INDEX + IH_ENTRIES_OFFSET;
		put32(bytes, 0xf5f5f010);
		put32(bytes + 4, 0xf5f5f5f0);
		*len = 8;
		break;
	case RECORD_ATTRS_OFFSET_AT_END:
		*off = L->mft_offset + (off_t)FILE_reserved_record *
			L->record_size + MR_ATTRS_OFFSET;
		put16(bytes, L->record_size);
		*len = 2;
		break;
	case ATTR_NAME_OFFSET_BEYOND_RECORD:
		*off = L->secure_named_root + AR_NAME_OFFSET;
		put16(bytes, 0xffff);
		*len = 2;
		break;
	case EXTEND_ENTRY_KEY_LENGTH_BEYOND_ENTRY:
		/*
		 * indexed_file names a record past the end of the $MFT, so
		 * the entry is queued for removal with its key; the length
		 * is kept, key_length is far larger than the entry.
		 */
		*off = L->extend_entry;
		put64(bytes, 0x0001000000001901ULL);
		put16(bytes + IE_LENGTH, L->extend_entry_length);
		put16(bytes + IE_KEY_LENGTH, 0x4e00);
		*len = 12;
		break;
	}
	require(*len && *off >= 0, "damage offset");
	/* The update sequence tails keep the last two bytes of every sector. */
	require(*off % L->sector_size + *len <= L->sector_size - 2,
		"damage on a sector tail");
}

static void run_case(const struct layout *L, const char *name, enum damage
		kind, const char *what, int expected_n, int expected_a)
{
	/*
	 * -a runs with -f: damage to the root directory's index also hides
	 * hiberfil.sys, and ntfsck repairs a volume whose hibernation state it
	 * cannot verify only when forced.
	 */
	static const char *modes[] = { "-n", "-a" };
	char image[PATH_MAX], what_[256];
	unsigned char bytes[16];
	off_t off;
	size_t len;
	int fd, i;

	current = name;
	case_failed = 0;
	for (i = 0; i < 2; i++) {
		int status;
		char *argv_n[] = { ntfsck, (char *)"-n", image, NULL };
		char *argv_a[] = { ntfsck, (char *)"-a", (char *)"-f", image, NULL };
		char **argv = i ? argv_a : argv_n;

		path_in(image, work, "case.img");
		copy_file(pristine, image);
		damage(L, kind, &off, bytes, &len);
		fd = open(image, O_RDWR);
		require(fd >= 0 && pwrite(fd, bytes, len, off) == (ssize_t)len,
			"apply damage");
		close(fd);

		status = run(argv);
		snprintf(what_, sizeof(what_), "%s, %s: expected exit status "
			 "%d, got %d", what, modes[i],
			 i ? expected_a : expected_n, status);
		check(status == (i ? expected_a : expected_n), what_);
		snprintf(what_, sizeof(what_), "%s, %s: died from signal %d",
			 what, modes[i], status - 128);
		check(status < 128, what_);
		check(!strstr(output, "AddressSanitizer") &&
		      !strstr(output, "runtime error"),
		      "a memory error was reported");

		/* A repair must leave a volume that checks clean. */
		if (i && status == 1) {
			char *recheck[] = { ntfsck, "-n", image, NULL };

			snprintf(what_, sizeof(what_), "%s: -n after the repair "
				 "expected exit status 0", what);
			check(run(recheck) == 0, what_);
		}
	}
	if (!case_failed) {
		printf("PASS %s\n", current);
		passes++;
	}
	fflush(stdout);
}

int main(int argc, char **argv)
{
	char *mk[] = { mkntfs, "-F", "-Q", pristine, NULL };
	struct layout L;
	unsigned char boot[512];
	size_t i;
	int fd;

	for (i = 1; i + 1 < (size_t)argc; i += 2) {
		if (!strcmp(argv[i], "--build-dir"))
			require(realpath(argv[i + 1], build_dir) != NULL, "--build-dir");
		else if (!strcmp(argv[i], "--temp-dir"))
			require(realpath(argv[i + 1], temp_root) != NULL, "--temp-dir");
		else
			break;
	}
	if (i != (size_t)argc || !build_dir[0] || !temp_root[0]) {
		fprintf(stderr, "usage: %s --build-dir DIR --temp-dir DIR\n", argv[0]);
		return 2;
	}
	path_in(ntfsck, build_dir, "src/ntfsck");
	path_in(mkntfs, build_dir, "src/mkntfs");
	require(access(ntfsck, X_OK) == 0, ntfsck);
	require(access(mkntfs, X_OK) == 0, mkntfs);

	path_in(work, temp_root, "index-bounds-XXXXXX");
	require(mkdtemp(work) != NULL, "mkdtemp");
	path_in(pristine, work, "pristine.img");
	fd = open(pristine, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	require(fd >= 0 && ftruncate(fd, IMAGE_SIZE) == 0, "create image");
	close(fd);
	require(run(mk) == 0, "mkntfs");

	fd = open(pristine, O_RDONLY);
	require(fd >= 0, pristine);
	/* The clean image must check clean, or the cases prove nothing. */
	require(read(fd, boot, 512) == 512, "read boot sector");
	require(!memcmp(boot + 3, "NTFS    ", 8), "missing NTFS signature");
	find_layout(fd, &L);
	close(fd);
	{
		char *check_argv[] = { ntfsck, "-n", pristine, NULL };
		int status = run(check_argv);

		if (status != 0) {
			printf("FAIL setup: the fresh image does not check clean "
			       "(exit %d)\n---- output ----\n%s---- end ----\n",
			       status, output);
			return 2;
		}
	}

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		run_case(&L, cases[i].name, cases[i].kind, cases[i].what,
			 cases[i].status_n, cases[i].status_a);

	printf("%d of %zu cases passed\n", passes, sizeof(cases) / sizeof(cases[0]));
	return failures ? 1 : 0;
}
