// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Exit status of ntfsck for failures before, during and after the repair
 * passes.
 *
 * An operational failure (open, lock, allocation, write) exits 8 and prints
 * neither the errors-left summary nor the clean line. Damage that a check
 * recorded and left exits 4 through the common summary, with the dirty flag
 * kept.
 *
 * Each case works on its own regular-file image in a temporary directory and
 * runs the real mkntfs and ntfsck of the build tree.
 *
 * This file builds two programs:
 *   cc -o test_failure_status test_failure_status.c
 *   cc -shared -fPIC -DFAILURE_STATUS_SHIM -o failure_status_shim.so \
 *      test_failure_status.c -ldl
 * The shim is process-wide by design: once ntfsck prints "Check system
 * files", it fails the next malloc or calloc of the process. With
 * FAILURE_STATUS_SHORT_WRITE=dev:ino:start:end:cut set, it fails no
 * allocation. Instead, the first write to that image which starts in
 * [start, end) and is longer than cut bytes writes cut bytes less, and the next
 * write to the image writes nothing. This is a write that the device ends
 * early without an error.
 *
 * Usage: test_failure_status --build-dir DIR --shim SO --temp-dir DIR
 *                            --corpus DIR
 * --corpus is the created_manually directory of the corrupted-image corpus.
 */
#define _GNU_SOURCE

#ifdef FAILURE_STATUS_SHIM

#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);

static int armed, fired;

static int fail_next(void)
{
	if (!armed || fired)
		return 0;
	fired = 1;
	/* A failed write of the marker only hides it; the fault still happens. */
	(void)!write(2, "ALLOC_FAULT\n", 12);
	errno = ENOMEM;
	return 1;
}

static void arm_on(const char *format)
{
	if (!armed && format && strstr(format, "Check system files") &&
	    !getenv("FAILURE_STATUS_SHORT_WRITE") &&
	    !getenv("FAILURE_STATUS_CRASH_AFTER"))
		armed = 1;
}

/* 0: waiting for the short write, 1: next write writes nothing, 2: done */
static int short_state;
static unsigned long long crash_count;
static ssize_t shim_pwrite(int fd, const void *buf, size_t count, off_t pos)
{
	static ssize_t (*real)(int, const void *, size_t, off_t);
	const char *spec = getenv("FAILURE_STATUS_SHORT_WRITE");
	unsigned long long dev, ino, start, end, cut;
	struct stat st;

	if (!real)
		real = (ssize_t (*)(int, const void *, size_t, off_t))
			dlsym(RTLD_NEXT, "pwrite64");
	if (spec && short_state < 2 &&
	    sscanf(spec, "%llu:%llu:%llu:%llu:%llu", &dev, &ino, &start, &end, &cut) == 5 &&
	    !fstat(fd, &st) && (unsigned long long)st.st_dev == dev &&
	    (unsigned long long)st.st_ino == ino) {
		if (short_state == 1) {
			short_state = 2;
			(void)!write(2, "SHORT_WRITE_END\n", 16);
			return 0;
		}
		if ((unsigned long long)pos >= start && (unsigned long long)pos < end &&
		    count > cut) {
			short_state = 1;
			(void)!write(2, "SHORT_WRITE\n", 12);
			return real(fd, buf, count - cut, pos);
		}
	}
	/*
	 * The n-th write in the range (the first for 0) completes, then the
	 * process dies.
	 */
	spec = getenv("FAILURE_STATUS_CRASH_AFTER");
	if (spec &&
	    sscanf(spec, "%llu:%llu:%llu:%llu:%llu", &dev, &ino, &start, &end, &cut) == 5 &&
	    !fstat(fd, &st) && (unsigned long long)st.st_dev == dev &&
	    (unsigned long long)st.st_ino == ino &&
	    (unsigned long long)pos >= start && (unsigned long long)pos < end &&
	    ++crash_count >= (cut ? cut : 1)) {
		ssize_t r = real(fd, buf, count, pos);

		(void)!write(2, "CRASH_AFTER_WRITE\n", 18);
		if (r == (ssize_t)count)
			kill(getpid(), SIGKILL);
		return r;
	}
	return real(fd, buf, count, pos);
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t pos)
{
	return shim_pwrite(fd, buf, count, pos);
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off_t pos)
{
	return shim_pwrite(fd, buf, count, pos);
}

/* Builds with _FORTIFY_SOURCE log through the _chk variants. */
int __vfprintf_chk(FILE *stream, int flag, const char *format, va_list ap)
{
	static int (*real)(FILE *, int, const char *, va_list);

	if (!real)
		real = (int (*)(FILE *, int, const char *, va_list))
			dlsym(RTLD_NEXT, "__vfprintf_chk");
	arm_on(format);
	return real(stream, flag, format, ap);
}

int __fprintf_chk(FILE *stream, int flag, const char *format, ...)
{
	va_list ap;
	int n;

	va_start(ap, format);
	n = __vfprintf_chk(stream, flag, format, ap);
	va_end(ap);
	return n;
}

int vfprintf(FILE *stream, const char *format, va_list ap)
{
	static int (*real)(FILE *, const char *, va_list);

	if (!real)
		real = (int (*)(FILE *, const char *, va_list))
			dlsym(RTLD_NEXT, "vfprintf");
	arm_on(format);
	return real(stream, format, ap);
}

int fprintf(FILE *stream, const char *format, ...)
{
	va_list ap;
	int n;

	va_start(ap, format);
	n = vfprintf(stream, format, ap);
	va_end(ap);
	return n;
}

void *malloc(size_t n)
{
	return fail_next() ? NULL : __libc_malloc(n);
}

void *calloc(size_t n, size_t m)
{
	return fail_next() ? NULL : __libc_calloc(n, m);
}

#else /* the test program */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#define IMAGE_SIZE		(64LL * 1024 * 1024)
#define MFTMIRR_RECORD		1	/* $MFTMirr */
#define ATTRDEF_RECORD		4	/* $AttrDef */
#define BITMAP_RECORD		6	/* $Bitmap */
#define VOLUME_RECORD		3	/* $Volume */
#define VOLUME_INFORMATION	0x70
#define FLAGS_OFFSET		10	/* reserved (8) + major (1) + minor (1) */
#define VOLUME_IS_DIRTY		0x0001
#define RUN_TIMEOUT		120	/* seconds per program run */
#define OUTPUT_MAX		(1 << 20)

static const char *CLEAN = "Clean, No errors found or left";

static char build_dir[PATH_MAX], shim[PATH_MAX], temp_root[PATH_MAX];
static char corpus[PATH_MAX], work[PATH_MAX], pristine[PATH_MAX];
static char ntfsck[PATH_MAX], mkntfs[PATH_MAX];
static char output[OUTPUT_MAX];
static int failures, passes, case_failed;
static const char *current;

/* Record a failed check of the current case (counted once); the case goes on. */
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

/* A setup step that must work, or the whole test cannot run. */
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

/*
 * Run argv with stdin from /dev/null, stdout and stderr into output[].
 * env (may be NULL) is a NULL-terminated list of "NAME=value" entries added
 * to the environment.
 * Returns the exit status, 128 + signal, or -1 when the run times out.
 */
static int run_env(char *const argv[], char *const env[])
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
		for (; env && *env; env++)
			if (putenv(*env))
				_exit(127);
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

static int run(char *const argv[], const char *extra_env)
{
	char *env[] = { (char *)extra_env, NULL };

	return run_env(argv, env);
}

static int run_ntfsck2(const char *a, const char *image, const char *env)
{
	char *argv[] = { ntfsck, (char *)a, (char *)image, NULL };

	return run(argv, env);
}

static int run_ntfsck3(const char *a, const char *b, const char *image)
{
	char *argv[] = { ntfsck, (char *)a, (char *)b, (char *)image, NULL };

	return run(argv, NULL);
}

static int has(const char *text)
{
	return strstr(output, text) != NULL;
}

/* "N errors left (errors:N, fixed:N)" at the start of a line. */
static int has_summary(void)
{
	const char *p = output;

	while ((p = strstr(p, " errors left (errors:"))) {
		const char *q = p;

		while (q > output && q[-1] >= '0' && q[-1] <= '9')
			q--;
		if (q < p && (q == output || q[-1] == '\n'))
			return 1;
		p++;
	}
	return 0;
}

static void assert_operational(void)
{
	check(!has("errors left"), "errors-left summary for an operational failure");
	check(!has(CLEAN), "clean line for an operational failure");
}

static void path_in(char *dst, const char *dir, const char *name)
{
	require(snprintf(dst, PATH_MAX, "%s/%s", dir, name) < PATH_MAX, "path length");
}

/* Copy src to dst, keeping all-zero 4 KiB blocks as holes. */
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

static void clone(char *dst, const char *name)
{
	path_in(dst, work, name);
	copy_file(pristine, dst);
}

static unsigned int le16(const unsigned char *p)
{
	return p[0] | p[1] << 8;
}

static unsigned long long le64(const unsigned char *p)
{
	unsigned long long v = 0;
	int i;

	for (i = 7; i >= 0; i--)
		v = v << 8 | p[i];
	return v;
}

struct geometry {
	unsigned int sector, cluster, record;
	unsigned long long mft, mirror;
};

static void geometry(const char *image, struct geometry *g)
{
	unsigned char boot[512];
	int fd = open(image, O_RDONLY);
	signed char code;

	require(fd >= 0 && pread(fd, boot, 512, 0) == 512, "read boot sector");
	close(fd);
	require(!memcmp(boot + 3, "NTFS    ", 8), "missing NTFS signature");
	g->sector = le16(boot + 11);
	g->cluster = g->sector * boot[13];
	code = (signed char)boot[64];
	g->record = code < 0 ? 1u << -code : (unsigned int)code * g->cluster;
	g->mft = le64(boot + 48) * g->cluster;
	g->mirror = le64(boot + 56) * g->cluster;
}

/* Absolute offsets of the $Volume flags in both MFT copies of record 3. */
static void flag_offsets(const char *image, off_t at[2])
{
	struct geometry g;
	unsigned char rec[4096], raw[4096];
	int fd, copy;

	geometry(image, &g);
	require(g.record <= sizeof(rec), "record size");
	fd = open(image, O_RDONLY);
	require(fd >= 0, image);
	for (copy = 0; copy < 2; copy++) {
		unsigned long long base = (copy ? g.mirror : g.mft) +
			(unsigned long long)VOLUME_RECORD * g.record;
		unsigned int usa, count, pos, used, i;

		require(pread(fd, raw, g.record, base) == (ssize_t)g.record, "read $Volume");
		require(!memcmp(raw, "FILE", 4), "missing $Volume FILE record");
		usa = le16(raw + 4);
		count = le16(raw + 6);
		require(count == g.record / g.sector + 1 && usa + count * 2 <= g.record,
			"update sequence bounds");
		memcpy(rec, raw, g.record);
		for (i = 1; i < count; i++) {
			unsigned int tail = i * g.sector - 2;

			require(!memcmp(raw + tail, raw + usa, 2), "update sequence tail");
			memcpy(rec + tail, raw + usa + 2 * i, 2);
		}
		pos = le16(rec + 20);
		used = rec[24] | rec[25] << 8 | rec[26] << 16 | (unsigned)rec[27] << 24;
		require(48 <= pos && pos < used && used <= g.record, "attribute bounds");
		at[copy] = 0;
		while (pos + 24 <= used) {
			unsigned int kind = rec[pos] | rec[pos + 1] << 8 |
				rec[pos + 2] << 16 | (unsigned)rec[pos + 3] << 24;
			unsigned int length = rec[pos + 4] | rec[pos + 5] << 8 |
				rec[pos + 6] << 16 | (unsigned)rec[pos + 7] << 24;
			unsigned int value, off;

			if (kind == 0xffffffff)
				break;
			require(24 <= length && length <= used - pos, "attribute length");
			if (kind == VOLUME_INFORMATION) {
				require(rec[pos + 8] == 0, "non-resident volume information");
				value = le16(rec + pos + 20);
				require(24 <= value && value <= length - 12, "volume value bounds");
				off = pos + value + FLAGS_OFFSET;
				require(off % g.sector < g.sector - 2, "flags on a sector tail");
				at[copy] = base + off;
				break;
			}
			pos += length;
		}
		require(at[copy] != 0, "missing volume information");
	}
	close(fd);
}

static void volume_flags(const char *image, unsigned int flags[2])
{
	unsigned char v[2];
	off_t at[2];
	int fd, i;

	flag_offsets(image, at);
	fd = open(image, O_RDONLY);
	require(fd >= 0, image);
	for (i = 0; i < 2; i++) {
		require(pread(fd, v, 2, at[i]) == 2, "read flags");
		flags[i] = le16(v);
	}
	close(fd);
}

static void set_dirty(const char *image)
{
	unsigned int flags[2];
	unsigned char v[2];
	off_t at[2];
	int fd, i;

	volume_flags(image, flags);
	flag_offsets(image, at);
	fd = open(image, O_WRONLY);
	require(fd >= 0, image);
	for (i = 0; i < 2; i++) {
		flags[i] |= VOLUME_IS_DIRTY;
		v[0] = flags[i] & 0xff;
		v[1] = flags[i] >> 8;
		require(pwrite(fd, v, 2, at[i]) == 2, "write flags");
	}
	close(fd);
}

/* Overwrite record `number` of the primary MFT with a bad signature. */
static void damage_record(const char *image, unsigned int number)
{
	struct geometry g;
	int fd;

	geometry(image, &g);
	fd = open(image, O_WRONLY);
	require(fd >= 0, image);
	require(pwrite(fd, "FAIL", 4, g.mft + (unsigned long long)number * g.record) == 4,
		"damage record");
	close(fd);
}

static unsigned int le32(const unsigned char *p)
{
	return p[0] | p[1] << 8 | p[2] << 16 | (unsigned int)p[3] << 24;
}

static void put_le(unsigned char *p, unsigned long long v, int bytes)
{
	int i;

	for (i = 0; i < bytes; i++, v >>= 8)
		p[i] = v & 0xff;
}

/* Read MFT record `number` from the copy at `base` and undo its fixups. */
static void read_record(int fd, const struct geometry *g, unsigned long long base,
			unsigned int number, unsigned char *rec)
{
	unsigned int usa, count, i;

	require(g->record <= 4096, "record size");
	require(pread(fd, rec, g->record, base + (unsigned long long)number * g->record) ==
		(ssize_t)g->record, "read record");
	require(!memcmp(rec, "FILE", 4), "missing FILE record");
	usa = le16(rec + 4);
	count = le16(rec + 6);
	require(count == g->record / g->sector + 1 && usa + count * 2 <= g->record,
		"update sequence bounds");
	for (i = 1; i < count; i++) {
		unsigned int tail = i * g->sector - 2;

		require(!memcmp(rec + tail, rec + usa, 2), "update sequence tail");
		memcpy(rec + tail, rec + usa + 2 * i, 2);
	}
}

/* Apply the fixups of `rec` again, with the same sequence number, and write it. */
static void write_record(int fd, const struct geometry *g, unsigned long long base,
			 unsigned int number, const unsigned char *rec)
{
	unsigned char raw[4096];
	unsigned int usa = le16(rec + 4), count = le16(rec + 6), i;

	memcpy(raw, rec, g->record);
	for (i = 1; i < count; i++) {
		unsigned int tail = i * g->sector - 2;

		memcpy(raw + usa + 2 * i, rec + tail, 2);
		memcpy(raw + tail, rec + usa, 2);
	}
	require(pwrite(fd, raw, g->record, base + (unsigned long long)number * g->record) ==
		(ssize_t)g->record, "write record");
}

/* Offset of the unnamed non-resident attribute of a type in a record. */
static unsigned int nonresident_attribute(const struct geometry *g,
					  const unsigned char *rec, unsigned int type)
{
	unsigned int pos = le16(rec + 20), used = le32(rec + 24);

	require(48 <= pos && pos < used && used <= g->record, "attribute bounds");
	while (pos + 24 <= used) {
		unsigned int kind = le32(rec + pos), length = le32(rec + pos + 4);

		if (kind == 0xffffffff)
			break;
		require(24 <= length && length <= used - pos, "attribute length");
		if (kind == type && rec[pos + 8] == 1 && rec[pos + 9] == 0)
			return pos;
		pos += length;
	}
	require(0, "missing non-resident attribute");
	return 0;
}

/* Offset of the unnamed non-resident $DATA attribute of a record. */
static unsigned int data_attribute(const struct geometry *g, const unsigned char *rec)
{
	return nonresident_attribute(g, rec, 0x80);
}

/* The one run of a $DATA attribute that fresh mkntfs writes as a single run. */
static void single_run(const unsigned char *rec, unsigned int attr,
		       unsigned long long *lcn, unsigned long long *length)
{
	const unsigned char *p = rec + attr + le16(rec + attr + 32);
	int ls = p[0] & 15, os = p[0] >> 4, i;

	require(ls && os && ls <= 8 && os <= 8, "mapping pairs header");
	*length = 0;
	*lcn = 0;
	for (i = ls - 1; i >= 0; i--)
		*length = *length << 8 | p[1 + i];
	for (i = os - 1; i >= 0; i--)
		*lcn = *lcn << 8 | p[1 + ls + i];
	require(p[1 + ls + os] == 0, "expected a single run");
}

/* Bytes of a signed value in a mapping pair. */
static int pair_bytes(long long v)
{
	int n = 1;

	while (n < 8 && (v < -(1LL << (8 * n - 1)) || v >= (1LL << (8 * n - 1))))
		n++;
	return n;
}

static int put_pair(unsigned char *p, long long length, long long delta)
{
	int ls = pair_bytes(length), os = pair_bytes(delta);

	p[0] = os << 4 | ls;
	put_le(p + 1, length, ls);
	put_le(p + 1 + ls, delta, os);
	return 1 + ls + os;
}

struct split {
	unsigned long long first_start, first_end;	/* bytes of the first run */
	unsigned long long second_start, second_end;	/* bytes of the second run */
};

/*
 * Make $UpCase a two-run file: the first half stays in place, the second half
 * moves to free clusters near the end of the volume, followed by two spare
 * allocated clusters. $Bitmap is updated to match. Then entry 'A' of the table
 * is damaged, so the next repair writes the whole table through both runs.
 */
static void split_upcase(const char *image, struct split *sp)
{
	struct geometry g;
	unsigned char rec[4096], *bitmap, *moved;
	unsigned long long bm_lcn, bm_len, lcn, len, first, second, target = 0, total;
	unsigned long long x;
	unsigned int attr, length, mpo, used, grow;
	unsigned char pairs[40];
	int fd, n;

	geometry(image, &g);
	total = (unsigned long long)IMAGE_SIZE / g.cluster;
	fd = open(image, O_RDWR);
	require(fd >= 0, image);

	read_record(fd, &g, g.mft, 6, rec);			/* $Bitmap */
	single_run(rec, data_attribute(&g, rec), &bm_lcn, &bm_len);
	bitmap = malloc(bm_len * g.cluster);
	require(bitmap != NULL, "malloc");
	require(pread(fd, bitmap, bm_len * g.cluster, bm_lcn * g.cluster) ==
		(ssize_t)(bm_len * g.cluster), "read $Bitmap");
#define IN_USE(c) (bitmap[(c) >> 3] >> ((c) & 7) & 1)

	read_record(fd, &g, g.mft, 10, rec);			/* $UpCase */
	attr = data_attribute(&g, rec);
	single_run(rec, attr, &lcn, &len);
	require(len >= 4, "$UpCase too small to split");
	first = len / 2;
	second = len - first + 2;
	for (x = total - second - 8; x > lcn + len + 4 && !target; x--) {
		unsigned long long c;

		for (c = x; c < x + second && !IN_USE(c); c++)
			;
		if (c == x + second)
			target = x;
	}
	require(target != 0, "no free clusters for the second run");

	moved = calloc(second, g.cluster);
	require(moved != NULL, "calloc");
	require(pread(fd, moved, (len - first) * g.cluster, (lcn + first) * g.cluster) ==
		(ssize_t)((len - first) * g.cluster), "read $UpCase tail");
	require(pwrite(fd, moved, second * g.cluster, target * g.cluster) ==
		(ssize_t)(second * g.cluster), "write $UpCase tail");
	free(moved);
	for (x = lcn + first; x < lcn + len; x++)
		bitmap[x >> 3] &= ~(1 << (x & 7));
	for (x = target; x < target + second; x++)
		bitmap[x >> 3] |= 1 << (x & 7);
#undef IN_USE
	require(pwrite(fd, bitmap, bm_len * g.cluster, bm_lcn * g.cluster) ==
		(ssize_t)(bm_len * g.cluster), "write $Bitmap");
	free(bitmap);

	n = put_pair(pairs, first, lcn);
	n += put_pair(pairs + n, second, (long long)target - (long long)lcn);
	pairs[n++] = 0;
	length = le32(rec + attr + 4);
	mpo = le16(rec + attr + 32);
	used = le32(rec + 24);
	if (mpo + n > length) {
		grow = (mpo + n - length + 7) & ~7u;
		require(used + grow <= g.record, "no room to grow $UpCase record");
		memmove(rec + attr + length + grow, rec + attr + length,
			used - attr - length);
		length += grow;
		put_le(rec + attr + 4, length, 4);
		put_le(rec + 24, used + grow, 4);
	}
	memset(rec + attr + mpo, 0, length - mpo);
	memcpy(rec + attr + mpo, pairs, n);
	put_le(rec + attr + 24, first + second - 1, 8);		/* highest VCN */
	put_le(rec + attr + 40, (first + second) * g.cluster, 8);	/* allocated */
	write_record(fd, &g, g.mft, 10, rec);

	require(pwrite(fd, "\x34\x12", 2, lcn * g.cluster + 'A' * 2) == 2,
		"damage $UpCase");
	close(fd);
	sp->first_start = lcn * g.cluster;
	sp->first_end = (lcn + first) * g.cluster;
	sp->second_start = target * g.cluster;
	sp->second_end = (target + second) * g.cluster;
}

/* Read `count` bytes at `pos` of an image into a new buffer. */
static unsigned char *read_range(const char *image, unsigned long long pos, size_t count)
{
	unsigned char *b = malloc(count);
	int fd = open(image, O_RDONLY);

	require(b != NULL && fd >= 0, "read range");
	require(pread(fd, b, count, pos) == (ssize_t)count, "read range");
	close(fd);
	return b;
}

/* Extract the one .img of a corpus case into its own directory. */
static void corpus_image(char *dst, const char *name)
{
	char dir[PATH_MAX], archive[PATH_MAX];
	char *tar[] = { "/bin/tar", "-xJf", archive, "-C", dir, NULL };
	struct dirent *e;
	DIR *d;
	int found = 0;

	require(corpus[0], "--corpus is required for corpus cases");
	require(snprintf(archive, sizeof(archive), "%s/%s/ntfs.img.tar.xz", corpus, name) <
		(int)sizeof(archive), "path length");
	require(access(archive, R_OK) == 0, archive);
	path_in(dir, work, name);
	require(mkdir(dir, 0700) == 0 || errno == EEXIST, dir);
	require(run(tar, NULL) == 0, "extract corpus image");
	d = opendir(dir);
	require(d != NULL, dir);
	while ((e = readdir(d))) {
		size_t n = strlen(e->d_name);

		if (n > 4 && !strcmp(e->d_name + n - 4, ".img")) {
			path_in(dst, dir, e->d_name);
			found++;
		}
	}
	closedir(d);
	require(found == 1, "expected one .img in the corpus archive");
}

static int same_file(const char *a, const char *b)
{
	char x[4096], y[4096];
	int fa = open(a, O_RDONLY), fb = open(b, O_RDONLY), same = 1;
	ssize_t n, m;

	require(fa >= 0 && fb >= 0, "open for compare");
	do {
		n = read(fa, x, sizeof(x));
		m = read(fb, y, sizeof(y));
		if (n != m || (n > 0 && memcmp(x, y, n)))
			same = 0;
	} while (same && n > 0);
	close(fa);
	close(fb);
	return same;
}

/* Operational failures: exit 8, no summary, no clean line. */

static void test_permission_denied(const char *mode, const char *mode2)
{
	char image[PATH_MAX];
	int rc;

	clone(image, mode2 ? "perm-af.img" : "perm-n.img");
	require(chmod(image, 0) == 0, "chmod 0");
	rc = mode2 ? run_ntfsck3(mode, mode2, image) : run_ntfsck2(mode, image, NULL);
	require(chmod(image, 0600) == 0, "chmod 0600");
	check(rc == 8, "expected exit status 8");
	assert_operational();
}

static void test_missing_image(void)
{
	char image[PATH_MAX];
	const char *modes[] = { "-n", "-a" };
	int i;

	path_in(image, work, "no-such-image.img");
	for (i = 0; i < 2; i++) {
		check(run_ntfsck2(modes[i], image, NULL) == 8, "expected exit status 8");
		assert_operational();
	}
}

static void test_locked_image(void)
{
	char image[PATH_MAX], c;
	const char *modes[] = { "-n", "-a" };
	int sync_pipe[2], i;
	pid_t holder;

	clone(image, "locked.img");
	require(!pipe(sync_pipe), "pipe");
	holder = fork();
	require(holder >= 0, "fork");
	if (!holder) {
		struct flock lock = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
		int fd = open(image, O_RDWR);

		if (fd < 0 || fcntl(fd, F_SETLK, &lock))
			_exit(1);
		if (write(sync_pipe[1], "L", 1) != 1)
			_exit(1);
		pause();
		_exit(0);
	}
	close(sync_pipe[1]);
	require(read(sync_pipe[0], &c, 1) == 1, "lock holder did not start");
	close(sync_pipe[0]);
	for (i = 0; i < 2; i++) {
		check(run_ntfsck2(modes[i], image, NULL) == 8, "expected exit status 8");
		assert_operational();
	}
	kill(holder, SIGKILL);
	waitpid(holder, NULL, 0);
}

static void test_failed_allocation(void)
{
	char image[PATH_MAX], env[PATH_MAX + 16];
	unsigned int flags[2];
	int rc;

	clone(image, "alloc.img");
	set_dirty(image);
	require(snprintf(env, sizeof(env), "LD_PRELOAD=%s", shim) < (int)sizeof(env),
		"path length");
	rc = run_ntfsck2("-y", image, env);
	check(has("ALLOC_FAULT"), "allocation fault was not reached");
	check(rc == 8, "expected exit status 8");
	assert_operational();
	volume_flags(image, flags);
	check(flags[0] == VOLUME_IS_DIRTY && flags[1] == VOLUME_IS_DIRTY,
	      "dirty flag was cleared after an incomplete check");
}

static void test_read_only_repair(void)
{
	char image[PATH_MAX], before[PATH_MAX];
	int rc;

	clone(image, "readonly.img");
	set_dirty(image);
	path_in(before, work, "readonly-before.img");
	copy_file(image, before);
	require(chmod(image, 0444) == 0, "chmod 0444");
	rc = run_ntfsck2("-a", image, NULL);
	require(chmod(image, 0600) == 0, "chmod 0600");
	check(rc == 8, "expected exit status 8");
	assert_operational();
	check(!has("fixed:1"), "a repair was reported on a read-only image");
	check(same_file(image, before), "read-only image changed");
}

/* Damage that is recorded and left: exit 4 through the summary. */

static void test_damaged_boot_sector(void)
{
	char image[PATH_MAX];

	corpus_image(image, "bs_total_sectors");
	check(run_ntfsck2("-n", image, NULL) == 4, "expected exit status 4");
	check(has_summary(), "no errors-left summary");
	check(!has(CLEAN), "clean line for a damaged volume");
}

/*
 * $LogFile (record 2) damaged. Repair mode cannot replay the journal and
 * stops before the scan; -n does not replay, reports that $LogFile could
 * not be checked and scans the volume read-only.
 */
static void test_damaged_journal(const char *mode, const char *mode2)
{
	char image[PATH_MAX], before[PATH_MAX];
	int rc;

	clone(image, mode2 ? "journal-af.img" : "journal-n.img");
	damage_record(image, 2);
	path_in(before, work, "journal-n-before.img");
	if (!mode2)
		copy_file(image, before);
	rc = mode2 ? run_ntfsck3(mode, mode2, image) : run_ntfsck2(mode, image, NULL);
	if (mode2) {
		check(has("Journal preserved"), "journal replay was not reached");
	} else {
		check(has("Cannot check $LogFile. Continuing with the read-only filesystem scan."),
		      "read-only scan was not reached");
		check(!has("Journal preserved"), "-n stopped at journal replay");
		check(same_file(image, before), "-n changed the image");
	}
	check(rc == 4, "expected exit status 4");
	check(has_summary(), "no errors-left summary");
	check(!has(CLEAN), "clean line for a damaged journal");
}

static void test_zero_link_count(void)
{
	char image[PATH_MAX];

	corpus_image(image, "mft_file_bad_link_count");
	check(run_ntfsck2("-n", image, NULL) == 4, "-n: expected exit status 4");
	check(has_summary(), "-n: no errors-left summary");
	check(!has(CLEAN), "-n: clean line for a zero link count");
	check(run_ntfsck2("-a", image, NULL) == 1, "-a: expected exit status 1 (repaired)");
	check(run_ntfsck2("-n", image, NULL) == 0, "recheck after the repair: expected 0");
}

/*
 * A repair write that the device ends early, without an error, on a file in
 * two runs. The write must stop there: data meant for the first run must not
 * be written into the second, and the run must not end as clean.
 */
static void test_short_write_on_split_file(void)
{
	char image[PATH_MAX], preload[PATH_MAX + 16], spec[160];
	char *env[] = { preload, spec, NULL };
	char *argv[] = { ntfsck, "-a", "-f", image, NULL };
	unsigned char *before, *after;
	unsigned int flags[2];
	struct geometry g;
	struct split sp;
	struct stat st;
	size_t second;
	int rc;

	clone(image, "short-write.img");
	geometry(image, &g);
	split_upcase(image, &sp);
	second = sp.second_end - sp.second_start;
	before = read_range(image, sp.second_start, second);
	require(stat(image, &st) == 0, "stat image");
	require(snprintf(preload, sizeof(preload), "LD_PRELOAD=%s", shim) <
		(int)sizeof(preload), "path length");
	require(snprintf(spec, sizeof(spec), "FAILURE_STATUS_SHORT_WRITE=%llu:%llu:%llu:%llu:%u",
		(unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
		sp.first_start, sp.first_end, g.cluster) < (int)sizeof(spec), "spec length");
	rc = run_env(argv, env);
	check(has("SHORT_WRITE\n"), "short write was not reached");
	check(rc == 8, "expected exit status 8");
	assert_operational();
	after = read_range(image, sp.second_start, second);
	check(!memcmp(before, after, second),
	      "data meant for the first run was written into the second run");
	free(before);
	free(after);
	volume_flags(image, flags);
	check((flags[0] & VOLUME_IS_DIRTY) && (flags[1] & VOLUME_IS_DIRTY),
	      "volume not marked dirty after a failed $UpCase repair");
	check(run_ntfsck2("-C", image, NULL) == 4, "-C: expected exit status 4 (dirty)");
}

/*
 * $Volume with a header error in both MFT copies that the check can repair.
 * The repair must fix the record in memory, check it again, and write it to
 * both copies.
 */
static void test_header_error_in_both_copies(void)
{
	char image[PATH_MAX];
	unsigned char rec[4096], copy[2][4096];
	struct geometry g;
	int fd, i;

	clone(image, "both-copies.img");
	geometry(image, &g);
	fd = open(image, O_RDWR);
	require(fd >= 0, image);
	for (i = 0; i < 2; i++) {
		unsigned long long base = i ? g.mirror : g.mft;

		read_record(fd, &g, base, VOLUME_RECORD, rec);
		put_le(rec + 28, g.record - 1, 4);		/* bytes allocated */
		write_record(fd, &g, base, VOLUME_RECORD, rec);
	}
	close(fd);
	check(run_ntfsck2("-n", image, NULL) == 4, "-n: expected exit status 4");
	check(has_summary(), "-n: no errors-left summary");
	check(run_ntfsck2("-a", image, NULL) == 1, "-a: expected exit status 1 (repaired)");
	fd = open(image, O_RDONLY);
	require(fd >= 0, image);
	read_record(fd, &g, g.mft, VOLUME_RECORD, copy[0]);
	read_record(fd, &g, g.mirror, VOLUME_RECORD, copy[1]);
	close(fd);
	check(le32(copy[0] + 28) == g.record && le32(copy[1] + 28) == g.record,
	      "bytes allocated not repaired in both copies");
	check(!memcmp(copy[0], copy[1], g.record), "the two copies differ after the repair");
	check(run_ntfsck2("-n", image, NULL) == 0, "recheck after the repair: expected 0");
}

/*
 * Both copies of $Volume have a header error, and the $MFT copy is also an
 * extent record (base_mft_record 5), which a system file never is. The
 * repair must use the mirror copy.
 */
static void test_both_copies_prefer_sound_mirror(void)
{
	char image[PATH_MAX];
	unsigned char rec[4096], copy[2][4096];
	struct geometry g;
	int fd, i;

	clone(image, "sound-mirror.img");
	geometry(image, &g);
	fd = open(image, O_RDWR);
	require(fd >= 0, image);
	for (i = 0; i < 2; i++) {
		unsigned long long base = i ? g.mirror : g.mft;

		read_record(fd, &g, base, VOLUME_RECORD, rec);
		put_le(rec + 28, g.record - 1, 4);		/* bytes allocated */
		if (!i)
			put_le(rec + 32, 5, 8);			/* base_mft_record */
		write_record(fd, &g, base, VOLUME_RECORD, rec);
	}
	close(fd);
	check(run_ntfsck2("-a", image, NULL) == 1, "-a: expected exit status 1 (repaired)");
	fd = open(image, O_RDONLY);
	require(fd >= 0, image);
	read_record(fd, &g, g.mft, VOLUME_RECORD, copy[0]);
	read_record(fd, &g, g.mirror, VOLUME_RECORD, copy[1]);
	close(fd);
	check(le64(copy[0] + 32) == 0 && le64(copy[1] + 32) == 0,
	      "the extent copy was written over $Volume");
	check(!memcmp(copy[0], copy[1], g.record), "the two copies differ after the repair");
	check(run_ntfsck2("-n", image, NULL) == 0, "recheck after the repair: expected 0");
}

/*
 * Both copies of $Volume have a header error and the mirror copy of
 * $MFTMirr differs from $MFT, which is rewritten first. $Volume must be
 * repaired, with the dirty flag, before that write; both are repaired.
 */
static void test_volume_repaired_before_other_mount_repairs(void)
{
	char image[PATH_MAX];
	unsigned char rec[4096];
	unsigned int flags[2];
	struct geometry g;
	int fd, i;

	clone(image, "volume-first.img");
	geometry(image, &g);
	fd = open(image, O_RDWR);
	require(fd >= 0, image);
	for (i = 0; i < 2; i++) {
		unsigned long long base = i ? g.mirror : g.mft;

		read_record(fd, &g, base, VOLUME_RECORD, rec);
		put_le(rec + 28, g.record - 1, 4);		/* bytes allocated */
		write_record(fd, &g, base, VOLUME_RECORD, rec);
	}
	read_record(fd, &g, g.mirror, MFTMIRR_RECORD, rec);
	put_le(rec + 8, 0x1234, 8);				/* LSN */
	write_record(fd, &g, g.mirror, MFTMIRR_RECORD, rec);
	close(fd);
	check(run_ntfsck2("-a", image, NULL) == 1, "-a: expected exit status 1 (repaired)");
	volume_flags(image, flags);
	check(!(flags[0] & VOLUME_IS_DIRTY) && !(flags[1] & VOLUME_IS_DIRTY),
	      "dirty flag left set after a complete repair");
	check(run_ntfsck2("-n", image, NULL) == 0, "recheck after the repair: expected 0");
}

/*
 * A repair during mount that the device ends early: here the mirror copy of
 * $MFTMirr differs from $MFT and its rewrite is cut short. The volume must
 * already be marked dirty on disk, so -C reports it.
 */
static void test_failed_mount_repair_leaves_volume_dirty(void)
{
	char image[PATH_MAX], preload[PATH_MAX + 16], spec[160];
	char *env[] = { preload, spec, NULL };
	char *argv[] = { ntfsck, "-a", image, NULL };
	unsigned char rec[4096];
	unsigned long long at;
	unsigned int flags[2];
	struct geometry g;
	struct stat st;
	int fd, rc;

	clone(image, "mount-repair.img");
	geometry(image, &g);
	fd = open(image, O_RDWR);
	require(fd >= 0, image);
	read_record(fd, &g, g.mirror, MFTMIRR_RECORD, rec);
	put_le(rec + 8, 0x1234, 8);				/* LSN */
	write_record(fd, &g, g.mirror, MFTMIRR_RECORD, rec);
	close(fd);
	at = g.mirror + (unsigned long long)MFTMIRR_RECORD * g.record;
	require(stat(image, &st) == 0, "stat image");
	require(snprintf(preload, sizeof(preload), "LD_PRELOAD=%s", shim) <
		(int)sizeof(preload), "path length");
	require(snprintf(spec, sizeof(spec), "FAILURE_STATUS_SHORT_WRITE=%llu:%llu:%llu:%llu:%u",
		(unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
		at, at + g.record, g.sector) < (int)sizeof(spec), "spec length");
	rc = run_env(argv, env);
	check(has("SHORT_WRITE\n"), "short write was not reached");
	check(rc == 8, "expected exit status 8");
	assert_operational();
	volume_flags(image, flags);
	check((flags[0] & VOLUME_IS_DIRTY) && (flags[1] & VOLUME_IS_DIRTY),
	      "volume not marked dirty after a failed mount repair");
	check(run_ntfsck2("-C", image, NULL) == 4, "-C: expected exit status 4 (dirty)");
}

/*
 * The $MFT copy of record 0 has no FILE magic, so $MFT is loaded from the
 * mirror and record 0 is rewritten before anything else; that write is cut
 * short. The volume must be marked dirty before it.
 */
static void test_failed_mft_load_repair_leaves_volume_dirty(void)
{
	char image[PATH_MAX], preload[PATH_MAX + 16], spec[160];
	char *env[] = { preload, spec, NULL };
	char *argv[] = { ntfsck, "-a", "-f", image, NULL };
	unsigned int flags[2];
	struct geometry g;
	struct stat st;
	int fd, rc;

	clone(image, "mft-load.img");
	geometry(image, &g);
	fd = open(image, O_WRONLY);
	require(fd >= 0, image);
	require(pwrite(fd, "XXXX", 4, g.mft) == 4, "damage $MFT record 0");
	close(fd);
	require(stat(image, &st) == 0, "stat image");
	require(snprintf(preload, sizeof(preload), "LD_PRELOAD=%s", shim) <
		(int)sizeof(preload), "path length");
	require(snprintf(spec, sizeof(spec), "FAILURE_STATUS_SHORT_WRITE=%llu:%llu:%llu:%llu:%u",
		(unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
		g.mft, g.mft + g.record, g.sector) < (int)sizeof(spec), "spec length");
	rc = run_env(argv, env);
	check(has("SHORT_WRITE\n"), "short write was not reached");
	check(rc == 8, "expected exit status 8");
	assert_operational();
	volume_flags(image, flags);
	check((flags[0] & VOLUME_IS_DIRTY) && (flags[1] & VOLUME_IS_DIRTY),
	      "volume not marked dirty after a failed $MFT repair");
	check(run_ntfsck2("-C", image, NULL) == 4, "-C: expected exit status 4 (dirty)");
}

/* LD_PRELOAD and fault specification for one image and byte range. */
static void fault_env(char *preload, size_t psize, char *spec, size_t ssize,
		      const char *name, const char *image, unsigned long long start,
		      unsigned long long end, unsigned long long arg)
{
	struct stat st;

	require(stat(image, &st) == 0, "stat image");
	require(snprintf(preload, psize, "LD_PRELOAD=%s", shim) < (int)psize,
		"path length");
	require(snprintf(spec, ssize, "%s=%llu:%llu:%llu:%llu:%llu", name,
		(unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
		start, end, arg) < (int)ssize, "spec length");
}

/* Overwrite the first cluster of $AttrDef; returns its byte range. */
static void damage_attrdef(const char *image, unsigned long long *start,
			   unsigned long long *end)
{
	unsigned char rec[4096], *zero;
	unsigned long long lcn, len;
	struct geometry g;
	int fd;

	geometry(image, &g);
	fd = open(image, O_RDWR);
	require(fd >= 0, image);
	read_record(fd, &g, g.mft, ATTRDEF_RECORD, rec);
	single_run(rec, data_attribute(&g, rec), &lcn, &len);
	zero = calloc(1, g.cluster);
	require(zero != NULL, "calloc");
	require(pwrite(fd, zero, g.cluster, lcn * g.cluster) == (ssize_t)g.cluster,
		"damage $AttrDef");
	free(zero);
	close(fd);
	*start = lcn * g.cluster;
	*end = (lcn + len) * g.cluster;
}

/*
 * $AttrDef is regenerated during mount, and that write is cut short. The
 * volume must already be marked dirty on disk, so -C reports it. Without the
 * fault the same damage is repaired and the volume ends clean.
 */
static void test_failed_attrdef_repair_leaves_volume_dirty(void)
{
	char image[PATH_MAX], preload[PATH_MAX + 16], spec[160];
	char *env[] = { preload, spec, NULL };
	char *argv[] = { ntfsck, "-a", image, NULL };
	unsigned long long start, end;
	unsigned int flags[2];
	struct geometry g;
	int rc;

	clone(image, "attrdef-control.img");
	damage_attrdef(image, &start, &end);
	check(run_ntfsck2("-a", image, NULL) == 1, "control: expected exit status 1 (repaired)");
	check(has("$AttrDef regenerated"), "control: $AttrDef was not regenerated");
	volume_flags(image, flags);
	check(!(flags[0] & VOLUME_IS_DIRTY) && !(flags[1] & VOLUME_IS_DIRTY),
	      "control: volume left dirty after the repair");
	check(run_ntfsck2("-n", image, NULL) == 0, "control: recheck expected 0");

	clone(image, "attrdef-short.img");
	geometry(image, &g);
	damage_attrdef(image, &start, &end);
	fault_env(preload, sizeof(preload), spec, sizeof(spec),
		  "FAILURE_STATUS_SHORT_WRITE", image, start, end, g.sector);
	rc = run_env(argv, env);
	check(has("SHORT_WRITE\n"), "short write was not reached");
	check(rc == 8, "expected exit status 8");
	assert_operational();
	volume_flags(image, flags);
	check((flags[0] & VOLUME_IS_DIRTY) && (flags[1] & VOLUME_IS_DIRTY),
	      "volume not marked dirty after a failed $AttrDef repair");
	check(run_ntfsck2("-C", image, NULL) == 4, "-C: expected exit status 4 (dirty)");
}

/* Set a wrong next attribute instance in the $Bitmap record. */
static void damage_next_instance(const char *image, const struct geometry *g)
{
	unsigned char rec[4096];
	unsigned int mirrored = g->cluster / g->record;
	int fd = open(image, O_RDWR);

	require(fd >= 0, image);
	read_record(fd, g, g->mft, BITMAP_RECORD, rec);
	require(le16(rec + 40) > 1, "next attribute instance");
	put_le(rec + 40, 1, 2);
	write_record(fd, g, g->mft, BITMAP_RECORD, rec);
	/* Keep both copies equal, so the copies agree when they are compared. */
	if (mirrored > BITMAP_RECORD)
		write_record(fd, g, g->mirror, BITMAP_RECORD, rec);
	close(fd);
}

static unsigned int next_instance(const char *image, const struct geometry *g)
{
	unsigned char rec[4096];
	int fd = open(image, O_RDONLY);

	require(fd >= 0, image);
	read_record(fd, g, g->mft, BITMAP_RECORD, rec);
	close(fd);
	return le16(rec + 40);
}

/*
 * The $Bitmap record has a wrong next attribute instance. Opening $Bitmap
 * during mount repairs the record and writes it, and that write is cut
 * short. The volume must already be marked dirty on disk, so -C reports it.
 * Without the fault the record is repaired and the volume ends clean.
 */
static void test_failed_record_repair_while_mounting_leaves_volume_dirty(void)
{
	char image[PATH_MAX], preload[PATH_MAX + 16], spec[160];
	char *env[] = { preload, spec, NULL };
	char *argv[] = { ntfsck, "-a", image, NULL };
	unsigned long long at;
	unsigned int flags[2], fresh;
	struct geometry g;
	int rc;

	clone(image, "next-instance-control.img");
	geometry(image, &g);
	fresh = next_instance(image, &g);
	damage_next_instance(image, &g);
	check(run_ntfsck2("-a", image, NULL) == 1, "control: expected exit status 1 (repaired)");
	check(next_instance(image, &g) == fresh, "control: record was not repaired");
	volume_flags(image, flags);
	check(!(flags[0] & VOLUME_IS_DIRTY) && !(flags[1] & VOLUME_IS_DIRTY),
	      "control: volume left dirty after the repair");
	check(run_ntfsck2("-n", image, NULL) == 0, "control: recheck expected 0");

	clone(image, "next-instance-short.img");
	damage_next_instance(image, &g);
	at = g.mft + (unsigned long long)BITMAP_RECORD * g.record;
	fault_env(preload, sizeof(preload), spec, sizeof(spec),
		  "FAILURE_STATUS_SHORT_WRITE", image, at, at + g.record, g.sector);
	rc = run_env(argv, env);
	check(has("SHORT_WRITE\n"), "short write was not reached");
	check(rc == 8, "expected exit status 8");
	assert_operational();
	volume_flags(image, flags);
	check((flags[0] & VOLUME_IS_DIRTY) && (flags[1] & VOLUME_IS_DIRTY),
	      "volume not marked dirty after a failed record repair while mounting");
	check(run_ntfsck2("-C", image, NULL) == 4, "-C: expected exit status 4 (dirty)");
}

/* Overwrite the OEM id of the boot sector; the backup boot sector is kept. */
static void damage_oem_id(const char *image)
{
	int fd = open(image, O_RDWR);

	require(fd >= 0, image);
	require(pwrite(fd, "XXXXXXXX", 8, 3) == 8, "damage boot sector");
	close(fd);
}

/*
 * The boot sector has a damaged OEM id, so it is rewritten from the backup
 * boot sector while mounting, and that write is cut short. The volume must
 * already be marked dirty on disk. Without the fault the boot sector is
 * rewritten and the volume ends clean.
 */
static void test_failed_boot_sector_repair_leaves_volume_dirty(void)
{
	char image[PATH_MAX], preload[PATH_MAX + 16], spec[160];
	char *env[] = { preload, spec, NULL };
	char *argv[] = { ntfsck, "-a", "-f", image, NULL };
	unsigned int flags[2];
	struct geometry g;
	int k, rc;

	for (k = 0; k < 2; k++) {
		clone(image, k ? "boot-short.img" : "boot-control.img");
		geometry(image, &g);
		damage_oem_id(image);
		if (!k) {
			check(run_ntfsck3("-a", "-f", image) == 1,
			      "control: expected exit status 1 (repaired)");
			check(has("Rewriting the bootsector"),
			      "control: boot sector was not rewritten");
			volume_flags(image, flags);
			check(!(flags[0] & VOLUME_IS_DIRTY) && !(flags[1] & VOLUME_IS_DIRTY),
			      "control: volume left dirty after the repair");
			check(run_ntfsck2("-n", image, NULL) == 0, "control: recheck expected 0");
			continue;
		}
		fault_env(preload, sizeof(preload), spec, sizeof(spec),
			  "FAILURE_STATUS_SHORT_WRITE", image, 0, g.sector, g.sector / 2);
		rc = run_env(argv, env);
		check(has("SHORT_WRITE\n"), "short write was not reached");
		check(rc == 8, "expected exit status 8");
		volume_flags(image, flags);
		check((flags[0] & VOLUME_IS_DIRTY) && (flags[1] & VOLUME_IS_DIRTY),
		      "volume not marked dirty after a failed boot sector repair");
		check(run_ntfsck2("-C", image, NULL) == 4, "-C: expected exit status 4 (dirty)");
	}
}

/* Clear the in-use flag of the $Bitmap record; its $MFT bitmap bit stays set. */
static void mark_bitmap_record_unused(const char *image, const struct geometry *g)
{
	unsigned char rec[4096];
	int fd = open(image, O_RDWR);

	require(fd >= 0, image);
	read_record(fd, g, g->mft, BITMAP_RECORD, rec);
	require(le16(rec + 22) & 1, "record in use");
	put_le(rec + 22, le16(rec + 22) & ~1u, 2);
	write_record(fd, g, g->mft, BITMAP_RECORD, rec);
	close(fd);
}

static unsigned int record_flags(const char *image, const struct geometry *g,
				 unsigned int number)
{
	unsigned char rec[4096];
	int fd = open(image, O_RDONLY);

	require(fd >= 0, image);
	read_record(fd, g, g->mft, number, rec);
	close(fd);
	return le16(rec + 22);
}

/*
 * The $Bitmap record is marked unused. Opening $Bitmap during mount marks it
 * used again and writes the $MFT bitmap at once, from inode open, not from a
 * record repair. The process dies right after that write completes. The
 * volume must already be marked dirty on disk, so -C reports it. Without the
 * crash the record is repaired and the volume ends clean.
 */
static void test_crash_after_first_mount_write_leaves_volume_dirty(void)
{
	char image[PATH_MAX], preload[PATH_MAX + 16], spec[160];
	char *env[] = { preload, spec, NULL };
	char *argv[] = { ntfsck, "-a", image, NULL };
	unsigned char rec[4096];
	unsigned long long lcn, len;
	unsigned int flags[2];
	struct geometry g;
	int fd, rc;

	clone(image, "unused-control.img");
	geometry(image, &g);
	mark_bitmap_record_unused(image, &g);
	check(run_ntfsck2("-a", image, NULL) == 1, "control: expected exit status 1 (repaired)");
	check(record_flags(image, &g, BITMAP_RECORD) & 1, "control: record still unused");
	volume_flags(image, flags);
	check(!(flags[0] & VOLUME_IS_DIRTY) && !(flags[1] & VOLUME_IS_DIRTY),
	      "control: volume left dirty after the repair");
	check(run_ntfsck2("-n", image, NULL) == 0, "control: recheck expected 0");

	clone(image, "unused-crash.img");
	mark_bitmap_record_unused(image, &g);
	fd = open(image, O_RDONLY);
	require(fd >= 0, image);
	read_record(fd, &g, g.mft, 0, rec);
	close(fd);
	single_run(rec, nonresident_attribute(&g, rec, 0xb0), &lcn, &len);
	fault_env(preload, sizeof(preload), spec, sizeof(spec),
		  "FAILURE_STATUS_CRASH_AFTER", image, lcn * g.cluster,
		  (lcn + len) * g.cluster, 0);
	rc = run_env(argv, env);
	check(has("CRASH_AFTER_WRITE\n"), "the $MFT bitmap write was not reached");
	check(rc == 128 + SIGKILL, "expected the run to be killed after the write");
	volume_flags(image, flags);
	check((flags[0] & VOLUME_IS_DIRTY) && (flags[1] & VOLUME_IS_DIRTY),
	      "volume not marked dirty before the first write while mounting");
	check(run_ntfsck2("-C", image, NULL) == 4, "-C: expected exit status 4 (dirty)");
}

/*
 * Each write of a repair in turn completes, and then the process dies.
 * Until the run clears the dirty flag at its end, the $MFT copy of $Volume
 * must be dirty after every one of them: no repair reaches the disk while
 * the volume is marked clean. The corpus image has a wrong link count in
 * the $MFT record, a repair that is kept in memory until the end.
 */
static void test_crash_after_each_write_leaves_volume_dirty(void)
{
	char source[PATH_MAX], image[PATH_MAX], preload[PATH_MAX + 16], spec[160];
	char what[128];
	char *env[] = { preload, spec, NULL };
	char *argv[] = { ntfsck, "-a", "-f", image, NULL };
	unsigned char dirty[256];
	unsigned int flags[2], k, total;

	corpus_image(source, "mft_file_bad_link_count");
	path_in(image, work, "each-write.img");
	for (k = 1; k < sizeof(dirty); k++) {
		copy_file(source, image);
		fault_env(preload, sizeof(preload), spec, sizeof(spec),
			  "FAILURE_STATUS_CRASH_AFTER", image, 0, ~0ULL, k);
		run_env(argv, env);
		if (!has("CRASH_AFTER_WRITE\n"))
			break;			/* the run ended before write k */
		volume_flags(image, flags);
		dirty[k] = flags[0] & VOLUME_IS_DIRTY;
	}
	require(k < sizeof(dirty), "too many writes");
	total = k - 1;
	check(total > 2, "expected repair writes before the flag is cleared");
	/* The last two writes clear the flag, in the $MFT and the mirror copy. */
	for (k = 1; k + 2 <= total; k++) {
		snprintf(what, sizeof(what), "volume not dirty after write %u of %u",
			 k, total);
		check(dirty[k], what);
	}
	check(!dirty[total], "the last write did not clear the flag");
}

static void run_case(const char *name, void (*fn)(void))
{
	current = name;
	case_failed = 0;
	output[0] = '\0';
	fn();
	if (!case_failed) {
		printf("PASS %s\n", name);
		passes++;
	}
	fflush(stdout);
}

static void permission_n(void) { test_permission_denied("-n", NULL); }
static void permission_af(void) { test_permission_denied("-a", "-f"); }
static void journal_n(void) { test_damaged_journal("-n", NULL); }
static void journal_af(void) { test_damaged_journal("-a", "-f"); }

static const struct {
	const char *name;
	void (*fn)(void);
} cases[] = {
	{ "permission_denied_with_n_is_operational", permission_n },
	{ "permission_denied_with_forced_repair_is_operational", permission_af },
	{ "missing_image_is_operational", test_missing_image },
	{ "image_locked_by_another_process_is_operational", test_locked_image },
	{ "failed_allocation_in_repair_passes_is_operational", test_failed_allocation },
	{ "repair_of_read_only_image_is_refused", test_read_only_repair },
	{ "damaged_boot_sector_with_n_reports_errors_left", test_damaged_boot_sector },
	{ "damaged_journal_with_n_scans_read_only", journal_n },
	{ "preserved_journal_with_forced_repair_reports_errors_left", journal_af },
	{ "zero_link_count_of_mft_is_left_with_n_and_repaired_with_a", test_zero_link_count },
	{ "short_write_on_a_split_file_stops_the_repair", test_short_write_on_split_file },
	{ "header_error_in_both_mft_copies_is_repaired", test_header_error_in_both_copies },
	{ "header_error_in_both_copies_uses_the_sound_mirror", test_both_copies_prefer_sound_mirror },
	{ "volume_is_repaired_before_other_mount_repairs", test_volume_repaired_before_other_mount_repairs },
	{ "failed_mount_repair_leaves_volume_dirty", test_failed_mount_repair_leaves_volume_dirty },
	{ "failed_mft_load_repair_leaves_volume_dirty", test_failed_mft_load_repair_leaves_volume_dirty },
	{ "failed_attrdef_repair_leaves_volume_dirty", test_failed_attrdef_repair_leaves_volume_dirty },
	{ "failed_record_repair_while_mounting_leaves_volume_dirty",
	  test_failed_record_repair_while_mounting_leaves_volume_dirty },
	{ "failed_boot_sector_repair_leaves_volume_dirty",
	  test_failed_boot_sector_repair_leaves_volume_dirty },
	{ "crash_after_first_mount_write_leaves_volume_dirty",
	  test_crash_after_first_mount_write_leaves_volume_dirty },
	{ "crash_after_each_write_leaves_volume_dirty",
	  test_crash_after_each_write_leaves_volume_dirty },
};

static void absolute(char *dst, const char *src, const char *what)
{
	require(realpath(src, dst) != NULL, what);
}

int main(int argc, char **argv)
{
	char *mk[] = { mkntfs, "-F", "-Q", "-s", "512", pristine, NULL };
	unsigned int flags[2];
	size_t i;
	int fd;

	for (i = 1; i + 1 < (size_t)argc; i += 2) {
		if (!strcmp(argv[i], "--build-dir"))
			absolute(build_dir, argv[i + 1], "--build-dir");
		else if (!strcmp(argv[i], "--shim"))
			absolute(shim, argv[i + 1], "--shim");
		else if (!strcmp(argv[i], "--temp-dir"))
			absolute(temp_root, argv[i + 1], "--temp-dir");
		else if (!strcmp(argv[i], "--corpus"))
			absolute(corpus, argv[i + 1], "--corpus");
		else
			break;
	}
	if (i != (size_t)argc || !build_dir[0] || !shim[0] || !temp_root[0]) {
		fprintf(stderr, "usage: %s --build-dir DIR --shim SO --temp-dir DIR"
			" [--corpus DIR]\n", argv[0]);
		return 2;
	}
	require(geteuid() != 0, "run as a normal user: root ignores file modes");
	path_in(ntfsck, build_dir, "src/ntfsck");
	path_in(mkntfs, build_dir, "src/mkntfs");
	require(access(ntfsck, X_OK) == 0, ntfsck);
	require(access(mkntfs, X_OK) == 0, mkntfs);

	path_in(work, temp_root, "failure-status-XXXXXX");
	require(mkdtemp(work) != NULL, "mkdtemp");
	path_in(pristine, work, "pristine.img");
	fd = open(pristine, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	require(fd >= 0 && ftruncate(fd, IMAGE_SIZE) == 0, "create image");
	close(fd);
	require(run(mk, NULL) == 0, "mkntfs");
	volume_flags(pristine, flags);
	require(flags[0] == 0 && flags[1] == 0, "fresh image is not clean");

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		run_case(cases[i].name, cases[i].fn);
	printf("%d of %zu cases passed\n", passes, sizeof(cases) / sizeof(cases[0]));
	return failures ? 1 : 0;
}

#endif /* FAILURE_STATUS_SHIM */
