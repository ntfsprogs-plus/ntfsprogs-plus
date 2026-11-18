// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Volume flag bits outside VOLUME_FLAGS_MASK (0xc03f) must survive the
 * writes of the volume flags that ntfsck makes around a repair: marking
 * the volume dirty before it and clearing the dirty bit after it.
 *
 * Each case sets the flags of $Volume (record 3) in both the $MFT and the
 * $MFTMirr copy of a fresh image, runs the ntfsck of the build tree with
 * -a (stdin closed, 120 s limit), and reads both copies back.
 *
 * Build: cc -o test_volume_flags test_volume_flags.c
 * Usage: test_volume_flags --build-dir DIR --temp-dir DIR
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

#define IMAGE_SIZE		(64LL * 1024 * 1024)
#define VOLUME_RECORD		3	/* $Volume */
#define VOLUME_INFORMATION	0x70
#define FLAGS_OFFSET		10	/* reserved (8) + major (1) + minor (1) */
#define VOLUME_IS_DIRTY		0x0001
#define BIT_0080		0x0080	/* outside VOLUME_FLAGS_MASK */
#define BIT_0100		0x0100	/* outside VOLUME_FLAGS_MASK */
#define BIT_0200		0x0200	/* outside VOLUME_FLAGS_MASK */
#define RUN_TIMEOUT		120
#define OUTPUT_MAX		(1 << 20)

static char build_dir[PATH_MAX], temp_root[PATH_MAX], work[PATH_MAX];
static char pristine[PATH_MAX], ntfsck[PATH_MAX], mkntfs[PATH_MAX];
static char output[OUTPUT_MAX];
static int failures, passes, case_failed;
static const char *current;

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

/* Absolute offsets of the $Volume flags in the $MFT and $MFTMirr copies. */
static void flag_offsets(const char *image, off_t at[2])
{
	unsigned char boot[512], rec[4096], raw[4096];
	unsigned int sector, cluster, record;
	unsigned long long start[2];
	signed char code;
	int fd, copy;

	fd = open(image, O_RDONLY);
	require(fd >= 0 && pread(fd, boot, 512, 0) == 512, "read boot sector");
	require(!memcmp(boot + 3, "NTFS    ", 8), "missing NTFS signature");
	sector = le16(boot + 11);
	cluster = sector * boot[13];
	code = (signed char)boot[64];
	record = code < 0 ? 1u << -code : (unsigned int)code * cluster;
	require(record <= sizeof(rec), "record size");
	start[0] = le64(boot + 48) * cluster;
	start[1] = le64(boot + 56) * cluster;
	for (copy = 0; copy < 2; copy++) {
		unsigned long long base = start[copy] +
			(unsigned long long)VOLUME_RECORD * record;
		unsigned int usa, count, pos, used, i;

		require(pread(fd, raw, record, base) == (ssize_t)record, "read $Volume");
		require(!memcmp(raw, "FILE", 4), "missing $Volume FILE record");
		usa = le16(raw + 4);
		count = le16(raw + 6);
		require(count == record / sector + 1 && usa + count * 2 <= record,
			"update sequence bounds");
		memcpy(rec, raw, record);
		for (i = 1; i < count; i++) {
			unsigned int tail = i * sector - 2;

			require(!memcmp(raw + tail, raw + usa, 2), "update sequence tail");
			memcpy(rec + tail, raw + usa + 2 * i, 2);
		}
		pos = le16(rec + 20);
		used = le32(rec + 24);
		require(48 <= pos && pos < used && used <= record, "attribute bounds");
		at[copy] = 0;
		while (pos + 24 <= used) {
			unsigned int kind = le32(rec + pos), length = le32(rec + pos + 4);
			unsigned int value, off;

			if (kind == 0xffffffff)
				break;
			require(24 <= length && length <= used - pos, "attribute length");
			if (kind == VOLUME_INFORMATION) {
				require(rec[pos + 8] == 0, "non-resident volume information");
				require(le32(rec + pos + 16) == 12, "volume information size");
				value = le16(rec + pos + 20);
				require(24 <= value && value <= length - 12, "volume value bounds");
				off = pos + value + FLAGS_OFFSET;
				require(off % sector < sector - 2, "flags on a sector tail");
				at[copy] = base + off;
				break;
			}
			pos += length;
		}
		require(at[copy] != 0, "missing volume information");
	}
	close(fd);
}

static void read_flags(const char *image, unsigned int flags[2])
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

/* Set the flags in both copies, as both copies of a clean volume agree. */
static void set_flags(const char *image, unsigned int value)
{
	unsigned char v[2] = { value & 0xff, value >> 8 };
	off_t at[2];
	int fd, i;

	flag_offsets(image, at);
	fd = open(image, O_WRONLY);
	require(fd >= 0, image);
	for (i = 0; i < 2; i++)
		require(pwrite(fd, v, 2, at[i]) == 2, "write flags");
	close(fd);
}

/* Set `before`, run ntfsck -a, expect exit 0 and `after` in both copies. */
static void flags_case(unsigned int before, unsigned int after)
{
	char image[PATH_MAX], *argv[] = { ntfsck, "-a", image, NULL };
	unsigned int flags[2];
	char what[128];

	path_in(image, work, "case.img");
	copy_file(pristine, image);
	set_flags(image, before);
	read_flags(image, flags);
	require(flags[0] == before && flags[1] == before, "flags were not set");
	check(run(argv) == 0, "expected exit status 0");
	read_flags(image, flags);
	snprintf(what, sizeof(what), "$MFT copy: expected 0x%04x, found 0x%04x",
		 after, flags[0]);
	check(flags[0] == after, what);
	snprintf(what, sizeof(what), "$MFTMirr copy: expected 0x%04x, found 0x%04x",
		 after, flags[1]);
	check(flags[1] == after, what);
}

/* A dirty-only volume has no error or fix, so the exit status is 0. */
static void dirty_clear_keeps_bit_0080(void)
{
	flags_case(VOLUME_IS_DIRTY | BIT_0080, BIT_0080);
}

/* -a marks the volume dirty before any repair and clears it again. */
static void clean_volume_keeps_bit_0080(void)
{
	flags_case(BIT_0080, BIT_0080);
}

static void clean_volume_keeps_bits_0100_and_0200(void)
{
	flags_case(BIT_0100 | BIT_0200, BIT_0100 | BIT_0200);
}

/* The known dirty bit is cleared; the bits outside the mask stay. */
static void dirty_clear_keeps_bit_0200(void)
{
	flags_case(VOLUME_IS_DIRTY | BIT_0080 | BIT_0200, BIT_0080 | BIT_0200);
}

static const struct {
	const char *name;
	void (*fn)(void);
} cases[] = {
	{ "dirty_clear_keeps_bit_0080", dirty_clear_keeps_bit_0080 },
	{ "clean_volume_keeps_bit_0080", clean_volume_keeps_bit_0080 },
	{ "clean_volume_keeps_bits_0100_and_0200", clean_volume_keeps_bits_0100_and_0200 },
	{ "dirty_clear_keeps_bit_0200", dirty_clear_keeps_bit_0200 },
};

int main(int argc, char **argv)
{
	char *mk[] = { mkntfs, "-F", "-Q", pristine, NULL };
	unsigned int flags[2];
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

	path_in(work, temp_root, "volume-flags-XXXXXX");
	require(mkdtemp(work) != NULL, "mkdtemp");
	path_in(pristine, work, "pristine.img");
	fd = open(pristine, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	require(fd >= 0 && ftruncate(fd, IMAGE_SIZE) == 0, "create image");
	close(fd);
	require(run(mk) == 0, "mkntfs");
	read_flags(pristine, flags);
	require(flags[0] == 0 && flags[1] == 0, "fresh image is not clean");

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		current = cases[i].name;
		case_failed = 0;
		output[0] = '\0';
		cases[i].fn();
		if (!case_failed) {
			printf("PASS %s\n", current);
			passes++;
		}
		fflush(stdout);
	}
	printf("%d of %zu cases passed\n", passes, sizeof(cases) / sizeof(cases[0]));
	return failures ? 1 : 0;
}
