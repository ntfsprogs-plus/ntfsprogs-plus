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
 * files", it fails the next malloc or calloc of the process.
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
#include <string.h>
#include <unistd.h>

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
	if (!armed && format && strstr(format, "Check system files"))
		armed = 1;
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
 * Run argv with stdin from /dev/null, stdout and stderr into output[].
 * extra_env (may be NULL) is one "NAME=value" added to the environment.
 * Returns the exit status, 128 + signal, or -1 when the run times out.
 */
static int run(char *const argv[], const char *extra_env)
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
		if (extra_env && putenv((char *)extra_env))
			_exit(127);
		setenv("LC_ALL", "C", 1);
		execv(argv[0], argv);
		_exit(127);
	}
	close(pipefd[1]);
	fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
	for (;;) {
		ssize_t n = read(pipefd[0], output + used,
				 sizeof(output) - 1 - used);

		if (n > 0) {
			used += n;
			if (used == sizeof(output) - 1)
				used = 0;	/* keep only the newest text */
			continue;
		}
		if (waitpid(pid, &status, WNOHANG) == pid)
			break;
		if (time(NULL) - start > RUN_TIMEOUT) {
			kill(pid, SIGKILL);
			waitpid(pid, &status, 0);
			close(pipefd[0]);
			output[used] = '\0';
			return -1;
		}
		usleep(10000);
	}
	/* Collect what was written just before the exit. */
	for (;;) {
		ssize_t n = read(pipefd[0], output + used,
				 sizeof(output) - 1 - used);

		if (n <= 0 || used + n >= sizeof(output) - 1)
			break;
		used += n;
	}
	close(pipefd[0]);
	output[used] = '\0';
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 128 + WTERMSIG(status);
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
