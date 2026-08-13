/*
 * xattr_flags_test.c — PoC for FUSE setxattr flags (XATTR_CREATE/XATTR_REPLACE)
 *
 * Demonstrates that certain FUSE daemons ignore or mishandle the flags
 * parameter of setxattr(2), violating POSIX semantics.
 *
 * Build: gcc -o xattr_flags_test xattr_flags_test.c
 * Usage: ./xattr_flags_test <test_file_path>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>

#define XATTR_NAME_A  "user.test_label_a"
#define XATTR_NAME_B  "user.test_label_b"
#define VALUE_ORIG     "original_value"
#define VALUE_HACKED   "hacked_value"

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *desc, int got_errno, int expect_errno)
{
    if (got_errno == expect_errno) {
        printf("  [PASS] %s  (errno=%d %s)\n", desc, got_errno,
               got_errno ? strerror(got_errno) : "OK");
        g_pass++;
    } else {
        printf("  [FAIL] %s  (expected errno=%d %s, got errno=%d %s)\n",
               desc, expect_errno,
               expect_errno ? strerror(expect_errno) : "OK(0)",
               got_errno,
               got_errno ? strerror(got_errno) : "OK(0)");
        g_fail++;
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <test_file_path>\n", argv[0]);
        return 1;
    }

    const char *filepath = argv[1];

    int fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    write(fd, "test", 4);
    close(fd);

    printf("=== FUSE setxattr flags PoC ===\n");
    printf("Test file: %s\n\n", filepath);

    /*
     * Test 1: XATTR_CREATE on a non-existing xattr → should succeed (errno=0)
     */
    printf("[Test 1] XATTR_CREATE on non-existing xattr\n");
    {
        int ret = setxattr(filepath, XATTR_NAME_A, VALUE_ORIG,
                           strlen(VALUE_ORIG), XATTR_CREATE);
        int err = (ret == -1) ? errno : 0;
        check("setxattr(XATTR_CREATE) on new attr", err, 0);
    }

    /*
     * Test 2: XATTR_CREATE on the same xattr again → should fail with EEXIST
     */
    printf("[Test 2] XATTR_CREATE on already-existing xattr (same name)\n");
    {
        int ret = setxattr(filepath, XATTR_NAME_A, VALUE_HACKED,
                           strlen(VALUE_HACKED), XATTR_CREATE);
        int err = (ret == -1) ? errno : 0;
        check("setxattr(XATTR_CREATE) on existing attr", err, EEXIST);
    }

    /* Verify value was NOT overwritten */
    {
        char buf[256] = {0};
        ssize_t len = getxattr(filepath, XATTR_NAME_A, buf, sizeof(buf));
        if (len > 0) {
            buf[len] = '\0';
            if (strcmp(buf, VALUE_ORIG) == 0) {
                printf("  [INFO] Value preserved: \"%s\" (correct)\n", buf);
            } else {
                printf("  [WARN] Value changed to: \"%s\" (original was \"%s\") — flag was ignored!\n",
                       buf, VALUE_ORIG);
            }
        }
    }

    /*
     * Test 3: XATTR_CREATE on a different, non-existing xattr name
     *         when another xattr already exists → should succeed
     *         (s3fs bug: returns EEXIST because it checks header-level)
     */
    printf("[Test 3] XATTR_CREATE on new attr name (other xattrs exist)\n");
    {
        int ret = setxattr(filepath, XATTR_NAME_B, "new_value",
                           9, XATTR_CREATE);
        int err = (ret == -1) ? errno : 0;
        check("setxattr(XATTR_CREATE, different name)", err, 0);
    }

    /*
     * Test 4: XATTR_REPLACE on a non-existing xattr → should fail with ENODATA
     */
    printf("[Test 4] XATTR_REPLACE on non-existing xattr\n");
    {
        int ret = setxattr(filepath, "user.nonexistent", "value",
                           5, XATTR_REPLACE);
        int err = (ret == -1) ? errno : 0;
        check("setxattr(XATTR_REPLACE) on non-existing attr", err, ENODATA);
    }

    /*
     * Test 5: XATTR_REPLACE on an existing xattr → should succeed
     */
    printf("[Test 5] XATTR_REPLACE on existing xattr\n");
    {
        int ret = setxattr(filepath, XATTR_NAME_A, "replaced",
                           8, XATTR_REPLACE);
        int err = (ret == -1) ? errno : 0;
        check("setxattr(XATTR_REPLACE) on existing attr", err, 0);
    }

    printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);

    if (g_fail > 0) {
        printf("VULNERABILITY CONFIRMED: setxattr flags semantics violated!\n");
    } else {
        printf("All checks passed: flags are handled correctly.\n");
    }

    return g_fail > 0 ? 2 : 0;
}