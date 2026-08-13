#!/bin/bash
#
# PoC: FUSE setxattr XATTR_CREATE / XATTR_REPLACE flags bypass
# Tests s3fs-fuse (vulnerable) and passthrough_ll (control)
#
set -e

BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

banner() { echo -e "\n${BOLD}========== $1 ==========${NC}\n"; }

##############################################################################
# 1. Compile test program
##############################################################################
banner "Compiling xattr_flags_test"
gcc -o /tmp/xattr_flags_test /tmp/xattr_flags_test.c
echo "Compiled OK."

##############################################################################
# 2. Baseline: test on native ext4 / tmpfs (should pass all)
##############################################################################
banner "Baseline: native filesystem (tmpfs)"
mkdir -p /tmp/native_test
/tmp/xattr_flags_test /tmp/native_test/testfile || true
rm -rf /tmp/native_test

##############################################################################
# 3. Test passthrough_ll  (control — should pass all)
##############################################################################
banner "Testing: passthrough_ll (libfuse example)"
PTLL_SOURCE="/tmp/ptll_source"
PTLL_MNT="/tmp/ptll_mnt"
mkdir -p "$PTLL_SOURCE" "$PTLL_MNT"

/opt/libfuse/build/example/passthrough_ll \
    -o source="$PTLL_SOURCE" -o xattr \
    "$PTLL_MNT" &
PTLL_PID=$!
sleep 1

if mountpoint -q "$PTLL_MNT" 2>/dev/null || ls "$PTLL_MNT" >/dev/null 2>&1; then
    echo "passthrough_ll mounted at $PTLL_MNT"
    /tmp/xattr_flags_test "$PTLL_MNT/testfile_ptll" || true
    fusermount3 -u "$PTLL_MNT" 2>/dev/null || fusermount -u "$PTLL_MNT" 2>/dev/null || umount "$PTLL_MNT" 2>/dev/null
else
    echo -e "${RED}passthrough_ll mount failed${NC}"
fi
wait $PTLL_PID 2>/dev/null || true
rm -rf "$PTLL_SOURCE" "$PTLL_MNT"

##############################################################################
# 4. Test s3fs-fuse (expected to show vulnerability)
##############################################################################
banner "Testing: s3fs-fuse (MinIO backend)"
S3FS_MNT="/tmp/s3fs_mnt"
mkdir -p "$S3FS_MNT"

# Create bucket using AWS Sig V4 (entrypoint may fail to create it)
python3 /tmp/create_bucket.py testbucket 2>/dev/null || echo "Bucket creation note"

# Mount s3fs with xattr enabled
s3fs testbucket "$S3FS_MNT" \
    -o passwd_file=/root/.passwd-s3fs \
    -o url=http://localhost:9000 \
    -o use_path_request_style \
    -o use_xattr 2>&1
sleep 2

if mountpoint -q "$S3FS_MNT" 2>/dev/null; then
    echo "s3fs mounted at $S3FS_MNT"
    /tmp/xattr_flags_test "$S3FS_MNT/testfile_s3fs" || true
    fusermount3 -u "$S3FS_MNT" 2>/dev/null || fusermount -u "$S3FS_MNT" 2>/dev/null || umount -l "$S3FS_MNT" 2>/dev/null || true
else
    echo -e "${RED}s3fs mount failed${NC}"
fi
rm -rf "$S3FS_MNT"

banner "PoC Complete"