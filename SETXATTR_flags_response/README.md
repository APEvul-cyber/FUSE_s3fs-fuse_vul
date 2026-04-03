# SETXATTR:flags — XATTR_CREATE/XATTR_REPLACE Semantics Broken in s3fs-fuse

## Vulnerability

s3fs-fuse checks `XATTR_CREATE`/`XATTR_REPLACE` flags at the S3 metadata header level instead of per-attribute name. This causes false `EEXIST` errors when creating new xattrs and false success when replacing non-existent xattrs.

## Files

| File | Description |
|------|-------------|
| `SETXATTR_flags_response.txt` | Original PoC analysis |
| `poc_setxattr_flags.sh` | Main PoC test script |
| `xattr_flags_test.c` | C test program for xattr flag verification |
| `create_bucket.py` | Helper script to create MinIO S3 bucket |
| `report_cve.md` | CVE report (GHSA style) |
| `report_issue.md` | GitHub Issue report |

## Environment Requirements

- Docker with `--privileged` or `--cap-add SYS_ADMIN --device /dev/fuse`
- Ubuntu 24.04 base image
- s3fs-fuse compiled from source
- MinIO as local S3 backend
- libfuse3 (for passthrough_ll baseline comparison)
- `gcc` for compiling xattr_flags_test.c

## How to Run

### 1. Build the Docker Environment

```bash
docker build -t fuse-poc-env .
docker run --rm --privileged --device /dev/fuse \
  --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
  -it fuse-poc-env bash
```

### 2. Inside the Container

```bash
# Start MinIO
minio server /data &
sleep 2

# Create the test bucket
python3 create_bucket.py testbucket

# Configure s3fs credentials
echo "minioadmin:minioadmin" > /root/.passwd-s3fs
chmod 600 /root/.passwd-s3fs

# Compile the xattr test program
gcc -o /tmp/xattr_flags_test xattr_flags_test.c

# Copy test files to expected locations
cp xattr_flags_test.c /tmp/
cp create_bucket.py /tmp/

# Run the PoC
bash poc_setxattr_flags.sh
```

### 3. Expected Output

The script tests xattr flag semantics on native filesystem (baseline), passthrough_ll (control), and s3fs-fuse (target).

**Vulnerable result (s3fs-fuse)**:
```
[FAIL] setxattr(XATTR_CREATE, different name)  (expected errno=0 OK, got errno=17 File exists)
[FAIL] setxattr(XATTR_REPLACE) on non-existing attr  (expected errno=61 No data available, got errno=0 OK)
VULNERABILITY CONFIRMED: setxattr flags semantics violated!
```
