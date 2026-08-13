# s3fs-fuse: XATTR_CREATE/REPLACE checked on the blob, not the name

**Affected:** `set_xattrs_to_header()`.
**CWE:** CWE-20

All xattrs live in one `x-amz-meta-xattr` header. CREATE fails with EEXIST if any xattr exists. REPLACE succeeds for a missing name if any xattr exists.

## Reproduce

See `poc_setxattr_flags.sh` / `xattr_flags_test.c`.

**Fix:** look up the attribute name inside the map, then apply CREATE/REPLACE.