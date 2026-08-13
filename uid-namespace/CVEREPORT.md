# s3fs-fuse: uid 0 bypasses object ACL

**Affected:** `check_object_access()` in `src/s3fs.cpp`.
**CWE:** CWE-250

`if (pcxt->uid == 0) return 0;` FUSE uid 0 from a user namespace is not host root.

## Reproduce

See `poc_test.sh`.

**Fix:** use mapped host UID; do not treat 0 as superuser under userns.