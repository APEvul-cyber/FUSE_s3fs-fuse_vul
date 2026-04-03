# check_object_access() unconditionally bypasses permission checks for uid==0

s3fs-fuse's `check_object_access()` function in `src/s3fs.cpp` unconditionally skips all access control checks when `fuse_in_header.uid == 0`. In Linux user namespace environments (rootless Docker, Kubernetes with `userns` remapping, podman), the container-local `uid=0` is mapped to an unprivileged host UID, but s3fs still grants unrestricted access to all S3 objects.

This allows any process running as `uid=0` inside a user namespace to read, modify, and delete all files on the s3fs mount, regardless of the files' ownership and permission bits.

## Steps to Reproduce

1. Mount s3fs with `allow_other` on the host:

```bash
s3fs testbucket /mnt/s3 \
  -o passwd_file=~/.passwd-s3fs \
  -o url=http://localhost:9000 \
  -o use_path_request_style \
  -o allow_other
```

2. Create a file owned by uid 500 with restrictive permissions:

```bash
echo "sensitive" > /mnt/s3/secret.txt
chown 500:500 /mnt/s3/secret.txt
chmod 600 /mnt/s3/secret.txt
```

3. From a rootless container (e.g., `podman run --userns=auto`), attempt to read the file as container `uid=0`:

```bash
cat /mnt/s3/secret.txt
# Succeeds — should be denied
```

4. For comparison, try as a non-zero UID inside the container:

```bash
su -s /bin/sh nobody -c "cat /mnt/s3/secret.txt"
# Correctly denied
```

## Expected Behavior

Container `uid=0` (mapped to unprivileged host UID) should be subject to normal POSIX permission checks and denied access to files owned by other UIDs with mode `600`.

## Actual Behavior

Container `uid=0` is granted full access to all files, bypassing all permission checks. The `check_object_access()` function returns immediately with success for any request where `uid==0`.

## Affected Code

`src/s3fs.cpp`, function `check_object_access()`, around line 673:

```cpp
if(0 == pcxt->uid){
    // root is allowed all accessing.
    return 0;
}
```

This function is called from at least 59 call sites covering all file operations (open, read, write, unlink, mkdir, rename, chmod, chown, getattr, readdir, etc.).

## Suggested Fix

Remove the blanket `uid==0` bypass or gate it behind a namespace-awareness check:

```cpp
// Option 1: Remove the bypass entirely, enforce permission bits for all UIDs
// (most secure, consistent with least-privilege)

// Option 2: Only allow bypass if the caller is verified host root
if(0 == pcxt->uid){
    // Check if this uid=0 comes from an unprivileged user namespace
    // by inspecting /proc/<pid>/status Uid line or using
    // namespace-aware credential verification
    if(!is_namespace_root(pcxt->pid)){
        // Fall through to normal permission checks
    } else {
        return 0;
    }
}
```
