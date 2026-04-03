# setxattr XATTR_CREATE/XATTR_REPLACE flags checked at header level instead of per-attribute name

`set_xattrs_to_header()` in `src/s3fs.cpp` (~line 3868) checks `XATTR_CREATE`/`XATTR_REPLACE` against the existence of the `x-amz-meta-xattr` S3 metadata header as a whole, rather than against the specific attribute name being set. This produces two incorrect behaviors when a file already has at least one xattr:

1. `setxattr(path, "user.b", ..., XATTR_CREATE)` returns `EEXIST` even though `user.b` does not exist — only `user.a` does.
2. `setxattr(path, "user.ghost", ..., XATTR_REPLACE)` returns success even though `user.ghost` does not exist (should return `ENODATA`).

## Steps to Reproduce

```bash
# Mount s3fs against any S3-compatible backend
s3fs testbucket /mnt/s3 \
  -o passwd_file=~/.passwd-s3fs \
  -o url=http://localhost:9000 \
  -o use_path_request_style

# Create test file with one xattr
touch /mnt/s3/testfile
setfattr -n user.a -v "value_a" /mnt/s3/testfile
```

Compile and run the following test program:

```c
#include <sys/xattr.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(void) {
    const char *path = "/mnt/s3/testfile";
    int ret;

    // Test 1: XATTR_CREATE a different attr name
    errno = 0;
    ret = setxattr(path, "user.b", "val", 3, XATTR_CREATE);
    printf("XATTR_CREATE user.b (new name): ret=%d errno=%d (%s)\n",
           ret, errno, ret ? strerror(errno) : "success");

    // Test 2: XATTR_REPLACE a non-existent attr
    errno = 0;
    ret = setxattr(path, "user.ghost", "val", 3, XATTR_REPLACE);
    printf("XATTR_REPLACE user.ghost (non-existent): ret=%d errno=%d (%s)\n",
           ret, errno, ret ? strerror(errno) : "success");

    return 0;
}
```

## Expected Behavior

- `XATTR_CREATE user.b`: success (attribute `user.b` does not exist, only `user.a` does)
- `XATTR_REPLACE user.ghost`: `ENODATA` (attribute `user.ghost` does not exist)

## Actual Behavior

- `XATTR_CREATE user.b`: `EEXIST`
- `XATTR_REPLACE user.ghost`: success

## Affected Code

`src/s3fs.cpp`, function `set_xattrs_to_header()`, around lines 3868–3898:

```cpp
if(meta.cend() == (iter = meta.find("x-amz-meta-xattr"))){
    if(XATTR_REPLACE == (flags & XATTR_REPLACE)){
        return -ENOATTR;
    }
}else{
    if(XATTR_CREATE == (flags & XATTR_CREATE)){
        return -EEXIST;   // checks whole header, not per-name
    }
}
```

The `x-amz-meta-xattr` header is a serialized blob containing all xattrs. The flag check tests the blob's existence, not whether the specific named attribute exists within it.

## Suggested Fix

Deserialize the xattr blob first, then check whether the target name exists:

```cpp
xattrs_t xattrs;
if(meta.find("x-amz-meta-xattr") != meta.end()){
    S3fsCurl::deserialize_xattrs(meta["x-amz-meta-xattr"], xattrs);
}

bool name_exists = (xattrs.find(name) != xattrs.end());

if((flags & XATTR_CREATE) && name_exists){
    return -EEXIST;
}
if((flags & XATTR_REPLACE) && !name_exists){
    return -ENOATTR;
}
```

---

**Full PoC and scripts**: [GitHub Repository](https://github.com/APEvul-cyber/FUSE_s3fs-fuse_vul/tree/main/SETXATTR_flags_response)
