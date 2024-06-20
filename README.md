# Overview

ntfsprogs-plus project focus on filesystem utilities based on ntfs-3g project
to support kernel ntfs filesystem. ntfsprogs-plus takes only what it need from ntfs-3g.
(ntfs-3g support several useful utilities and user-level filesystem code using FUSE)

ntfs-3g was the only solution to support ntfs for free in linux. They also support several tools
to manage and debug ntfs filesystem like ntfsclone, ntfsinfo, ntfscluster. Those utilities are
very useful, but ntfs-3g does not support filesystem check utility.
They just support ntfsfix which is a utility that only fixes boot sector with mirror boot
sector, and a rare bug case of Windows XP (called by self-located MFT), reset journal.

So, ntfsprogs-plus try to implement checking filesystem utility which is named ntfsck.
You may think ntfsck is a linux version of chkdsk of Windows.
ntfsprogs-plus use a little modified ntfs-3g library for fsck.
ntfs-3g have some memory bugs and restriction. ntfsprogs-plus also try to remove memory bug and restriction.

At first release, ntfsck fully check filesystem and repair it. And not yet support journal replay.

# Build and Install
You can configure and set up build environment according to your condition.

If you're the first time to build ntfsprogs-plus, then you'd better to run 'autogen.sh'
```
$ ./autogen.sh
```
After that, you can build with make, if not configured, 'make' will execute configure command automatically.
```
$ make clean; make
$ make install
```

You can configure ntfsprogs-plus with address sanitizer like below.
```
$ CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -pg" LDFLAGS="-fsanitize=address -ldl" ./configure
```

And you may enable debug
```
$ configure --enable-debug
```

If you want to compile with arm cross compiler, you can also configure.
```
$ ./configure --host=arm-linux-gnueabi --target=arm-linux-gnueabi
```

# Test
'test' directory in github repository have some corrupted images.
Those images have basic and variable kinds of corruption.
test_fsck.sh script tests images automatically.

At first fsck is executed with auto repair mode, after that, fsck is executed with checking mode
with repaired image. If fsck is terminated with no error on checking mode,
you can consider corrupted image was repaired well.

# Added or modified features
## ntfsclone
## ntfspoke
## ntfscluster
## ntfsinfo

## ntfsck
usage:
```
ntfsck -a <device>
ntfsck -n <device>
ntfsck -C <device>
```

Boot sector check and repairing
Meta system files check and repairing
Inode and LCN Bitmap consistency check
Inode structure check - essential attribute check, runlist check, attribute list check
Directory structure check - include inode strcuture check, directory index check, directory index bitmap check
Cluster duplication check

# TODO
ntfsck does not check related with compress and encryption. And also do not support journal replay.
