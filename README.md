# Overview

ntfsprogs-plus project focus on filesystem utilities based on ntfs-3g project
to support kernel ntfs filesystem. ntfsprogs-plus takes some utilities from ntfs-3g only what it need.
(ntfs-3g consist of several useful utilities and user-level filesystem code using FUSE)

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
You should have GNU Build system (autoconf, automake, libtool) and some libraries
to build ntfsprogs-plus. If you don't have them, you should install them

For ubuntu
```
sudo apt install build-essential automake autoconf libtool
sudo apt install libgcrypt20-dev libasan8
```
For redhat
```
yum install automake autoconf libtool
yum install libgcrypt20-dev libasan8
```
If packages have the version number like as libgcrypt20-dev / libasan8,
you'd better to use 'search' command to find proper version of your system.
```
sudo apt search libgcrypt 	// For ubuntu series
sudo yum search libasan		// For redhat series
```

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

# Utilities Usage

## ntfsck
ntfs filesystem check utility.
You can show with '--help' option to view detail options.

Normally you may use '-a' option for automatic repair.
'-n' option represent that do check but not repair.
'-C' option return if the volume is dirty or clean.

```
ntfsck -a <device>
ntfsck -n <device>
ntfsck -C <device>
```
ntfsck include basic filesystem checking features, like as below:
- Boot sector check
- Meta system files check
- Inode and LCN Bitmap consistency check
- Inode structure check
  - Essential attribute check
  - Runlist check
  - Attribute list check
- Directory structure check
  - All checks for inode strcuture above
  - Directory index check
  - Directory index bitmap check
- Cluster duplication check : If found cluster duplication. it copied to new clusters.

## ntfsclone
ntfs disk dump utility.
It can clone NTFS to a sparse file, special ntfsclone image or standard output.
You may clone ntfs as an "image_file" with a ntfsclone image that clone only metadata of "device" by below command.
```
ntfsclone -s -O <image_file> -m --ignore-fs-check <device>
```
After cloning, you may restore dump file("dump_file") from ntfsclone image("image_file").
```
ntfsclone -r -O <dump_file> <image_file>
```
Now, you can check and analyze ntfs filesystem with "dump_file"

## ntfscluster
ntfs utiliy that find inodes that contains a specific clusters.
You can find inodes list that contains cluster described by "cluster range". You can also specify only one cluster to find inode include it.
```
ntfscluster -c <cluster range> <device>
```

## ntfsinfo
ntfsinfo show all attributes of specified inode.
You can look into more detail information of inode that consist of inode:
```
ntfsinfo -i <inode number> <device>
```

# License
ntfsprogs-plus is published under GPLv2 license.
