## ntfsplugs-plus
[ntfsprogs-plus](https://github.com/ntfsprogs-plus/ntfsprogs-plus)
is created as an official userspace utilities that contain all of
the standard utilities for creating and fixing and debugging ntfs filesystem
in linux system. This project was forked from ntfs-3g, and unnecessary fuse
and user-level ntfs filesystem codes were removed from ntfs-3g,
and ntfsck for repair function was implemented and added to this project.
Since users will use the ntfs kernel driver for the Linux kernel,
a new project consisting of only the necessary utilities has been launched.
And this software is licensed under the GNU General Public License Version 2.

## Building and Installing
Install prerequisite packages:
```
For Ubuntu:
    sudo apt-get install autoconf libtool pkg-config

For Fedora, RHEL:
    sudo yum install autoconf automake libtool
```

Build steps:
```sh
git clone https://github.com/ntfsprogs-plus/ntfsprogs-plus.git
cd ntfsprogs-plus

./autogen.sh
./configure

make
sudo make install

```
