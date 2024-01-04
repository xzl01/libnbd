#!/usr/bin/env bash
# nbd client library in userspace
# Copyright Red Hat
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

. ../tests/functions.sh

set -e
set -x

requires cmp --version
requires dd --version
requires dd oflag=seek_bytes </dev/null
requires nbdkit --version
requires test -r /dev/urandom
requires test -r /dev/zero

file=copy-nbd-to-sparse-file.file
file2=copy-nbd-to-sparse-file.file2
cleanup_fn rm -f $file $file2

# Create a random partially sparse file.
touch $file
for i in `seq 1 100`; do
    dd if=/dev/urandom of=$file ibs=512 count=1 \
       oflag=seek_bytes seek=$((RANDOM * 9973)) conv=notrunc
    dd if=/dev/zero of=$file ibs=512 count=1 \
       oflag=seek_bytes seek=$((RANDOM * 9973)) conv=notrunc
done

# Apply nbdkit on top of the file, copy it and make sure that it
# doesn't get corrupted.
$VG nbdcopy -S 512 -- [ nbdkit --exit-with-parent file $file ] $file2

ls -ls $file $file2
cmp $file $file2
