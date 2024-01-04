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

requires nbdkit --exit-with-parent --version
requires cmp --version
requires dd --version
requires dd oflag=seek_bytes </dev/null
requires stat --version
requires test -r /dev/urandom
requires test -r /dev/zero
requires truncate --version

file=copy-file-to-nbd.file
file2=copy-file-to-nbd.file2
pidfile=copy-file-to-nbd.pid
sock=$(mktemp -u /tmp/libnbd-test-copy.XXXXXX)
cleanup_fn rm -f $file $file2 $pidfile $sock

# Create a random partially sparse file.
touch $file
for i in `seq 1 100`; do
    dd if=/dev/urandom of=$file ibs=512 count=1 \
       oflag=seek_bytes seek=$((RANDOM * 9973)) conv=notrunc
    dd if=/dev/zero of=$file ibs=512 count=1 \
       oflag=seek_bytes seek=$((RANDOM * 9973)) conv=notrunc
done
size="$( stat -c %s $file )"

nbdkit --exit-with-parent -f -v -P $pidfile -U $sock memory size=$size &
# Wait for the pidfile to appear.
for i in {1..60}; do
    if test -f $pidfile; then
        break
    fi
    sleep 1
done
if ! test -f $pidfile; then
    echo "$0: nbdkit did not start up"
    exit 1
fi

$VG nbdcopy $file "nbd+unix:///?socket=$sock"
$VG nbdcopy "nbd+unix:///?socket=$sock" $file2

ls -l $file $file2
cmp $file $file2
