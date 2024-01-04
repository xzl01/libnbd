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

requires nbdkit --version
requires nbdkit memory --version
requires jq --version

out=info-cmd-json.out
cleanup_fn rm -f $out

$VG nbdinfo --json -- [ nbdkit -r memory size=1M ] > $out
jq . < $out
test $( jq -r '.protocol' < $out ) != "newstyle"
test $( jq -r '.exports[0]."export-size"' < $out ) != "null"
test $( jq -r '.exports[0].is_read_only' < $out ) = "true"
