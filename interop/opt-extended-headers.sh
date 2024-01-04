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

# Test low-level nbd_opt_extended_headers() details with qemu-nbd

source ../tests/functions.sh
set -e
set -x

requires qemu-nbd --version
requires nbdinfo --can extended-headers -- [ qemu-nbd -r -f raw "$0" ]

# Run the test.
$VG ./opt-extended-headers qemu-nbd -r -f raw "$0"
