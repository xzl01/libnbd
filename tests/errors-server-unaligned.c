/* NBD client library in userspace
 * Copyright Red Hat
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* Deliberately provoke some errors and check the error messages from
 * nbd_get_error etc look reasonable.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>

#include <libnbd.h>

#include "requires.h"

static char *progname;
static char buf[512];

static void
check (int experr, const char *prefix)
{
  const char *msg = nbd_get_error ();
  int errnum = nbd_get_errno ();

  fprintf (stderr, "error: \"%s\"\n", msg);
  fprintf (stderr, "errno: %d (%s)\n", errnum, strerror (errnum));
  if (strncmp (msg, prefix, strlen (prefix)) != 0) {
    fprintf (stderr, "%s: test failed: missing context prefix: %s\n",
             progname, msg);
    exit (EXIT_FAILURE);
  }
  if (errnum != experr) {
    fprintf (stderr, "%s: test failed: "
             "expected errno = %d (%s), but got %d\n",
             progname, experr, strerror (experr), errnum);
    exit (EXIT_FAILURE);
  }
}

static void
check_server_fail (struct nbd_handle *h, int64_t cookie,
                   const char *cmd, int experr)
{
  int r;

  if (cookie == -1) {
    fprintf (stderr, "%s: test failed: %s not sent to server\n",
             progname, cmd);
    exit (EXIT_FAILURE);
  }

  while ((r = nbd_aio_command_completed (h, cookie)) == 0) {
    if (nbd_poll (h, -1) == -1) {
      fprintf (stderr, "%s: test failed: poll failed while awaiting %s: %s\n",
               progname, cmd, nbd_get_error ());
      exit (EXIT_FAILURE);
    }
  }

  if (r != -1) {
    fprintf (stderr, "%s: test failed: %s did not fail at server\n",
             progname, cmd);
    exit (EXIT_FAILURE);
  }
  check (experr, "nbd_aio_command_completed: ");
}

int
main (int argc, char *argv[])
{
  struct nbd_handle *nbd;
  const char *cmd[] = {
    "nbdkit", "-s", "-v", "--exit-with-parent",
    "memory", "1024",
    "--filter=blocksize-policy", "blocksize-minimum=512",
    "blocksize-error-policy=error",
    NULL
  };
  uint32_t strict;

  progname = argv[0];

  requires ("nbdkit --version --filter=blocksize-policy null");

  nbd = nbd_create ();
  if (nbd == NULL) {
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  }

  /* Connect to the server. */
  if (nbd_connect_command (nbd, (char **)cmd) == -1) {
    fprintf (stderr, "%s: %s\n", argv[0], nbd_get_error ());
    exit (EXIT_FAILURE);
  }

  /* For debugging purposes, print the block size constraints exported
   * by nbdkit.
   */
  printf ("server block size minimum: %" PRId64 "\n",
          nbd_get_block_size (nbd, LIBNBD_SIZE_MINIMUM));
  printf ("server block size preferred: %" PRId64 "\n",
          nbd_get_block_size (nbd, LIBNBD_SIZE_PREFERRED));
  printf ("server block size maximum: %" PRId64 "\n",
          nbd_get_block_size (nbd, LIBNBD_SIZE_MAXIMUM));
  printf ("libnbd payload size maximum: %" PRId64 "\n",
          nbd_get_block_size (nbd, LIBNBD_SIZE_PAYLOAD));
  fflush (stdout);

  /* Send an unaligned read, server-side */
  strict = nbd_get_strict_mode (nbd) & ~LIBNBD_STRICT_ALIGN;
  if (nbd_set_strict_mode (nbd, strict) == -1) {
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  }
  check_server_fail (nbd,
                     nbd_aio_pread (nbd, buf, 1, 1, NBD_NULL_COMPLETION, 0),
                     "unaligned nbd_aio_pread", EINVAL);

  nbd_close (nbd);
  exit (EXIT_SUCCESS);
}
