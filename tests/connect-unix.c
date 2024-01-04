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

/* Test connecting over a Unix domain socket. */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <libnbd.h>

#define PIDFILE "connect-unix.pid"

int
main (int argc, char *argv[])
{
  char socket[] = "/tmp/connect-unix-sock-XXXXXX";
  struct nbd_handle *nbd;
  pid_t pid;
  size_t i;
  char *actual_uri, *expected_uri;

  if (mkstemp (socket) == -1) {
    perror (socket);
    exit (EXIT_FAILURE);
  }

  unlink (socket);
  unlink (PIDFILE);

  pid = fork ();
  if (pid == -1) {
    perror ("fork");
    exit (EXIT_FAILURE);
  }
  if (pid == 0) {
    execlp ("nbdkit",
            "nbdkit", "-f", "-U", socket, "-P", PIDFILE,
            "--exit-with-parent", "null", NULL);
    perror ("nbdkit");
    _exit (EXIT_FAILURE);
  }

  /* Wait for nbdkit to start listening. */
  for (i = 0; i < 60; ++i) {
    if (access (PIDFILE, F_OK) == 0)
      break;
    sleep (1);
  }
  unlink (PIDFILE);

  nbd = nbd_create ();
  if (nbd == NULL) {
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  }

  if (nbd_connect_unix (nbd, socket) == -1) {
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  }

  if (nbd_supports_uri (nbd) == 1) {
    /* libnbd should be able to construct a URI for this connection. */
    if (asprintf (&expected_uri, "nbd+unix:///?socket=%s", socket) == -1) {
      perror ("asprintf");
      exit (EXIT_FAILURE);
    }
    actual_uri = nbd_get_uri (nbd);
    if (actual_uri == NULL) {
      fprintf (stderr, "%s\n", nbd_get_error ());
      exit (EXIT_FAILURE);
    }
    if (strcmp (actual_uri, expected_uri) != 0) {
      fprintf (stderr, "%s: actual URI %s != expected URI %s\n",
               argv[0], actual_uri, expected_uri);
      exit (EXIT_FAILURE);
    }
    free (actual_uri);
    free (expected_uri);
  }

  if (nbd_shutdown (nbd, 0) == -1) {
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  }

  nbd_close (nbd);
  unlink (socket);
  exit (EXIT_SUCCESS);
}
