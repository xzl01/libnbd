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

/* Test metadata context "base:allocation". */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>

#include <libnbd.h>

#define BOGUS_CONTEXT "x-libnbd:nosuch"

static int check_extent32 (void *data, const char *metacontext,
                           uint64_t offset,
                           uint32_t *entries, size_t nr_entries, int *error);

static int check_extent64 (void *data, const char *metacontext,
                           uint64_t offset,
                           nbd_extent *entries, size_t nr_entries, int *error);

int
main (int argc, char *argv[])
{
  struct nbd_handle *nbd;
  char plugin_path[256];
  int id;
  nbd_extent_callback extent32_callback = { .callback = check_extent32,
                                            .user_data = &id };
  nbd_extent64_callback extent64_callback = { .callback = check_extent64,
                                              .user_data = &id };
  int r;
  const char *s;
  char *tmp;

  snprintf (plugin_path, sizeof plugin_path, "%s/meta-base-allocation.sh",
            getenv ("srcdir") ? : ".");

  char *args[] =
    { "nbdkit", "-s", "--exit-with-parent", "-v",
      "sh", plugin_path,
      NULL };

  nbd = nbd_create ();
  if (nbd == NULL) {
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  }

  /* No contexts requested by default */
  if ((r = nbd_get_nr_meta_contexts (nbd)) != 0) {
    fprintf (stderr, "unexpected number of contexts: %d\n", r);
    exit (EXIT_FAILURE);
  }

  /* Clearing an empty list is not fatal */
  if (nbd_clear_meta_contexts (nbd) != 0) {
    fprintf (stderr, "unable to clear requested contexts\n");
    exit (EXIT_FAILURE);
  }

  /* Negotiate metadata context "base:allocation" with the server.
   * This is supported in nbdkit >= 1.12.
   */
  if (nbd_add_meta_context (nbd, LIBNBD_CONTEXT_BASE_ALLOCATION) == -1) {
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  }

  /* Also request negotiation of a bogus context, which should not
   * fail here nor affect block status later.
   */
  if (nbd_add_meta_context (nbd, BOGUS_CONTEXT) == -1) {
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  }

  /* Test that we can read back what we have requested */
  if ((r = nbd_get_nr_meta_contexts (nbd)) != 2) {
    fprintf (stderr, "unexpected number of contexts: %d\n", r);
    exit (EXIT_FAILURE);
  }
  tmp = nbd_get_meta_context (nbd, 1);
  if (tmp == NULL) {
    fprintf (stderr, "unable to read back requested context 1: %s\n",
             nbd_get_error ());
    exit (EXIT_FAILURE);
  }
  if (strcmp (tmp, BOGUS_CONTEXT) != 0) {
    fprintf (stderr, "read back wrong context: %s\n", tmp);
    exit (EXIT_FAILURE);
  }
  free (tmp);

  if (nbd_connect_command (nbd, args) == -1) {
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  }

  /* Protocol should be "newstyle-fixed", with structured replies. */
  s = nbd_get_protocol (nbd);
  if (strcmp (s, "newstyle-fixed") != 0) {
    fprintf (stderr,
             "incorrect protocol \"%s\", expected \"newstyle-fixed\"\n", s);
    exit (EXIT_FAILURE);
  }
  if ((r = nbd_get_structured_replies_negotiated (nbd)) != 1) {
    fprintf (stderr,
             "incorrect structured replies %d, expected 1\n", r);
    exit (EXIT_FAILURE);
  }

  switch (nbd_can_meta_context (nbd, BOGUS_CONTEXT)) {
  case -1:
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  case 0:
    break;
  default:
    fprintf (stderr, "unexpected status for nbd_can_meta_context\n");
    exit (EXIT_FAILURE);
  }

  switch (nbd_can_meta_context (nbd, LIBNBD_CONTEXT_BASE_ALLOCATION)) {
  case -1:
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  case 1:
    break;
  default:
    fprintf (stderr, "unexpected status for nbd_can_meta_context\n");
    exit (EXIT_FAILURE);
  }

  /* Read the block status. */
  id = 1;
  if (nbd_block_status (nbd, 65536, 0, extent32_callback, 0) == -1) {
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  }
  if (nbd_block_status_64 (nbd, 65536, 0, extent64_callback, 0) == -1) {
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  }

  id = 2;
  if (nbd_block_status (nbd, 1024, 32768-512, extent32_callback, 0) == -1) {
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  }
  if (nbd_block_status_64 (nbd, 1024, 32768-512, extent64_callback, 0) == -1) {
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  }

  id = 3;
  if (nbd_block_status (nbd, 1024, 32768-512, extent32_callback,
                        LIBNBD_CMD_FLAG_REQ_ONE) == -1) {
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  }
  if (nbd_block_status_64 (nbd, 1024, 32768-512, extent64_callback,
                           LIBNBD_CMD_FLAG_REQ_ONE) == -1) {
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  }

  if (nbd_shutdown (nbd, 0) == -1) {
    fprintf (stderr, "%s\n", nbd_get_error ());
    exit (EXIT_FAILURE);
  }

  nbd_close (nbd);
  exit (EXIT_SUCCESS);
}

static int
check_extent32 (void *data, const char *metacontext, uint64_t offset,
                uint32_t *entries, size_t nr_entries, int *error)
{
  size_t i;
  int id;

  id = * (int *)data;

  printf ("extent: id=%d, metacontext=%s, offset=%" PRIu64 ", "
          "nr_entries=%zu, error=%d\n",
          id, metacontext, offset, nr_entries, *error);

  assert (*error == 0);
  if (strcmp (metacontext, LIBNBD_CONTEXT_BASE_ALLOCATION) == 0) {
    for (i = 0; i < nr_entries; i += 2) {
      printf ("\t%zu\tlength=%" PRIu32 ", status=%" PRIu32 "\n",
              i, entries[i], entries[i+1]);
    }
    fflush (stdout);

    switch (id) {
    case 1:
      assert (nr_entries == 10);
      assert (entries[0] == 8192);  assert (entries[1] == 0);
      assert (entries[2] == 8192);  assert (entries[3] == LIBNBD_STATE_HOLE);
      assert (entries[4] == 16384); assert (entries[5] == (LIBNBD_STATE_HOLE|
                                                           LIBNBD_STATE_ZERO));
      assert (entries[6] == 16384); assert (entries[7] == LIBNBD_STATE_ZERO);
      assert (entries[8] == 16384); assert (entries[9] == 0);
      break;

    case 2:
      assert (nr_entries == 4);
      assert (entries[0] == 512);   assert (entries[1] == (LIBNBD_STATE_HOLE|
                                                           LIBNBD_STATE_ZERO));
      assert (entries[2] == 16384); assert (entries[3] == LIBNBD_STATE_ZERO);
      break;

    case 3:
      assert (nr_entries == 2);
      assert (entries[0] == 512);   assert (entries[1] == (LIBNBD_STATE_HOLE|
                                                           LIBNBD_STATE_ZERO));
      break;

    default:
      abort ();
    }

  }
  else
    fprintf (stderr, "warning: ignored unexpected meta context %s\n",
             metacontext);

  return 0;
}

static int
check_extent64 (void *data, const char *metacontext, uint64_t offset,
                nbd_extent *entries, size_t nr_entries, int *error)
{
  size_t i;
  int id;

  id = * (int *)data;

  printf ("extent: id=%d, metacontext=%s, offset=%" PRIu64 ", "
          "nr_entries=%zu, error=%d\n",
          id, metacontext, offset, nr_entries, *error);

  assert (*error == 0);
  if (strcmp (metacontext, LIBNBD_CONTEXT_BASE_ALLOCATION) == 0) {
    for (i = 0; i < nr_entries; i++) {
      printf ("\t%zu\tlength=%" PRIu64 ", status=%" PRIu64 "\n",
              i, entries[i].length, entries[i].flags);
    }
    fflush (stdout);

    switch (id) {
    case 1:
      assert (nr_entries == 5);
      assert (entries[0].length == 8192);
      assert (entries[0].flags == 0);
      assert (entries[1].length == 8192);
      assert (entries[1].flags == LIBNBD_STATE_HOLE);
      assert (entries[2].length == 16384);
      assert (entries[2].flags == (LIBNBD_STATE_HOLE|LIBNBD_STATE_ZERO));
      assert (entries[3].length == 16384);
      assert (entries[3].flags == LIBNBD_STATE_ZERO);
      assert (entries[4].length == 16384);
      assert (entries[4].flags == 0);
      break;

    case 2:
      assert (nr_entries == 2);
      assert (entries[0].length == 512);
      assert (entries[0].flags == (LIBNBD_STATE_HOLE|LIBNBD_STATE_ZERO));
      assert (entries[1].length == 16384);
      assert (entries[1].flags == LIBNBD_STATE_ZERO);
      break;

    case 3:
      assert (nr_entries == 1);
      assert (entries[0].length == 512);
      assert (entries[0].flags == (LIBNBD_STATE_HOLE|LIBNBD_STATE_ZERO));
      break;

    default:
      abort ();
    }

  }
  else
    fprintf (stderr, "warning: ignored unexpected meta context %s\n",
             metacontext);

  return 0;
}
