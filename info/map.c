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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <libnbd.h>

#include "ansi-colours.h"
#include "minmax.h"
#include "vector.h"

#include "nbdinfo.h"

DEFINE_VECTOR_TYPE (extent_vector, nbd_extent);

static void print_extents (extent_vector *entries);
static void print_totals (extent_vector *entries, int64_t size);
static int extent_callback (void *user_data, const char *metacontext,
                            uint64_t offset,
                            nbd_extent *entries, size_t nr_entries,
                            int *error);

void
do_map (void)
{
  size_t i;
  int64_t size;
  extent_vector entries = empty_vector;
  uint64_t offset, align, max_len;
  size_t prev_entries_size;

  /* Map mode requires switching over to transmission phase. */
  if (nbd_aio_is_negotiating (nbd) &&
      nbd_opt_go (nbd) == -1) {
    fprintf (stderr, "%s: %s\n", progname, nbd_get_error ());
    exit (EXIT_FAILURE);
  }

  /* Did we get the requested map? */
  if (!nbd_can_meta_context (nbd, map)) {
    fprintf (stderr,
             "%s: --map: server does not support metadata context \"%s\"\n",
             progname, map);
    exit (EXIT_FAILURE);
  }
  align = nbd_get_block_size (nbd, LIBNBD_SIZE_MINIMUM) ?: 512;
  max_len = UINT32_MAX - align + 1;

  size = nbd_get_size (nbd);
  if (size == -1) {
    fprintf (stderr, "%s: %s\n", progname, nbd_get_error ());
    exit (EXIT_FAILURE);
  }
  if (nbd_get_extended_headers_negotiated (nbd) == 1)
    max_len = size;

  for (offset = 0; offset < size;) {
    prev_entries_size = entries.len;
    if (nbd_block_status_64 (nbd, MIN (size - offset, max_len), offset,
                             (nbd_extent64_callback) {
                               .callback = extent_callback,
                               .user_data = &entries },
                             0) == -1) {
      fprintf (stderr, "%s: %s\n", progname, nbd_get_error ());
      exit (EXIT_FAILURE);
    }
    /* We expect extent_callback to add at least one extent to entries. */
    if (prev_entries_size == entries.len) {
      fprintf (stderr, "%s: --map: server did not return any extents\n",
               progname);
      exit (EXIT_FAILURE);
    }
    for (i = prev_entries_size; i < entries.len; i++)
      offset += entries.ptr[i].length;
  }

  if (!totals)
    print_extents (&entries);
  else
    print_totals (&entries, size);
  free (entries.ptr);
}

/* Callback handling --map. */
static void print_one_extent (uint64_t offset, uint64_t len, uint64_t type);
static void extent_description (const char *metacontext, uint64_t type,
                                char **descr, bool *free_descr,
                                const char **fg, const char **bg);

static int
extent_callback (void *user_data, const char *metacontext,
                 uint64_t offset,
                 nbd_extent *entries, size_t nr_entries,
                 int *error)
{
  extent_vector *list = user_data;
  size_t i;

  if (strcmp (metacontext, map) != 0)
    return 0;

  /* Just append the entries we got to the list.  They are printed in
   * print_extents below.
   */
  for (i = 0; i < nr_entries; ++i) {
    if (extent_vector_append (list, entries[i]) == -1) {
      perror ("realloc");
      exit (EXIT_FAILURE);
    }
  }
  return 0;
}

static void
print_extents (extent_vector *entries)
{
  size_t i, j;
  uint64_t offset = 0;          /* end of last extent printed + 1 */
  size_t last = 0;              /* last entry printed + 1 */

  if (json_output) fprintf (fp, "[\n");

  for (i = 0; i < entries->len; i++) {
    uint64_t type = entries->ptr[last].flags;

    /* If we're coalescing and the current type is different from the
     * previous one then we should print everything up to this entry.
     */
    if (last != i && entries->ptr[i].flags != type) {
      uint64_t len;

      /* Calculate the length of the coalesced extent. */
      for (j = last, len = 0; j < i; j++)
        len += entries->ptr[j].length;
      print_one_extent (offset, len, type);
      offset += len;
      last = i;
    }
  }

  /* Print the last extent if there is one. */
  if (last != i) {
    uint64_t type = entries->ptr[last].flags;
    uint64_t len;

    for (j = last, len = 0; j < i; j++)
      len += entries->ptr[j].length;
    print_one_extent (offset, len, type);
  }

  if (json_output) fprintf (fp, "\n]\n");
}

static void
print_one_extent (uint64_t offset, uint64_t len, uint64_t type)
{
  static bool comma = false;
  char *descr;
  bool free_descr;
  const char *fg, *bg;

  extent_description (map, type, &descr, &free_descr, &fg, &bg);

  if (!json_output) {
    if (fg)
      ansi_colour (fg, fp);
    if (bg)
      ansi_colour (bg, fp);
    fprintf (fp, "%10" PRIu64 "  "
             "%10" PRIu64 "  "
             "%3" PRIu64,
             offset, len, type);
    if (descr)
      fprintf (fp, "  %s", descr);
    if (fg || bg)
      ansi_restore (fp);
    fprintf (fp, "\n");
  }
  else {
    if (comma)
      fprintf (fp, ",\n");

    fprintf (fp, "{ \"offset\": %" PRIu64 ", "
             "\"length\": %" PRIu64 ", "
             "\"type\": %" PRIu64,
             offset, len, type);
    if (descr) {
      fprintf (fp, ", \"description\": ");
      print_json_string (descr);
    }
    fprintf (fp, "}");
    comma = true;
  }

  if (free_descr)
    free (descr);
}

/* --map --totals suboption */
static void
print_totals (extent_vector *entries, int64_t size)
{
  uint64_t type;
  bool comma = false;

  /* This is necessary to avoid a divide by zero below, but if the
   * size of the export is zero then we know we will not print any
   * information below so return quickly.
   */
  if (size == 0) {
    if (json_output) fprintf (fp, "[]\n");
    return;
  }

  if (json_output) fprintf (fp, "[\n");

  /* In the outer loop assume we have already printed all entries with
   * entry type < type.  Count all instances of type and at the same
   * time find the next type that exists > type.
   */
  type = 0;
  for (;;) {
    uint64_t next_type = 0;
    uint64_t c = 0;
    size_t i;

    for (i = 0; i < entries->len; i++) {
      uint64_t t = entries->ptr[i].flags;

      if (t == type)
        c += entries->ptr[i].length;
      else if (type < t && (next_type == 0 || t < next_type))
        next_type = t;
    }

    if (c > 0) {
      char *descr;
      bool free_descr;
      const char *fg, *bg;
      double percent = 100.0 * c / size;

      extent_description (map, type, &descr, &free_descr, &fg, &bg);

      if (!json_output) {
        if (fg)
          ansi_colour (fg, fp);
        if (bg)
          ansi_colour (bg, fp);
        fprintf (fp, "%10" PRIu64 " %5.1f%% %3" PRIu64,
                 c, percent, type);
        if (descr)
          fprintf (fp, " %s", descr);
        if (fg || bg)
          ansi_restore (fp);
        fprintf (fp, "\n");
      }
      else {
        if (comma)
          fprintf (fp, ",\n");

        fprintf (fp,
                 "{ \"size\": %" PRIu64 ", "
                 "\"percent\": %g, "
                 "\"type\": %" PRIu64,
                 c, percent, type);
        if (descr) {
          fprintf (fp, ", \"description\": ");
          print_json_string (descr);
        }
        fprintf (fp, " }");
        comma = true;
      }

      if (free_descr)
        free (descr);
    }

    if (next_type == 0)
      break;
    type = next_type;
  }

  if (json_output) fprintf (fp, "\n]\n");
}

static void
extent_description (const char *metacontext, uint64_t type,
                    char **descr, bool *free_descr,
                    const char **fg, const char **bg)
{
  if (strcmp (metacontext, "base:allocation") == 0) {
    switch (type) {
    case 0:
      *descr = "data"; *free_descr = false;
      *fg = ANSI_FG_BOLD_BLACK; *bg = NULL;
      return;
    case 1:
      *descr = "hole"; *free_descr = false;
      *fg = *bg = NULL;
      return;
    case 2:
      *descr = "zero"; *free_descr = false;
      *fg = *bg = NULL;
      return;
    case 3:
      *descr = "hole,zero"; *free_descr = false;
      *fg = *bg = NULL;
      return;
    }
  }
  else if (strncmp (metacontext, "qemu:dirty-bitmap:", 18) == 0) {
    switch (type) {
    case 0:
      *descr = "clean"; *free_descr = false;
      *fg = ANSI_FG_GREEN; *bg = NULL;
      return;
    case 1:
      *descr = "dirty"; *free_descr = false;
      *fg = ANSI_FG_RED; *bg = NULL;
      return;
    }
  }
  else if (strcmp (metacontext, "qemu:allocation-depth") == 0) {
    switch (type) {
    case 0:
      *descr = "absent"; *free_descr = false;
      *fg = *bg = NULL;
      return;
    case 1:
      *descr = "local"; *free_descr = false;
      *fg = ANSI_FG_BRIGHT_WHITE; *bg = ANSI_BG_BLACK;
      return;
    default:
      if (asprintf (descr, "backing depth %" PRIu64, type) == -1) {
        perror ("asprintf");
        exit (EXIT_FAILURE);
      }
      *free_descr = true;
      *fg = NULL; *bg = ANSI_BG_LIGHT_GREY;
      return;
    }
  }

  /* Don't know - description field will be omitted. */
  *descr = NULL;
  *free_descr = false;
  *fg = NULL;
  *bg = NULL;
}
