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

#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>

#include "internal.h"

static int opt_meta_context_queries (struct nbd_handle *h,
                                     uint32_t opt,
                                     char **queries,
                                     nbd_context_callback *context)
  LIBNBD_ATTRIBUTE_NONNULL (1, 4);
static int aio_opt_meta_context_queries (struct nbd_handle *h,
                                         uint32_t opt,
                                         char **queries,
                                         nbd_context_callback *context,
                                         nbd_completion_callback *complete)
  LIBNBD_ATTRIBUTE_NONNULL (1, 4, 5);

/* Internal function which frees an option with callback. */
void
nbd_internal_free_option (struct nbd_handle *h)
{
  if (h->opt_current == NBD_OPT_LIST)
    FREE_CALLBACK (h->opt_cb.fn.list);
  else if (h->opt_current == NBD_OPT_LIST_META_CONTEXT ||
           h->opt_current == NBD_OPT_SET_META_CONTEXT)
    FREE_CALLBACK (h->opt_cb.fn.context);
  FREE_CALLBACK (h->opt_cb.completion);
}

int
nbd_unlocked_set_opt_mode (struct nbd_handle *h, bool value)
{
  h->opt_mode = value;
  return 0;
}

/* NB: may_set_error = false. */
int
nbd_unlocked_get_opt_mode (struct nbd_handle *h)
{
  return h->opt_mode;
}

static int
wait_for_option (struct nbd_handle *h)
{
  while (nbd_internal_is_state_connecting (get_next_state (h))) {
    if (nbd_unlocked_poll (h, -1) == -1)
      return -1;
  }

  return 0;
}

static int
go_complete (void *opaque, int *err)
{
  int *i = opaque;
  *i = *err;
  return 0;
}

/* Issue NBD_OPT_GO (or NBD_OPT_EXPORT_NAME) and wait for the reply. */
int
nbd_unlocked_opt_go (struct nbd_handle *h)
{
  int err = 0;
  nbd_completion_callback c = { .callback = go_complete, .user_data = &err };
  int r = nbd_unlocked_aio_opt_go (h, &c);

  if (r == -1)
    return r;

  r = wait_for_option (h);
  if (r == 0 && err) {
    assert (nbd_internal_is_state_negotiating (get_next_state (h)) ||
            nbd_internal_is_state_dead (get_next_state (h)));
    set_error (err, "server replied with error to opt_go request");
    return -1;
  }
  if (r == 0)
    assert (nbd_internal_is_state_ready (get_next_state (h)));
  return r;
}

/* Issue NBD_OPT_INFO and wait for the reply. */
int
nbd_unlocked_opt_info (struct nbd_handle *h)
{
  int err = 0;
  nbd_completion_callback c = { .callback = go_complete, .user_data = &err };
  int r = nbd_unlocked_aio_opt_info (h, &c);

  if (r == -1)
    return r;

  r = wait_for_option (h);
  if (r == 0 && err) {
    assert (nbd_internal_is_state_negotiating (get_next_state (h)) ||
            nbd_internal_is_state_dead (get_next_state (h)));
    set_error (err, "server replied with error to opt_info request");
    return -1;
  }
  return r;
}

/* Issue NBD_OPT_ABORT and wait for the state change. */
int
nbd_unlocked_opt_abort (struct nbd_handle *h)
{
  int r = nbd_unlocked_aio_opt_abort (h);

  if (r == -1)
    return r;

  return wait_for_option (h);
}

/* Issue NBD_OPT_STARTTLS and wait for the reply. */
int
nbd_unlocked_opt_starttls (struct nbd_handle *h)
{
  int err = 0;
  nbd_completion_callback c = { .callback = go_complete, .user_data = &err };
  int r = nbd_unlocked_aio_opt_starttls (h, &c);

  if (r == -1)
    return r;

  r = wait_for_option (h);
  if (r == 0) {
    if (nbd_internal_is_state_negotiating (get_next_state (h)))
      r = err == 0;
    else {
      assert (nbd_internal_is_state_dead (get_next_state (h)));
      set_error (err,
                 "failed to get response to opt_starttls request");
      r = -1;
    }
  }
  return r;
}

/* Issue NBD_OPT_EXTENDED_HEADERS and wait for the reply. */
int
nbd_unlocked_opt_extended_headers (struct nbd_handle *h)
{
  int err;
  nbd_completion_callback c = { .callback = go_complete, .user_data = &err };
  int r = nbd_unlocked_aio_opt_extended_headers (h, &c);

  if (r == -1)
    return r;

  r = wait_for_option (h);
  if (r == 0) {
    if (nbd_internal_is_state_negotiating (get_next_state (h)))
      r = err == 0;
    else {
      assert (nbd_internal_is_state_dead (get_next_state (h)));
      set_error (err,
                 "failed to get response to opt_extended_headers request");
      r = -1;
    }
  }
  return r;
}

/* Issue NBD_OPT_STRUCTURED_REPLY and wait for the reply. */
int
nbd_unlocked_opt_structured_reply (struct nbd_handle *h)
{
  int err = 0;
  nbd_completion_callback c = { .callback = go_complete, .user_data = &err };
  int r = nbd_unlocked_aio_opt_structured_reply (h, &c);

  if (r == -1)
    return r;

  r = wait_for_option (h);
  if (r == 0) {
    if (nbd_internal_is_state_negotiating (get_next_state (h)))
      r = err == 0;
    else {
      assert (nbd_internal_is_state_dead (get_next_state (h)));
      set_error (err,
                 "failed to get response to opt_structured_reply request");
      r = -1;
    }
  }
  return r;
}

struct list_helper {
  int count;
  nbd_list_callback list;
  int err;
};
static int
list_visitor (void *opaque, const char *name, const char *description)
{
  struct list_helper *h = opaque;
  if (h->count < INT_MAX)
    h->count++;
  CALL_CALLBACK (h->list, name, description);
  return 0;
}
static int
list_complete (void *opaque, int *err)
{
  struct list_helper *h = opaque;
  h->err = *err;
  FREE_CALLBACK (h->list);
  return 0;
}

/* Issue NBD_OPT_LIST and wait for the reply. */
int
nbd_unlocked_opt_list (struct nbd_handle *h, nbd_list_callback *list)
{
  struct list_helper s = { .list = *list };
  nbd_list_callback l = { .callback = list_visitor, .user_data = &s };
  nbd_completion_callback c = { .callback = list_complete, .user_data = &s };

  if (nbd_unlocked_aio_opt_list (h, &l, &c) == -1)
    return -1;

  assert (CALLBACK_IS_NULL (l));
  SET_CALLBACK_TO_NULL (*list);
  if (wait_for_option (h) == -1)
    return -1;
  if (s.err) {
    set_error (s.err, "server replied with error to list request");
    return -1;
  }
  return s.count;
}

struct context_helper {
  int count;
  nbd_context_callback context;
  int err;
};
static int
context_visitor (void *opaque, const char *name)
{
  struct context_helper *h = opaque;
  if (h->count < INT_MAX)
    h->count++;
  CALL_CALLBACK (h->context, name);
  return 0;
}
static int
context_complete (void *opaque, int *err)
{
  struct context_helper *h = opaque;
  h->err = *err;
  FREE_CALLBACK (h->context);
  return 0;
}

static int
opt_meta_context_queries (struct nbd_handle *h,
                          uint32_t opt,
                          char **queries,
                          nbd_context_callback *context)
{
  struct context_helper s = { .context = *context };
  nbd_context_callback l = { .callback = context_visitor, .user_data = &s };
  nbd_completion_callback c = { .callback = context_complete, .user_data = &s };

  if (aio_opt_meta_context_queries (h, opt, queries, &l, &c) == -1)
    return -1;

  assert (CALLBACK_IS_NULL (l));
  SET_CALLBACK_TO_NULL (*context);
  if (wait_for_option (h) == -1)
    return -1;
  if (s.err) {
    set_error (s.err, "server replied with error to meta context request");
    return -1;
  }
  return s.count;
}

/* Issue NBD_OPT_LIST_META_CONTEXT and wait for the reply. */
int
nbd_unlocked_opt_list_meta_context (struct nbd_handle *h,
                                    nbd_context_callback *context)
{
  return opt_meta_context_queries (h, NBD_OPT_LIST_META_CONTEXT,
                                   NULL, context);
}

/* Issue NBD_OPT_LIST_META_CONTEXT and wait for the reply. */
int
nbd_unlocked_opt_list_meta_context_queries (struct nbd_handle *h,
                                            char **queries,
                                            nbd_context_callback *context)
{
  return opt_meta_context_queries (h, NBD_OPT_LIST_META_CONTEXT,
                                   queries, context);
}

/* Issue NBD_OPT_SET_META_CONTEXT and wait for the reply. */
int
nbd_unlocked_opt_set_meta_context (struct nbd_handle *h,
                                   nbd_context_callback *context)
{
  return opt_meta_context_queries (h, NBD_OPT_SET_META_CONTEXT,
                                   NULL, context);
}

/* Issue NBD_OPT_SET_META_CONTEXT and wait for the reply. */
int
nbd_unlocked_opt_set_meta_context_queries (struct nbd_handle *h,
                                           char **queries,
                                           nbd_context_callback *context)
{
  return opt_meta_context_queries (h, NBD_OPT_SET_META_CONTEXT,
                                   queries, context);
}

/* Issue NBD_OPT_GO (or NBD_OPT_EXPORT_NAME) without waiting. */
int
nbd_unlocked_aio_opt_go (struct nbd_handle *h,
                         nbd_completion_callback *complete)
{
  h->opt_current = NBD_OPT_GO;
  h->opt_cb.completion = *complete;
  SET_CALLBACK_TO_NULL (*complete);

  if (nbd_internal_run (h, cmd_issue) == -1)
    debug (h, "option queued, ignoring state machine failure");
  return 0;
}

/* Issue NBD_OPT_INFO without waiting. */
int
nbd_unlocked_aio_opt_info (struct nbd_handle *h,
                           nbd_completion_callback *complete)
{
  if ((h->gflags & LIBNBD_HANDSHAKE_FLAG_FIXED_NEWSTYLE) == 0) {
    set_error (ENOTSUP, "server is not using fixed newstyle protocol");
    return -1;
  }

  h->opt_current = NBD_OPT_INFO;
  h->opt_cb.completion = *complete;
  SET_CALLBACK_TO_NULL (*complete);

  if (nbd_internal_run (h, cmd_issue) == -1)
    debug (h, "option queued, ignoring state machine failure");
  return 0;
}

/* Issue NBD_OPT_ABORT without waiting. */
int
nbd_unlocked_aio_opt_abort (struct nbd_handle *h)
{
  h->opt_current = NBD_OPT_ABORT;

  if (nbd_internal_run (h, cmd_issue) == -1)
    debug (h, "option queued, ignoring state machine failure");
  return 0;
}

/* Issue NBD_OPT_STARTTLS without waiting. */
int
nbd_unlocked_aio_opt_starttls (struct nbd_handle *h,
                               nbd_completion_callback *complete)
{
  if ((h->gflags & LIBNBD_HANDSHAKE_FLAG_FIXED_NEWSTYLE) == 0) {
    set_error (ENOTSUP, "server is not using fixed newstyle protocol");
    return -1;
  }

#ifndef HAVE_GNUTLS
  set_error (ENOTSUP, "libnbd was compiled without TLS support");
  return -1;

#else
  h->opt_current = NBD_OPT_STARTTLS;
  h->opt_cb.completion = *complete;
  SET_CALLBACK_TO_NULL (*complete);

  if (nbd_internal_run (h, cmd_issue) == -1)
    debug (h, "option queued, ignoring state machine failure");
  return 0;
#endif
}

/* Issue NBD_OPT_EXTENDED_HEADERS without waiting. */
int
nbd_unlocked_aio_opt_extended_headers (struct nbd_handle *h,
                                       nbd_completion_callback *complete)
{
  if ((h->gflags & LIBNBD_HANDSHAKE_FLAG_FIXED_NEWSTYLE) == 0) {
    set_error (ENOTSUP, "server is not using fixed newstyle protocol");
    return -1;
  }

  h->opt_current = NBD_OPT_EXTENDED_HEADERS;
  h->opt_cb.completion = *complete;
  SET_CALLBACK_TO_NULL (*complete);

  if (nbd_internal_run (h, cmd_issue) == -1)
    debug (h, "option queued, ignoring state machine failure");
  return 0;
}

/* Issue NBD_OPT_STRUCTURED_REPLY without waiting. */
int
nbd_unlocked_aio_opt_structured_reply (struct nbd_handle *h,
                                       nbd_completion_callback *complete)
{
  if ((h->gflags & LIBNBD_HANDSHAKE_FLAG_FIXED_NEWSTYLE) == 0) {
    set_error (ENOTSUP, "server is not using fixed newstyle protocol");
    return -1;
  }

  h->opt_current = NBD_OPT_STRUCTURED_REPLY;
  h->opt_cb.completion = *complete;
  SET_CALLBACK_TO_NULL (*complete);

  if (nbd_internal_run (h, cmd_issue) == -1)
    debug (h, "option queued, ignoring state machine failure");
  return 0;
}

/* Issue NBD_OPT_LIST without waiting. */
int
nbd_unlocked_aio_opt_list (struct nbd_handle *h, nbd_list_callback *list,
                           nbd_completion_callback *complete)
{
  if ((h->gflags & LIBNBD_HANDSHAKE_FLAG_FIXED_NEWSTYLE) == 0) {
    set_error (ENOTSUP, "server is not using fixed newstyle protocol");
    return -1;
  }

  assert (CALLBACK_IS_NULL (h->opt_cb.fn.list));
  h->opt_cb.fn.list = *list;
  SET_CALLBACK_TO_NULL (*list);
  h->opt_cb.completion = *complete;
  SET_CALLBACK_TO_NULL (*complete);
  h->opt_current = NBD_OPT_LIST;
  if (nbd_internal_run (h, cmd_issue) == -1)
    debug (h, "option queued, ignoring state machine failure");
  return 0;
}

static int
aio_opt_meta_context_queries (struct nbd_handle *h,
                              uint32_t opt,
                              char **queries,
                              nbd_context_callback *context,
                              nbd_completion_callback *complete)
{
  if ((h->gflags & LIBNBD_HANDSHAKE_FLAG_FIXED_NEWSTYLE) == 0) {
    set_error (ENOTSUP, "server is not using fixed newstyle protocol");
    return -1;
  }

  if (nbd_internal_set_querylist (h, queries) == -1)
    return -1;

  assert (CALLBACK_IS_NULL (h->opt_cb.fn.context));
  h->opt_cb.fn.context = *context;
  SET_CALLBACK_TO_NULL (*context);
  h->opt_cb.completion = *complete;
  SET_CALLBACK_TO_NULL (*complete);
  h->opt_current = opt;
  if (nbd_internal_run (h, cmd_issue) == -1)
    debug (h, "option queued, ignoring state machine failure");
  return 0;
}

/* Issue NBD_OPT_LIST_META_CONTEXT without waiting. */
int
nbd_unlocked_aio_opt_list_meta_context (struct nbd_handle *h,
                                        nbd_context_callback *context,
                                        nbd_completion_callback *complete)
{
  return aio_opt_meta_context_queries (h, NBD_OPT_LIST_META_CONTEXT,
                                       NULL, context, complete);
}

/* Issue NBD_OPT_LIST_META_CONTEXT without waiting. */
int
nbd_unlocked_aio_opt_list_meta_context_queries (struct nbd_handle *h,
                                                char **queries,
                                                nbd_context_callback *context,
                                                nbd_completion_callback *compl)
{
  return aio_opt_meta_context_queries (h, NBD_OPT_LIST_META_CONTEXT,
                                       queries, context, compl);
}

/* Issue NBD_OPT_SET_META_CONTEXT without waiting. */
int
nbd_unlocked_aio_opt_set_meta_context (struct nbd_handle *h,
                                       nbd_context_callback *context,
                                       nbd_completion_callback *complete)
{
  return aio_opt_meta_context_queries (h, NBD_OPT_SET_META_CONTEXT,
                                       NULL, context, complete);
}

/* Issue NBD_OPT_SET_META_CONTEXT without waiting. */
int
nbd_unlocked_aio_opt_set_meta_context_queries (struct nbd_handle *h,
                                               char **queries,
                                               nbd_context_callback *context,
                                               nbd_completion_callback *compl)
{
  return aio_opt_meta_context_queries (h, NBD_OPT_SET_META_CONTEXT,
                                       queries, context, compl);
}
