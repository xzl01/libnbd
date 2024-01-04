/* NBD client library in userspace
 * WARNING: THIS FILE IS GENERATED FROM
 * generator/generator
 * ANY CHANGES YOU MAKE TO THIS FILE WILL BE LOST.
 *
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

#define PY_SSIZE_T_CLEAN 1
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <libnbd.h>

#include "methods.h"

static PyMethodDef methods[] = {
  {
    "create",
    nbd_internal_py_create,
    METH_VARARGS,
    NULL
  },
  {
    "close",
    nbd_internal_py_close,
    METH_VARARGS,
    NULL
  },
  {
    "display_version",
    nbd_internal_py_display_version,
    METH_VARARGS,
    NULL
  },
  {
    "alloc_aio_buffer",
    nbd_internal_py_alloc_aio_buffer,
    METH_VARARGS,
    NULL
  },
  {
    "aio_buffer_is_zero",
    nbd_internal_py_aio_buffer_is_zero,
    METH_VARARGS,
    NULL
  },
  {
    "set_debug",
    nbd_internal_py_set_debug,
    METH_VARARGS,
    NULL
  },
  {
    "get_debug",
    nbd_internal_py_get_debug,
    METH_VARARGS,
    NULL
  },
  {
    "set_debug_callback",
    nbd_internal_py_set_debug_callback,
    METH_VARARGS,
    NULL
  },
  {
    "clear_debug_callback",
    nbd_internal_py_clear_debug_callback,
    METH_VARARGS,
    NULL
  },
  {
    "stats_bytes_sent",
    nbd_internal_py_stats_bytes_sent,
    METH_VARARGS,
    NULL
  },
  {
    "stats_chunks_sent",
    nbd_internal_py_stats_chunks_sent,
    METH_VARARGS,
    NULL
  },
  {
    "stats_bytes_received",
    nbd_internal_py_stats_bytes_received,
    METH_VARARGS,
    NULL
  },
  {
    "stats_chunks_received",
    nbd_internal_py_stats_chunks_received,
    METH_VARARGS,
    NULL
  },
  {
    "set_handle_name",
    nbd_internal_py_set_handle_name,
    METH_VARARGS,
    NULL
  },
  {
    "get_handle_name",
    nbd_internal_py_get_handle_name,
    METH_VARARGS,
    NULL
  },
  {
    "set_private_data",
    nbd_internal_py_set_private_data,
    METH_VARARGS,
    NULL
  },
  {
    "get_private_data",
    nbd_internal_py_get_private_data,
    METH_VARARGS,
    NULL
  },
  {
    "set_export_name",
    nbd_internal_py_set_export_name,
    METH_VARARGS,
    NULL
  },
  {
    "get_export_name",
    nbd_internal_py_get_export_name,
    METH_VARARGS,
    NULL
  },
  {
    "set_request_block_size",
    nbd_internal_py_set_request_block_size,
    METH_VARARGS,
    NULL
  },
  {
    "get_request_block_size",
    nbd_internal_py_get_request_block_size,
    METH_VARARGS,
    NULL
  },
  {
    "set_full_info",
    nbd_internal_py_set_full_info,
    METH_VARARGS,
    NULL
  },
  {
    "get_full_info",
    nbd_internal_py_get_full_info,
    METH_VARARGS,
    NULL
  },
  {
    "get_canonical_export_name",
    nbd_internal_py_get_canonical_export_name,
    METH_VARARGS,
    NULL
  },
  {
    "get_export_description",
    nbd_internal_py_get_export_description,
    METH_VARARGS,
    NULL
  },
  {
    "set_tls",
    nbd_internal_py_set_tls,
    METH_VARARGS,
    NULL
  },
  {
    "get_tls",
    nbd_internal_py_get_tls,
    METH_VARARGS,
    NULL
  },
  {
    "get_tls_negotiated",
    nbd_internal_py_get_tls_negotiated,
    METH_VARARGS,
    NULL
  },
  {
    "set_tls_certificates",
    nbd_internal_py_set_tls_certificates,
    METH_VARARGS,
    NULL
  },
  {
    "set_tls_verify_peer",
    nbd_internal_py_set_tls_verify_peer,
    METH_VARARGS,
    NULL
  },
  {
    "get_tls_verify_peer",
    nbd_internal_py_get_tls_verify_peer,
    METH_VARARGS,
    NULL
  },
  {
    "set_tls_username",
    nbd_internal_py_set_tls_username,
    METH_VARARGS,
    NULL
  },
  {
    "get_tls_username",
    nbd_internal_py_get_tls_username,
    METH_VARARGS,
    NULL
  },
  {
    "set_tls_psk_file",
    nbd_internal_py_set_tls_psk_file,
    METH_VARARGS,
    NULL
  },
  {
    "set_request_extended_headers",
    nbd_internal_py_set_request_extended_headers,
    METH_VARARGS,
    NULL
  },
  {
    "get_request_extended_headers",
    nbd_internal_py_get_request_extended_headers,
    METH_VARARGS,
    NULL
  },
  {
    "get_extended_headers_negotiated",
    nbd_internal_py_get_extended_headers_negotiated,
    METH_VARARGS,
    NULL
  },
  {
    "set_request_structured_replies",
    nbd_internal_py_set_request_structured_replies,
    METH_VARARGS,
    NULL
  },
  {
    "get_request_structured_replies",
    nbd_internal_py_get_request_structured_replies,
    METH_VARARGS,
    NULL
  },
  {
    "get_structured_replies_negotiated",
    nbd_internal_py_get_structured_replies_negotiated,
    METH_VARARGS,
    NULL
  },
  {
    "set_request_meta_context",
    nbd_internal_py_set_request_meta_context,
    METH_VARARGS,
    NULL
  },
  {
    "get_request_meta_context",
    nbd_internal_py_get_request_meta_context,
    METH_VARARGS,
    NULL
  },
  {
    "set_handshake_flags",
    nbd_internal_py_set_handshake_flags,
    METH_VARARGS,
    NULL
  },
  {
    "get_handshake_flags",
    nbd_internal_py_get_handshake_flags,
    METH_VARARGS,
    NULL
  },
  {
    "set_pread_initialize",
    nbd_internal_py_set_pread_initialize,
    METH_VARARGS,
    NULL
  },
  {
    "get_pread_initialize",
    nbd_internal_py_get_pread_initialize,
    METH_VARARGS,
    NULL
  },
  {
    "set_strict_mode",
    nbd_internal_py_set_strict_mode,
    METH_VARARGS,
    NULL
  },
  {
    "get_strict_mode",
    nbd_internal_py_get_strict_mode,
    METH_VARARGS,
    NULL
  },
  {
    "set_opt_mode",
    nbd_internal_py_set_opt_mode,
    METH_VARARGS,
    NULL
  },
  {
    "get_opt_mode",
    nbd_internal_py_get_opt_mode,
    METH_VARARGS,
    NULL
  },
  {
    "opt_go",
    nbd_internal_py_opt_go,
    METH_VARARGS,
    NULL
  },
  {
    "opt_abort",
    nbd_internal_py_opt_abort,
    METH_VARARGS,
    NULL
  },
  {
    "opt_starttls",
    nbd_internal_py_opt_starttls,
    METH_VARARGS,
    NULL
  },
  {
    "opt_extended_headers",
    nbd_internal_py_opt_extended_headers,
    METH_VARARGS,
    NULL
  },
  {
    "opt_structured_reply",
    nbd_internal_py_opt_structured_reply,
    METH_VARARGS,
    NULL
  },
  {
    "opt_list",
    nbd_internal_py_opt_list,
    METH_VARARGS,
    NULL
  },
  {
    "opt_info",
    nbd_internal_py_opt_info,
    METH_VARARGS,
    NULL
  },
  {
    "opt_list_meta_context",
    nbd_internal_py_opt_list_meta_context,
    METH_VARARGS,
    NULL
  },
  {
    "opt_list_meta_context_queries",
    nbd_internal_py_opt_list_meta_context_queries,
    METH_VARARGS,
    NULL
  },
  {
    "opt_set_meta_context",
    nbd_internal_py_opt_set_meta_context,
    METH_VARARGS,
    NULL
  },
  {
    "opt_set_meta_context_queries",
    nbd_internal_py_opt_set_meta_context_queries,
    METH_VARARGS,
    NULL
  },
  {
    "add_meta_context",
    nbd_internal_py_add_meta_context,
    METH_VARARGS,
    NULL
  },
  {
    "get_nr_meta_contexts",
    nbd_internal_py_get_nr_meta_contexts,
    METH_VARARGS,
    NULL
  },
  {
    "get_meta_context",
    nbd_internal_py_get_meta_context,
    METH_VARARGS,
    NULL
  },
  {
    "clear_meta_contexts",
    nbd_internal_py_clear_meta_contexts,
    METH_VARARGS,
    NULL
  },
  {
    "set_uri_allow_transports",
    nbd_internal_py_set_uri_allow_transports,
    METH_VARARGS,
    NULL
  },
  {
    "set_uri_allow_tls",
    nbd_internal_py_set_uri_allow_tls,
    METH_VARARGS,
    NULL
  },
  {
    "set_uri_allow_local_file",
    nbd_internal_py_set_uri_allow_local_file,
    METH_VARARGS,
    NULL
  },
  {
    "connect_uri",
    nbd_internal_py_connect_uri,
    METH_VARARGS,
    NULL
  },
  {
    "connect_unix",
    nbd_internal_py_connect_unix,
    METH_VARARGS,
    NULL
  },
  {
    "connect_vsock",
    nbd_internal_py_connect_vsock,
    METH_VARARGS,
    NULL
  },
  {
    "connect_tcp",
    nbd_internal_py_connect_tcp,
    METH_VARARGS,
    NULL
  },
  {
    "connect_socket",
    nbd_internal_py_connect_socket,
    METH_VARARGS,
    NULL
  },
  {
    "connect_command",
    nbd_internal_py_connect_command,
    METH_VARARGS,
    NULL
  },
  {
    "connect_systemd_socket_activation",
    nbd_internal_py_connect_systemd_socket_activation,
    METH_VARARGS,
    NULL
  },
  {
    "set_socket_activation_name",
    nbd_internal_py_set_socket_activation_name,
    METH_VARARGS,
    NULL
  },
  {
    "get_socket_activation_name",
    nbd_internal_py_get_socket_activation_name,
    METH_VARARGS,
    NULL
  },
  {
    "is_read_only",
    nbd_internal_py_is_read_only,
    METH_VARARGS,
    NULL
  },
  {
    "can_flush",
    nbd_internal_py_can_flush,
    METH_VARARGS,
    NULL
  },
  {
    "can_fua",
    nbd_internal_py_can_fua,
    METH_VARARGS,
    NULL
  },
  {
    "is_rotational",
    nbd_internal_py_is_rotational,
    METH_VARARGS,
    NULL
  },
  {
    "can_trim",
    nbd_internal_py_can_trim,
    METH_VARARGS,
    NULL
  },
  {
    "can_zero",
    nbd_internal_py_can_zero,
    METH_VARARGS,
    NULL
  },
  {
    "can_fast_zero",
    nbd_internal_py_can_fast_zero,
    METH_VARARGS,
    NULL
  },
  {
    "can_block_status_payload",
    nbd_internal_py_can_block_status_payload,
    METH_VARARGS,
    NULL
  },
  {
    "can_df",
    nbd_internal_py_can_df,
    METH_VARARGS,
    NULL
  },
  {
    "can_multi_conn",
    nbd_internal_py_can_multi_conn,
    METH_VARARGS,
    NULL
  },
  {
    "can_cache",
    nbd_internal_py_can_cache,
    METH_VARARGS,
    NULL
  },
  {
    "can_meta_context",
    nbd_internal_py_can_meta_context,
    METH_VARARGS,
    NULL
  },
  {
    "get_protocol",
    nbd_internal_py_get_protocol,
    METH_VARARGS,
    NULL
  },
  {
    "get_size",
    nbd_internal_py_get_size,
    METH_VARARGS,
    NULL
  },
  {
    "get_block_size",
    nbd_internal_py_get_block_size,
    METH_VARARGS,
    NULL
  },
  {
    "pread",
    nbd_internal_py_pread,
    METH_VARARGS,
    NULL
  },
  {
    "pread_structured",
    nbd_internal_py_pread_structured,
    METH_VARARGS,
    NULL
  },
  {
    "pwrite",
    nbd_internal_py_pwrite,
    METH_VARARGS,
    NULL
  },
  {
    "shutdown",
    nbd_internal_py_shutdown,
    METH_VARARGS,
    NULL
  },
  {
    "flush",
    nbd_internal_py_flush,
    METH_VARARGS,
    NULL
  },
  {
    "trim",
    nbd_internal_py_trim,
    METH_VARARGS,
    NULL
  },
  {
    "cache",
    nbd_internal_py_cache,
    METH_VARARGS,
    NULL
  },
  {
    "zero",
    nbd_internal_py_zero,
    METH_VARARGS,
    NULL
  },
  {
    "block_status",
    nbd_internal_py_block_status,
    METH_VARARGS,
    NULL
  },
  {
    "block_status_64",
    nbd_internal_py_block_status_64,
    METH_VARARGS,
    NULL
  },
  {
    "block_status_filter",
    nbd_internal_py_block_status_filter,
    METH_VARARGS,
    NULL
  },
  {
    "poll",
    nbd_internal_py_poll,
    METH_VARARGS,
    NULL
  },
  {
    "poll2",
    nbd_internal_py_poll2,
    METH_VARARGS,
    NULL
  },
  {
    "aio_connect",
    nbd_internal_py_aio_connect,
    METH_VARARGS,
    NULL
  },
  {
    "aio_connect_uri",
    nbd_internal_py_aio_connect_uri,
    METH_VARARGS,
    NULL
  },
  {
    "aio_connect_unix",
    nbd_internal_py_aio_connect_unix,
    METH_VARARGS,
    NULL
  },
  {
    "aio_connect_vsock",
    nbd_internal_py_aio_connect_vsock,
    METH_VARARGS,
    NULL
  },
  {
    "aio_connect_tcp",
    nbd_internal_py_aio_connect_tcp,
    METH_VARARGS,
    NULL
  },
  {
    "aio_connect_socket",
    nbd_internal_py_aio_connect_socket,
    METH_VARARGS,
    NULL
  },
  {
    "aio_connect_command",
    nbd_internal_py_aio_connect_command,
    METH_VARARGS,
    NULL
  },
  {
    "aio_connect_systemd_socket_activation",
    nbd_internal_py_aio_connect_systemd_socket_activation,
    METH_VARARGS,
    NULL
  },
  {
    "aio_opt_go",
    nbd_internal_py_aio_opt_go,
    METH_VARARGS,
    NULL
  },
  {
    "aio_opt_abort",
    nbd_internal_py_aio_opt_abort,
    METH_VARARGS,
    NULL
  },
  {
    "aio_opt_starttls",
    nbd_internal_py_aio_opt_starttls,
    METH_VARARGS,
    NULL
  },
  {
    "aio_opt_extended_headers",
    nbd_internal_py_aio_opt_extended_headers,
    METH_VARARGS,
    NULL
  },
  {
    "aio_opt_structured_reply",
    nbd_internal_py_aio_opt_structured_reply,
    METH_VARARGS,
    NULL
  },
  {
    "aio_opt_list",
    nbd_internal_py_aio_opt_list,
    METH_VARARGS,
    NULL
  },
  {
    "aio_opt_info",
    nbd_internal_py_aio_opt_info,
    METH_VARARGS,
    NULL
  },
  {
    "aio_opt_list_meta_context",
    nbd_internal_py_aio_opt_list_meta_context,
    METH_VARARGS,
    NULL
  },
  {
    "aio_opt_list_meta_context_queries",
    nbd_internal_py_aio_opt_list_meta_context_queries,
    METH_VARARGS,
    NULL
  },
  {
    "aio_opt_set_meta_context",
    nbd_internal_py_aio_opt_set_meta_context,
    METH_VARARGS,
    NULL
  },
  {
    "aio_opt_set_meta_context_queries",
    nbd_internal_py_aio_opt_set_meta_context_queries,
    METH_VARARGS,
    NULL
  },
  {
    "aio_pread",
    nbd_internal_py_aio_pread,
    METH_VARARGS,
    NULL
  },
  {
    "aio_pread_structured",
    nbd_internal_py_aio_pread_structured,
    METH_VARARGS,
    NULL
  },
  {
    "aio_pwrite",
    nbd_internal_py_aio_pwrite,
    METH_VARARGS,
    NULL
  },
  {
    "aio_disconnect",
    nbd_internal_py_aio_disconnect,
    METH_VARARGS,
    NULL
  },
  {
    "aio_flush",
    nbd_internal_py_aio_flush,
    METH_VARARGS,
    NULL
  },
  {
    "aio_trim",
    nbd_internal_py_aio_trim,
    METH_VARARGS,
    NULL
  },
  {
    "aio_cache",
    nbd_internal_py_aio_cache,
    METH_VARARGS,
    NULL
  },
  {
    "aio_zero",
    nbd_internal_py_aio_zero,
    METH_VARARGS,
    NULL
  },
  {
    "aio_block_status",
    nbd_internal_py_aio_block_status,
    METH_VARARGS,
    NULL
  },
  {
    "aio_block_status_64",
    nbd_internal_py_aio_block_status_64,
    METH_VARARGS,
    NULL
  },
  {
    "aio_block_status_filter",
    nbd_internal_py_aio_block_status_filter,
    METH_VARARGS,
    NULL
  },
  {
    "aio_get_fd",
    nbd_internal_py_aio_get_fd,
    METH_VARARGS,
    NULL
  },
  {
    "aio_get_direction",
    nbd_internal_py_aio_get_direction,
    METH_VARARGS,
    NULL
  },
  {
    "aio_notify_read",
    nbd_internal_py_aio_notify_read,
    METH_VARARGS,
    NULL
  },
  {
    "aio_notify_write",
    nbd_internal_py_aio_notify_write,
    METH_VARARGS,
    NULL
  },
  {
    "aio_is_created",
    nbd_internal_py_aio_is_created,
    METH_VARARGS,
    NULL
  },
  {
    "aio_is_connecting",
    nbd_internal_py_aio_is_connecting,
    METH_VARARGS,
    NULL
  },
  {
    "aio_is_negotiating",
    nbd_internal_py_aio_is_negotiating,
    METH_VARARGS,
    NULL
  },
  {
    "aio_is_ready",
    nbd_internal_py_aio_is_ready,
    METH_VARARGS,
    NULL
  },
  {
    "aio_is_processing",
    nbd_internal_py_aio_is_processing,
    METH_VARARGS,
    NULL
  },
  {
    "aio_is_dead",
    nbd_internal_py_aio_is_dead,
    METH_VARARGS,
    NULL
  },
  {
    "aio_is_closed",
    nbd_internal_py_aio_is_closed,
    METH_VARARGS,
    NULL
  },
  {
    "aio_command_completed",
    nbd_internal_py_aio_command_completed,
    METH_VARARGS,
    NULL
  },
  {
    "aio_peek_command_completed",
    nbd_internal_py_aio_peek_command_completed,
    METH_VARARGS,
    NULL
  },
  {
    "aio_in_flight",
    nbd_internal_py_aio_in_flight,
    METH_VARARGS,
    NULL
  },
  {
    "connection_state",
    nbd_internal_py_connection_state,
    METH_VARARGS,
    NULL
  },
  {
    "get_package_name",
    nbd_internal_py_get_package_name,
    METH_VARARGS,
    NULL
  },
  {
    "get_version",
    nbd_internal_py_get_version,
    METH_VARARGS,
    NULL
  },
  {
    "kill_subprocess",
    nbd_internal_py_kill_subprocess,
    METH_VARARGS,
    NULL
  },
  {
    "supports_tls",
    nbd_internal_py_supports_tls,
    METH_VARARGS,
    NULL
  },
  {
    "supports_vsock",
    nbd_internal_py_supports_vsock,
    METH_VARARGS,
    NULL
  },
  {
    "supports_uri",
    nbd_internal_py_supports_uri,
    METH_VARARGS,
    NULL
  },
  {
    "get_uri",
    nbd_internal_py_get_uri,
    METH_VARARGS,
    NULL
  },
  { NULL, NULL, 0, NULL }
};

static struct PyModuleDef moduledef = {
  PyModuleDef_HEAD_INIT,
  "libnbdmod",           /* m_name */
  "libnbd module",       /* m_doc */
  -1,                    /* m_size */
  methods,               /* m_methods */
  NULL,                  /* m_reload */
  NULL,                  /* m_traverse */
  NULL,                  /* m_clear */
  NULL,                  /* m_free */
};

/* nbd.Error exception. */
PyObject *nbd_internal_py_Error;

extern PyMODINIT_FUNC PyInit_libnbdmod (void);

PyMODINIT_FUNC
PyInit_libnbdmod (void)
{
  PyObject *mod;

  mod = PyModule_Create (&moduledef);
  if (mod == NULL)
    return NULL;

  nbd_internal_py_Error = PyErr_NewException ("nbd.Error", NULL, NULL);
  if (PyModule_AddObject (mod, "Error", nbd_internal_py_Error) < 0) {
    Py_XDECREF (nbd_internal_py_Error);
    Py_DECREF (mod);
    return NULL;
  }

  return mod;
}