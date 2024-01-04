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

/* Miscellaneous helper functions for Python. */

#include <config.h>

#define PY_SSIZE_T_CLEAN 1
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <libnbd.h>

#include "methods.h"

/* These two functions are used when parsing argv parameters. */
char **
nbd_internal_py_get_string_list (PyObject *obj)
{
  size_t i, len;
  char **r;

  assert (obj);

  if (!PyList_Check (obj)) {
    PyErr_SetString (PyExc_TypeError, "expecting a list parameter");
    return NULL;
  }

  Py_ssize_t slen = PyList_Size (obj);
  if (slen == -1) {
    PyErr_SetString (PyExc_RuntimeError,
                     "get_string_list: PyList_Size failure");
    return NULL;
  }
  len = (size_t)slen;
  r = malloc (sizeof (char *) * (len+1));
  if (r == NULL) {
    PyErr_NoMemory ();
    return NULL;
  }

  for (i = 0; i < len; ++i) {
    PyObject *bytes = PyUnicode_AsUTF8String (PyList_GetItem (obj, i));
    if (!bytes)
      goto err;
    r[i] = strdup (PyBytes_AS_STRING (bytes));
    Py_DECREF (bytes);
    if (r[i] == NULL) {
      PyErr_NoMemory ();
      goto err;
    }
  }
  r[len] = NULL;

  return r;

 err:
  while (i--)
    free (r[i]);
  free (r);
  return NULL;
}

void
nbd_internal_py_free_string_list (char **argv)
{
  size_t i;

  if (!argv)
    return;

  for (i = 0; argv[i] != NULL; ++i)
    free (argv[i]);
  free (argv);
}

/* Convert a Python object into a struct sockaddr, according to the
 * general rules described here:
 * https://docs.python.org/3/library/socket.html
 *
 * There is a function in cpython called getsockaddrarg which roughly
 * does the same thing, but in cpython they know the socket family
 * already (which we do not).  In any case that function cannot be
 * called directly.
 */
int
nbd_internal_py_get_sockaddr (PyObject *addr,
                              struct sockaddr_storage *ss, socklen_t *len)
{
  memset (ss, 0, sizeof *ss);

  if (PyUnicode_Check (addr)) { /* AF_UNIX */
    struct sockaddr_un *sun = (struct sockaddr_un *)ss;
    const char *unixsocket;
    size_t namelen;

    sun->sun_family = AF_UNIX;
    unixsocket = PyUnicode_AsUTF8 (addr);
    if (!unixsocket)
      goto err;
    namelen = strlen (unixsocket);
    if (namelen > sizeof sun->sun_path) {
      PyErr_SetString (PyExc_RuntimeError,
                       "get_sockaddr: Unix domain socket name too long");
      return -1;
    }
    memcpy (sun->sun_path, unixsocket, namelen);
    *len = sizeof *sun;
    return 0;
  }

#if 0
  else if (PyTuple_Check (addr)) {
    Py_ssize_t n = PyTuple_Size (addr);

    switch (n) {
    case 2:                     /* AF_INET */
      /* XXX TODO */
      break;

    case 4:                     /* AF_INET6 */
      /* XXX TODO */
      break;

    default:
      goto err;
    }
  }
#endif

  else {
  err:
    PyErr_SetString (PyExc_TypeError, "get_sockaddr: unknown address type");
    return -1;
  }
}

/* Obtain the type object for nbd.Buffer */
PyObject *
nbd_internal_py_get_nbd_buffer_type (void)
{
  static PyObject *type;

  if (!type) {
    PyObject *modname = PyUnicode_FromString ("nbd");
    PyObject *module = PyImport_Import (modname);
    assert (module);
    type = PyObject_GetAttrString (module, "Buffer");
    assert (type);
    Py_DECREF (modname);
    Py_DECREF (module);
  }
  return type;
}

/* Helper to package callback *error into modifiable PyObject */
PyObject *
nbd_internal_py_wrap_errptr (int err)
{
  static PyObject *py_ctypes_mod;

  if (!py_ctypes_mod) {
    PyObject *py_modname = PyUnicode_FromString ("ctypes");
    if (!py_modname)
      return NULL;
    py_ctypes_mod = PyImport_Import (py_modname);
    Py_DECREF (py_modname);
    if (!py_ctypes_mod)
      return NULL;
  }

  return PyObject_CallMethod (py_ctypes_mod, "c_int", "i", err);
}

/* Helper to compute view.toreadonly()[start:end] in chunk callback */
PyObject *
nbd_internal_py_get_subview (PyObject *view, const char *subbuf, size_t count)
{
  Py_buffer *orig;
  const char *base;
  PyObject *start, *end, *slice;
  PyObject *ret;

  assert (PyMemoryView_Check (view));
  orig = PyMemoryView_GET_BUFFER (view);
  assert (PyBuffer_IsContiguous (orig, 'A'));
  base = orig->buf;
  assert (subbuf >= base && count <= orig->len &&
          subbuf + count <= base + orig->len);
  start = PyLong_FromLong (subbuf - base);
  if (!start) return NULL;
  end = PyLong_FromLong (subbuf - base + count);
  if (!end) { Py_DECREF (start); return NULL; }
  slice = PySlice_New (start, end, NULL);
  Py_DECREF (start);
  Py_DECREF (end);
  if (!slice) return NULL;
  ret = PyObject_GetItem (view, slice);
  Py_DECREF (slice);
  /* memoryview.toreadonly() was only added in Python 3.8.
   * PyMemoryView_GetContiguous (ret, PyBuf_READ, 'A') doesn't force readonly.
   * So we mess around directly with the Py_buffer.
   */
  if (ret)
    PyMemoryView_GET_BUFFER (ret)->readonly = 1;
  return ret;
}
