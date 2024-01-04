(* hey emacs, this is OCaml code: -*- tuareg -*- *)
(* nbd client library in userspace: generator
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
 *)

(* Go language bindings.
 *
 * These are designed so they can be shipped separately and should
 * interwork with older or newer versions of libnbd (to some extent).
 * This means we cannot use <config.h> and must be careful to use
 * #ifdef LIBNBD_HAVE_* from <libnbd.h>
 *)

open Printf

open API
open Utils

let go_name_of_arg = function
  | Bool n -> n
  | BytesIn (n, len) -> n
  | BytesOut (n, len) -> n
  | BytesPersistIn (n, len) -> n
  | BytesPersistOut (n, len) -> n
  | Closure { cbname } -> cbname
  | Enum (n, _) -> n
  | Extent64 _ -> assert false (* only used in extent64_closure *)
  | Fd n -> n
  | Flags (n, _) -> n
  | Int n -> n
  | Int64 n -> n
  | Path n -> n
  | SizeT n -> n
  | SockAddrAndLen (n, len) -> n
  | String n -> n
  | StringList n -> n
  | UInt n -> n
  | UInt32 n -> n
  | UInt64 n -> n
  | UIntPtr n -> n

let go_arg_type = function
  | Bool _ -> "bool"
  | BytesIn _ -> "[]byte"
  | BytesPersistIn _ -> "AioBuffer"
  | BytesOut _ -> "[]byte"
  | BytesPersistOut _ -> "AioBuffer"
  | Closure { cbname } -> sprintf "%sCallback" (camel_case cbname)
  | Enum (_, { enum_prefix }) -> camel_case enum_prefix
  | Extent64 _ -> assert false (* only used in extent64_closure *)
  | Fd _ -> "int"
  | Flags (_, { flag_prefix }) -> camel_case flag_prefix
  | Int _ -> "int"
  | Int64 _ -> "int64"
  | Path _ -> "string"
  | SizeT _ -> "int"
  | SockAddrAndLen _ -> "string"
  | String _ -> "string"
  | StringList _ -> "[]string"
  | UInt _ -> "uint"
  | UInt32 _ -> "uint32"
  | UInt64 _ -> "uint64"
  | UIntPtr _ -> "uint"

let go_name_of_optarg = function
  | OClosure { cbname } -> sprintf "%sCallback" (camel_case cbname)
  | OFlags (n, _, _) -> String.capitalize_ascii n

let go_ret_type = function
  (* RErr returns only the error, with no return value. *)
  | RErr -> None
  | RBool -> Some "bool"
  | RStaticString -> Some "*string"
  | RFd -> Some "int"
  | RInt -> Some "uint"
  | RInt64 -> Some "uint64"
  | RCookie -> Some "uint64"
  | RSizeT -> Some "uint"
  | RString -> Some "*string"
  (* RUInt | RUIntPtr | RUInt64 returns (type, error) for consistency, but the
   * error is always nil unless h is closed
   *)
  | RUInt -> Some "uint"
  | RUIntPtr -> Some "uint"
  | RUInt64 -> Some "uint64"
  | REnum { enum_prefix } -> Some (camel_case enum_prefix)
  | RFlags { flag_prefix } -> Some (camel_case flag_prefix)

let go_ret_error = function
  | RErr -> None
  | RBool -> Some "false"
  | RStaticString | RString -> Some "nil"
  | RFd | RInt | RInt64 | RCookie | RSizeT | RUInt | RUIntPtr | RUInt64
  | REnum _ | RFlags _ -> Some "0"

let go_ret_c_errcode = function
  | RBool -> Some "-1"
  | RStaticString -> Some "nil"
  | RErr | RFd | RInt | RInt64 | RCookie | RSizeT -> Some "-1"
  | RString -> Some "nil"
  | RUInt | RUIntPtr | RUInt64 | REnum _ | RFlags _ -> None

(* We need a wrapper around every function (except Close) to
 * handle errors because cgo calls are sequence points and
 * could result in us being rescheduled on another thread,
 * but libnbd error handling means we must call nbd_get_error
 * etc from the same thread.
 *)
let print_wrapper (name, { args; optargs; ret }) =
  let ret_c_type = C.type_of_ret ret and errcode = C.errcode_of_ret ret in
  let ucname = String.uppercase_ascii name in
  pr "%s\n" ret_c_type;
  pr "_nbd_%s_wrapper (struct error *err,\n" name;
  pr "        ";
  C.print_arg_list ~wrap:true ~handle:true ~parens:NoParens args optargs;
  pr ")\n";
  pr "{\n";
  pr "#ifdef LIBNBD_HAVE_NBD_%s\n" ucname;
  pr "  %s ret;\n" ret_c_type;
  pr "\n";
  pr "  ret = nbd_%s " name;
  C.print_arg_list ~wrap:true ~handle:true ~types:false args optargs;
  pr ";\n";
  (match errcode with
   | None -> ()
   | Some errcode ->
      pr "  if (ret == %s)\n" errcode;
      pr "    save_error (err);\n";
  );
  pr "  return ret;\n";
  pr "#else // !LIBNBD_HAVE_NBD_%s\n" ucname;
  pr "  missing_function (err, \"%s\");\n" name;
  (match errcode with
   | None -> ()
   | Some errcode -> pr "  return %s;\n" errcode
  );
  pr "#endif\n";
  pr "}\n";
  pr "\n"

(* C wrappers around callbacks. *)
let print_callback_wrapper { cbname; cbargs } =
  pr "int\n";
  pr "_nbd_%s_callback_wrapper " cbname;
  C.print_cbarg_list ~wrap:true cbargs;
  pr "\n";
  pr "{\n";
  pr "  return %s_callback ((long)" cbname;
  C.print_cbarg_list ~types:false ~parens:false cbargs;
  pr ");\n";
  pr "}\n";
  pr "\n";
  pr "void\n";
  pr "_nbd_%s_callback_free (void *user_data)\n" cbname;
  pr "{\n";
  pr "  long *p = user_data;\n";
  pr "  extern void freeCallbackId (long);\n";
  pr "  freeCallbackId (*p);\n";
  pr "  free (p);\n";
  pr "}\n";
  pr "\n"

let print_binding (name, { args; optargs; ret; shortdesc }) =
  let cname = camel_case name in

  pr "\n";
  (* Tedious method of passing optional arguments in golang. *)
  if optargs <> [] then (
    pr "/* Struct carrying optional arguments for %s. */\n" cname;
    pr "type %sOptargs struct {\n" cname;
    List.iter (
      fun optarg ->
        let fname = go_name_of_optarg optarg in
        pr "    /* %s field is ignored unless %sSet == true. */\n"
          fname fname;
        pr "    %sSet bool\n" fname;
        pr "    %s    " fname;
        (match optarg with
         | OClosure { cbname } -> pr "%sCallback" (camel_case cbname)
         | OFlags (_, {flag_prefix}, _) -> pr "%s" (camel_case flag_prefix)
        );
        pr "\n"
    ) optargs;
    pr "}\n";
    pr "\n";
  );

  (* Define the golang function which calls the C wrapper. *)
  pr "/* %s: %s */\n" cname shortdesc;
  pr "func (h *Libnbd) %s(" cname;
  let comma = ref false in
  List.iter (
    fun arg ->
      if !comma then pr ", ";
      comma := true;
      pr "%s %s" (go_name_of_arg arg) (go_arg_type arg)
  ) args;
  if optargs <> [] then (
    if !comma then pr ", ";
    comma := true;
    pr "optargs *%sOptargs" cname
  );
  pr ") ";
  (match go_ret_type ret with
   | None -> pr "error"
   | Some t -> pr "(%s, error)" t
  );
  pr " {\n";
  pr "    if h.h == nil {\n";
  (match go_ret_error ret with
   | None -> pr "        return closed_handle_error(\"%s\")\n" name
   | Some v -> pr "        return %s, closed_handle_error(\"%s\")\n" v name
  );
  pr "    }\n";
  pr "\n";
  pr "    var c_err C.struct_error\n";
  List.iter (
    function
    | Bool n ->
       pr "    c_%s := C.bool(%s)\n" n n
    | BytesIn (n, len) ->
       pr "    c_%s := unsafe.Pointer(&%s[0])\n" n n;
       pr "    c_%s := C.size_t(len(%s))\n" len n;
    | BytesOut (n, len) ->
       pr "    c_%s := unsafe.Pointer(&%s[0])\n" n n;
       pr "    c_%s := C.size_t(len(%s))\n" len n;
    | BytesPersistIn (n, len) ->
       pr "    c_%s := %s.P\n" n n;
       pr "    c_%s := C.size_t(%s.Size)\n" len n;
    | BytesPersistOut (n, len) ->
       pr "    c_%s := %s.P\n" n n;
       pr "    c_%s := C.size_t(%s.Size)\n" len n;
    | Closure { cbname } ->
       pr "    var c_%s C.nbd_%s_callback\n" cbname cbname;
       pr "    c_%s.callback = (*[0]byte)(C._nbd_%s_callback_wrapper)\n"
         cbname cbname;
       pr "    c_%s.free = (*[0]byte)(C._nbd_%s_callback_free)\n"
         cbname cbname;
       pr "    %s_cbid := registerCallbackId(%s)\n" cbname cbname;
       pr "    c_%s.user_data = C.alloc_cbid(C.long(%s_cbid))\n" cbname cbname
    | Enum (n, _) ->
       pr "    c_%s := C.int(%s)\n" n n
    | Extent64 _ -> assert false (* only used in extent64_closure *)
    | Fd n ->
       pr "    c_%s := C.int(%s)\n" n n
    | Flags (n, _) ->
       pr "    c_%s := C.uint32_t(%s)\n" n n
    | Int n ->
       pr "    c_%s := C.int(%s)\n" n n
    | Int64 n ->
       pr "    c_%s := C.int64_t(%s)\n" n n
    | Path n ->
       pr "    c_%s := C.CString(%s)\n" n n;
       pr "    defer C.free(unsafe.Pointer(c_%s))\n" n
    | SizeT n ->
       pr "    c_%s := C.size_t(%s)\n" n n
    | SockAddrAndLen (n, len) ->
       pr "    panic(\"SockAddrAndLen not supported\")\n";
       pr "    var c_%s *C.struct_sockaddr\n" n;
       pr "    var c_%s C.uint\n" len
    | String n ->
       pr "    c_%s := C.CString(%s)\n" n n;
       pr "    defer C.free(unsafe.Pointer(c_%s))\n" n
    | StringList n ->
       pr "    c_%s := arg_string_list(%s)\n" n n;
       pr "    defer free_string_list(c_%s)\n" n
    | UInt n ->
       pr "    c_%s := C.uint(%s)\n" n n
    | UInt32 n ->
       pr "    c_%s := C.uint32_t(%s)\n" n n
    | UInt64 n ->
       pr "    c_%s := C.uint64_t(%s)\n" n n
    | UIntPtr n ->
       pr "    c_%s := C.uintptr_t(%s)\n" n n
  ) args;
  if optargs <> [] then (
    List.iter (
      function
      | OClosure { cbname } -> pr "    var c_%s C.nbd_%s_callback\n"
                                 cbname cbname
      | OFlags (n, _, _) -> pr "    var c_%s C.uint32_t\n" n
    ) optargs;
    pr "    if optargs != nil {\n";
    List.iter (
      fun optarg ->
         pr "        if optargs.%sSet {\n" (go_name_of_optarg optarg);
         (match optarg with
          | OClosure { cbname } ->
             pr "            c_%s.callback = (*[0]byte)(C._nbd_%s_callback_wrapper)\n"
               cbname cbname;
             pr "            c_%s.free = (*[0]byte)(C._nbd_%s_callback_free)\n"
               cbname cbname;
             pr "            %s_cbid := registerCallbackId(optargs.%s)\n"
               cbname (go_name_of_optarg optarg);
             pr "            c_%s.user_data = C.alloc_cbid(C.long(%s_cbid))\n"
               cbname cbname
          | OFlags (n, _, _) ->
             pr "            c_%s = C.uint32_t(optargs.%s)\n"
               n (go_name_of_optarg optarg);
         );
         pr "        }\n";
    ) optargs;
    pr "    }\n";
  );
  pr "\n";
  pr "    ret := C._nbd_%s_wrapper(&c_err, h.h" name;
  List.iter (
    function
    | Bool n -> pr ", c_%s" n
    | BytesIn (n, len) -> pr ", c_%s, c_%s" n len
    | BytesOut (n, len) ->  pr ", c_%s, c_%s" n len
    | BytesPersistIn (n, len) ->  pr ", c_%s, c_%s" n len
    | BytesPersistOut (n, len) ->  pr ", c_%s, c_%s" n len
    | Closure { cbname } ->  pr ", c_%s" cbname
    | Enum (n, _) -> pr ", c_%s" n
    | Extent64 _ -> assert false (* only used in extent64_closure *)
    | Fd n -> pr ", c_%s" n
    | Flags (n, _) -> pr ", c_%s" n
    | Int n -> pr ", c_%s" n
    | Int64 n -> pr ", c_%s" n
    | Path n -> pr ", c_%s" n
    | SizeT n -> pr ", c_%s" n
    | SockAddrAndLen (n, len) -> pr ", c_%s, c_%s" n len
    | String n -> pr ", c_%s" n
    | StringList n -> pr ", &c_%s[0]" n
    | UInt n | UIntPtr n -> pr ", c_%s" n
    | UInt32 n -> pr ", c_%s" n
    | UInt64 n -> pr ", c_%s" n
  ) args;
  List.iter (
    function
    | OClosure { cbname} -> pr ", c_%s" cbname
    | OFlags (n, _, _) -> pr ", c_%s" n
  ) optargs;
  pr ")\n";

  (* This ensures that we keep the handle alive until the C
   * function has completed, in case all other references
   * to the handle have disappeared and the finalizer would run.
   *)
  pr "    runtime.KeepAlive(h.h)\n";

  let errcode = go_ret_c_errcode ret in
  (match errcode with
   | None -> ()
   | Some errcode ->
      pr "    if ret == %s {\n" errcode;
      pr "        err := get_error(\"%s\", c_err)\n" name;
      pr "        C.free_error(&c_err)\n";
      (match go_ret_error ret with
       | None -> pr "        return err\n"
       | Some v -> pr "        return %s, err\n" v
      );
      pr "    }\n";
  );
  (match ret with
   | RErr ->
      pr "    return nil\n"
   | RBool ->
      pr "    return int(ret) != 0, nil\n"
   | RStaticString ->
      pr "    /* ret is statically allocated, do not free it. */\n";
      pr "    r := C.GoString(ret)\n";
      pr "    return &r, nil\n"
   | RFd ->
      pr "    return int(ret), nil\n"
   | RInt ->
      pr "    return uint(ret), nil\n"
   | RInt64 ->
      pr "    return uint64(ret), nil\n"
   | RCookie ->
      pr "    return uint64(ret), nil\n"
   | RSizeT ->
      pr "    return uint(ret), nil\n"
   | RString ->
      pr "    r := C.GoString(ret)\n";
      pr "    C.free(unsafe.Pointer(ret))\n";
      pr "    return &r, nil\n"
   | RUInt ->
      pr "    return uint(ret), nil\n"
   | RUIntPtr ->
      pr "    return uint(ret), nil\n"
   | RUInt64 ->
      pr "    return uint64(ret), nil\n"
   | REnum { enum_prefix } ->
      pr "    return %s(ret), nil\n" (camel_case enum_prefix)
   | RFlags { flag_prefix } ->
      pr "    return %s(ret), nil\n" (camel_case flag_prefix)
  );
  pr "}\n"

let generate_golang_bindings_go () =
  generate_header CStyle;

  pr "\
package libnbd

/*
#cgo pkg-config: libnbd
#cgo CFLAGS: -D_GNU_SOURCE=1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include \"libnbd.h\"
#include \"wrappers.h\"

// There must be no blank line between end comment and import!
// https://github.com/golang/go/issues/9733
*/
import \"C\"

import (
    \"runtime\"
    \"unsafe\"
)

/* Enums. */
";
  List.iter (
    fun { enum_prefix; enums } ->
      pr "type %s int\n" (camel_case enum_prefix);
      pr "\n";
      pr "const (\n";
      List.iter (
        fun (enum, v) ->
          pr "    %s_%s = %s(%d)\n" enum_prefix enum (camel_case enum_prefix) v
      ) enums;
      pr ")\n";
      pr "\n"
  ) all_enums;

  pr "\
/* Flags. */
";
  List.iter (
    fun { flag_prefix; flags } ->
      let flag_type = camel_case flag_prefix in
      let mask = ref 0 in
      pr "type %s uint32\n" flag_type;
      pr "\n";
      pr "const (\n";
      List.iter (
        fun (flag, v) ->
          pr "    %s_%s = %s(0x%02x)\n" flag_prefix flag flag_type v;
          mask := !mask lor v
      ) flags;
      pr "    %s_MASK = %s(0x%02x)\n" flag_prefix flag_type !mask;
      pr ")\n";
      pr "\n"
  ) all_flags;

  pr "\
/* Constants. */
const (
";
  List.iter (
    fun (n, v) -> pr "    %s uint32 = %d\n" n v
  ) constants;
  List.iter (
    fun (ns, ctxts) ->
      let ns_upper = String.uppercase_ascii ns in
      pr "    /* Meta-context namespace \"%s\" */\n" ns;
      pr "    NAMESPACE_%s = \"%s:\"\n" ns_upper ns;
      List.iter (
        fun (ctxt, consts) ->
          let ctxt_macro = String.uppercase_ascii (macro_name ctxt) in
          pr "    CONTEXT_%s_%s = \"%s:%s\"\n" ns_upper ctxt_macro ns ctxt;
          if consts <> [] then
            pr "    /* Defined bits in \"%s:%s\" */\n" ns ctxt;
          List.iter (fun (n, v) ->
              pr "    %s uint32 = %d\n" n v
          ) consts
      ) ctxts;
  ) metadata_namespaces;

  pr ")\n";

  (* Bindings. *)
  List.iter print_binding handle_calls

let generate_golang_closures_go () =
  generate_header CStyle;

  pr "\
package libnbd

/*
#cgo pkg-config: libnbd
#cgo CFLAGS: -D_GNU_SOURCE=1

#include <stdlib.h>

#include \"libnbd.h\"
#include \"wrappers.h\"
*/
import \"C\"

import \"unsafe\"

/* Closures. */

func copy_uint32_array(entries *C.uint32_t, count C.size_t) []uint32 {
    ret := make([]uint32, count)
    s := unsafe.Slice(entries, count)
    for i, item := range s {
        ret[i] = uint32(item)
    }
    return ret
}

func copy_extent_array(entries *C.nbd_extent, count C.size_t) []LibnbdExtent {
    ret := make([]LibnbdExtent, count)
    s := unsafe.Slice(entries, count)
    for i, item := range s {
        ret[i].Length = uint64(item.length)
        ret[i].Flags = uint64(item.flags)
    }
    return ret
}
";

  List.iter (
    fun { cbname; cbargs } ->
      let uname = camel_case cbname in
      pr "\n";
      pr "type %sCallback func(" uname;
      let comma = ref false in
      List.iter (
        fun cbarg ->
          if !comma then pr ", "; comma := true;
          match cbarg with
          | CBArrayAndLen (UInt32 n, _) ->
             pr "%s []uint32" n;
          | CBArrayAndLen (Extent64 n, _) ->
             pr "%s []LibnbdExtent" n;
          | CBBytesIn (n, len) ->
             pr "%s []byte" n;
          | CBInt n ->
             pr "%s int" n
          | CBUInt n ->
             pr "%s uint" n
          | CBInt64 n ->
             pr "%s int64" n
          | CBString n ->
             pr "%s string" n
          | CBUInt64 n ->
             pr "%s uint64" n
          | CBMutable (Int n) ->
             pr "%s *int" n
          | CBArrayAndLen _ | CBMutable _ -> assert false
      ) cbargs;
      pr ") int\n";
      pr "\n";
      pr "//export %s_callback\n" cbname;
      pr "func %s_callback(callbackid *C.long" cbname;
      List.iter (
        fun cbarg ->
          pr ", ";
          match cbarg with
          | CBArrayAndLen (UInt32 n, count) ->
             pr "%s *C.uint32_t, %s C.size_t" n count
          | CBArrayAndLen (Extent64 n, count) ->
             pr "%s *C.nbd_extent, %s C.size_t" n count
          | CBBytesIn (n, len) ->
             pr "%s unsafe.Pointer, %s C.size_t" n len
          | CBInt n ->
             pr "%s C.int" n
          | CBUInt n ->
             pr "%s C.uint" n
          | CBInt64 n ->
             pr "%s C.int64_t" n
          | CBString n ->
             pr "%s *C.char" n
          | CBUInt64 n ->
             pr "%s C.uint64_t" n
          | CBMutable (Int n) ->
             pr "%s *C.int" n
          | CBArrayAndLen _ | CBMutable _ -> assert false
      ) cbargs;
      pr ") C.int {\n";
      pr "    callbackFunc := getCallbackId(int(*callbackid))\n";
      pr "    callback, ok := callbackFunc.(%sCallback)\n" uname;
      pr "    if !ok {\n";
      pr "        panic(\"inappropriate callback type\")\n";
      pr "    }\n";

      (* Deal with mutable int by creating a local variable
       * and passing a pointer to it to the callback.
       *)
      List.iter (
        fun cbarg ->
          match cbarg with
          | CBMutable (Int n) ->
             pr "    go_%s := int(*%s)\n" n n
          | _ -> ()
      ) cbargs;

      pr "    ret := callback(";
      let comma = ref false in
      List.iter (
        fun cbarg ->
          if !comma then pr ", "; comma := true;
          match cbarg with
          | CBArrayAndLen (UInt32 n, count) ->
             pr "copy_uint32_array(%s, %s)" n count
          | CBArrayAndLen (Extent64 n, count) ->
             pr "copy_extent_array(%s, %s)" n count
          | CBBytesIn (n, len) ->
             pr "C.GoBytes(%s, C.int(%s))" n len
          | CBInt n ->
             pr "int(%s)" n
          | CBUInt n ->
             pr "uint(%s)" n
          | CBInt64 n ->
             pr "int64(%s)" n
          | CBString n ->
             pr "C.GoString(%s)" n
          | CBUInt64 n ->
             pr "uint64(%s)" n
          | CBMutable (Int n) ->
             pr "&go_%s" n
          | CBArrayAndLen _ | CBMutable _ -> assert false
      ) cbargs;
      pr ")\n";

      List.iter (
        fun cbarg ->
          match cbarg with
          | CBMutable (Int n) ->
             pr "    *%s = C.int(go_%s)\n" n n
          | _ -> ()
      ) cbargs;
      pr "    return C.int(ret)\n";
      pr "}\n"
  ) all_closures

let generate_golang_wrappers_go () =
  generate_header CStyle;

  pr "\
package libnbd

/*
#cgo pkg-config: libnbd
#cgo CFLAGS: -D_GNU_SOURCE=1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include \"libnbd.h\"
#include \"wrappers.h\"

";

  (* Wrappers. *)
  List.iter print_wrapper handle_calls;

  (* Callback wrappers. *)
  List.iter print_callback_wrapper all_closures;

  pr "\
// There must be no blank line between end comment and import!
// https://github.com/golang/go/issues/9733
*/
import \"C\"
"

let generate_golang_wrappers_h () =
  generate_header CStyle;

  pr "\
#ifndef LIBNBD_GOLANG_WRAPPERS_H
#define LIBNBD_GOLANG_WRAPPERS_H

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include \"libnbd.h\"

/* When calling callbacks we pass the callback ID (a golang int /
 * C.long) in the void *user_data field.  We need to create a block
 * to store the callback number.  This must be freed by C.free(vp)
 */
static inline void *
alloc_cbid (long i)
{
  long *p = malloc (sizeof (long));
  assert (p != NULL);
  *p = i;
  return p;
}

/* save_error is called from the same thread to make a copy
 * of the error which can later be retrieve from golang code
 * possibly running in a different thread.
 */
struct error {
  char *error;
  int errnum;
};

static inline void
save_error (struct error *err)
{
  err->error = strdup (nbd_get_error ());
  err->errnum = nbd_get_errno ();
}

static inline void
free_error (struct error *err)
{
  free (err->error);
}

/* If you mix old C library and new bindings then some C
 * functions may not be defined.  They return ENOTSUP.
 */
static inline void
missing_function (struct error *err, const char *fn)
{
  asprintf (&err->error, \"%%s: \"
            \"function missing because golang bindings were compiled \"
            \"against an old version of the C library\", fn);
  err->errnum = ENOTSUP;
}

";

  (* Function decl for each wrapper. *)
  List.iter (
    fun (name, { args; optargs; ret }) ->
      let ret_c_type = C.type_of_ret ret in
      pr "%s _nbd_%s_wrapper (struct error *err,\n" ret_c_type name;
      pr "        ";
      C.print_arg_list ~wrap:true ~handle:true ~parens:NoParens args optargs;
      pr ");\n";
  ) handle_calls;
  pr "\n";

  (* Function decl for each callback wrapper. *)
  List.iter (
    fun { cbname; cbargs } ->
      (*
       * It would be nice to do this, but it basically means we have
       * to guess the prototype that golang will generate for a
       * golang exported function.  Also golang doesn't bother with
       * const-correctness.
       pr "extern int %s_callback (long callbackid" cbname;
       List.iter (
         fun cbarg ->
           pr ", ";
           match cbarg with
           | CBArrayAndLen (UInt32 n, count) ->
              pr "uint32_t *%s, size_t %s" n count
           | CBArrayAndLen (Extent64 n, count) ->
              pr "nbd_extent *%s, size_t %s" n count
           | CBBytesIn (n, len) ->
              pr "void *%s, size_t %s" n len
           | CBInt n ->
              pr "int %s" n
           | CBUInt n ->
              pr "unsigned int %s" n
           | CBInt64 n ->
              pr "int64_t %s" n
           | CBString n ->
              pr "char *%s" n
           | CBUInt64 n ->
              pr "uint64_t *%s" n
           | CBMutable (Int n) ->
              pr "int *%s" n
           | CBArrayAndLen _ | CBMutable _ -> assert false
       ) cbargs;
       pr ");\n";
       pr "\n";
       * So instead we do this:
       *)
      pr "extern int %s_callback ();\n" cbname;
      pr "\n";
      pr "int _nbd_%s_callback_wrapper " cbname;
      C.print_cbarg_list ~wrap:true cbargs;
      pr ";\n";
      pr "void _nbd_%s_callback_free (void *user_data);\n" cbname;
      pr "\n";
  ) all_closures;

  pr "\
#endif /* LIBNBD_GOLANG_WRAPPERS_H */
"
