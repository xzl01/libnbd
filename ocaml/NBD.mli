(* NBD client library in userspace
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
 *)

(** OCaml bindings for libnbd.

    For full documentation see libnbd-ocaml(3) and libnbd(3).

    For examples written in OCaml see the libnbd source code
    [ocaml/examples] subdirectory.
*)

exception Error of string * Unix.error option
(** Exception thrown when an API call fails.

    The string is the error message, and the int is the {!Unix.error}
    (if available).
*)

exception Closed of string
(** Exception thrown if you call a closed handle. *)

type cookie = int64

type extent = int64 * int64
(** Length and flags of an extent in {!block_status_64} callback. *)

module TLS : sig
  type t =
  | DISABLE
  | ALLOW
  | REQUIRE
  | UNKNOWN of int
end

module SIZE : sig
  type t =
  | MINIMUM
  | PREFERRED
  | MAXIMUM
  | PAYLOAD
  | UNKNOWN of int
end

module CMD_FLAG : sig
  type t =
  | FUA
  | NO_HOLE
  | DF
  | REQ_ONE
  | FAST_ZERO
  | PAYLOAD_LEN
  | UNKNOWN of int

  val mask : t list
end

module HANDSHAKE_FLAG : sig
  type t =
  | FIXED_NEWSTYLE
  | NO_ZEROES
  | UNKNOWN of int

  val mask : t list
end

module STRICT : sig
  type t =
  | COMMANDS
  | FLAGS
  | BOUNDS
  | ZERO_SIZE
  | ALIGN
  | PAYLOAD
  | AUTO_FLAG
  | UNKNOWN of int

  val mask : t list
end

module ALLOW_TRANSPORT : sig
  type t =
  | TCP
  | UNIX
  | VSOCK
  | UNKNOWN of int

  val mask : t list
end

module SHUTDOWN : sig
  type t =
  | ABANDON_PENDING
  | UNKNOWN of int

  val mask : t list
end

val aio_direction_read : int32
val aio_direction_write : int32
val aio_direction_both : int32
val read_data : int32
val read_hole : int32
val read_error : int32
val namespace_base : string
val context_base_allocation : string
val state_hole : int32
val state_zero : int32
val namespace_qemu : string
val context_qemu_dirty_bitmap : string
val state_dirty : int32
val context_qemu_allocation_depth : string

module Buffer : sig
  type t
  (** Persistent, mutable C-compatible malloc'd buffer, used in AIO calls. *)

  val alloc : int -> t
  (** Allocate an uninitialized buffer.  The parameter is the size
      in bytes. *)

  val to_bytes : t -> bytes
  (** Copy buffer to an OCaml [bytes] object. *)

  val of_bytes : bytes -> t
  (** Copy an OCaml [bytes] object to a newly allocated buffer. *)

  val size : t -> int
  (** Return the size of the buffer. *)

end
(** Persistent buffer used in AIO calls. *)

val errno_of_unix_error : Unix.error -> int
(** Return the raw C errno corresponding to a {!Unix.error}.  This
    can be used in callbacks to update the [int ref] parameter. *)

type t
(** The handle. *)

val create : unit -> t
(** Create a new handle. *)

val close : t -> unit
(** Close a handle.

    Handles can also be closed by the garbage collector when
    they become unreachable.  This call is used only if you want
    to force the handle to close now and reclaim resources
    immediately.
*)

val with_handle : (t -> 'a) -> 'a
(** Wrapper around {!create}.  It calls the function parameter with a
    newly created handle, and ensures that {!close} is always called
    even if the function throws an exception.

    Use this when it is essential that the handle is closed in order
    to free up external resources in a timely manner; for example if
    running the server as a subprocess and you want to ensure that the
    subprocess is always killed; or if you need to disconnect from the
    server before continuing with another operation. *)

val set_debug : t -> bool -> unit
(** [NBD.set_debug t debug]

    set or clear the debug flag

    Set or clear the debug flag. When debugging is enabled,
    debugging messages from the library are printed to
    stderr, unless a debugging callback has been defined too
    (see nbd_set_debug_callback(3)) in which case they are
    sent to that function. This flag defaults to false on
    newly created handles, except if "LIBNBD_DEBUG=1" is set
    in the environment in which case it defaults to true.
*)

val get_debug : t -> bool
(** [NBD.get_debug t]

    return the state of the debug flag

    Return the state of the debug flag on this handle.
*)

val set_debug_callback : t -> (string -> string -> int) -> unit
(** [NBD.set_debug_callback t debug]

    set the debug callback

    Set the debug callback. This function is called when the
    library emits debug messages, when debugging is enabled
    on a handle. The callback parameters are "user_data"
    passed to this function, the name of the libnbd function
    emitting the debug message ("context"), and the message
    itself ("msg"). If no debug callback is set on a handle
    then messages are printed on "stderr".

    The callback should not call "nbd_*" APIs on the same
    handle since it can be called while holding the handle
    lock and will cause a deadlock.
*)

val clear_debug_callback : t -> unit
(** [NBD.clear_debug_callback t]

    clear the debug callback

    Remove the debug callback if one was previously
    associated with the handle (with
    nbd_set_debug_callback(3)). If no callback was
    associated this does nothing.
*)

val stats_bytes_sent : t -> int64
(** [NBD.stats_bytes_sent t]

    statistics of bytes sent over connection so far

    Return the number of bytes that the client has sent to
    the server.

    This tracks the plaintext bytes utilized by the NBD
    protocol; it may differ from the number of bytes
    actually sent over the connection, particularly when TLS
    is in use.
*)

val stats_chunks_sent : t -> int64
(** [NBD.stats_chunks_sent t]

    statistics of chunks sent over connection so far

    Return the number of chunks that the client has sent to
    the server, where a chunk is a group of bytes delineated
    by a magic number that cannot be further subdivided
    without breaking the protocol.

    This number does not necessarily relate to the number of
    API calls made, nor to the number of TCP packets sent
    over the connection.
*)

val stats_bytes_received : t -> int64
(** [NBD.stats_bytes_received t]

    statistics of bytes received over connection so far

    Return the number of bytes that the client has received
    from the server.

    This tracks the plaintext bytes utilized by the NBD
    protocol; it may differ from the number of bytes
    actually received over the connection, particularly when
    TLS is in use.
*)

val stats_chunks_received : t -> int64
(** [NBD.stats_chunks_received t]

    statistics of chunks received over connection so far

    Return the number of chunks that the client has received
    from the server, where a chunk is a group of bytes
    delineated by a magic number that cannot be further
    subdivided without breaking the protocol.

    This number does not necessarily relate to the number of
    API calls made, nor to the number of TCP packets
    received over the connection.
*)

val set_handle_name : t -> string -> unit
(** [NBD.set_handle_name t handle_name]

    set the handle name

    Handles have a name which is unique within the current
    process. The handle name is used in debug output.

    Handle names are normally generated automatically and
    have the form "nbd1", "nbd2", etc., but you can
    optionally use this call to give the handles a name
    which is meaningful for your application to make
    debugging output easier to understand.
*)

val get_handle_name : t -> string
(** [NBD.get_handle_name t]

    get the handle name

    Get the name of the handle. If it was previously set by
    calling nbd_set_handle_name(3) then this returns the
    name that was set. Otherwise it will return a generic
    name like "nbd1", "nbd2", etc.
*)

val set_private_data : t -> int -> int
(** [NBD.set_private_data t private_data]

    set the per-handle private data

    Handles contain a private data field for applications to
    use for any purpose.

    When calling libnbd from C, the type of this field is
    "uintptr_t" so it can be used to store an unsigned
    integer or a pointer.

    In non-C bindings it can be used to store an unsigned
    integer.

    This function sets the value of this field and returns
    the old value (or 0 if it was not previously set).
*)

val get_private_data : t -> int
(** [NBD.get_private_data t]

    get the per-handle private data

    Return the value of the private data field set
    previously by a call to nbd_set_private_data(3) (or 0 if
    it was not previously set).
*)

val set_export_name : t -> string -> unit
(** [NBD.set_export_name t export_name]

    set the export name

    For servers which require an export name or can serve
    different content on different exports, set the
    "export_name" to connect to. The default is the empty
    string "".

    This is only relevant when connecting to servers using
    the newstyle protocol as the oldstyle protocol did not
    support export names. The NBD protocol limits export
    names to 4096 bytes, but servers may not support the
    full length. The encoding of export names is always
    UTF-8.

    When option mode is not in use, the export name must be
    set before beginning a connection. However, when
    nbd_set_opt_mode(3) has enabled option mode, it is
    possible to change the export name prior to
    nbd_opt_go(3). In particular, the use of nbd_opt_list(3)
    during negotiation can be used to determine a name the
    server is likely to accept, and nbd_opt_info(3) can be
    used to learn details about an export before connecting.

    This call may be skipped if using nbd_connect_uri(3) to
    connect to a URI that includes an export name.
*)

val get_export_name : t -> string
(** [NBD.get_export_name t]

    get the export name

    Get the export name associated with the handle. This is
    the name that libnbd requests; see
    nbd_get_canonical_export_name(3) for determining if the
    server has a different canonical name for the given
    export (most common when requesting the default export
    name of an empty string "")
*)

val set_request_block_size : t -> bool -> unit
(** [NBD.set_request_block_size t request]

    control whether NBD_OPT_GO requests block size

    By default, when connecting to an export, libnbd
    requests that the server report any block size
    restrictions. The NBD protocol states that a server may
    supply block sizes regardless of whether the client
    requests them, and libnbd will report those block sizes
    (see nbd_get_block_size(3)); conversely, if a client
    does not request block sizes, the server may reject the
    connection instead of dealing with a client sending
    unaligned requests. This function makes it possible to
    test server behavior by emulating older clients.

    Note that even when block size is requested, the server
    is not obligated to provide any. Furthermore, if block
    sizes are provided (whether or not the client requested
    them), libnbd enforces alignment to those sizes unless
    nbd_set_strict_mode(3) is used to bypass client-side
    safety checks.
*)

val get_request_block_size : t -> bool
(** [NBD.get_request_block_size t]

    see if NBD_OPT_GO requests block size

    Return the state of the block size request flag on this
    handle.
*)

val set_full_info : t -> bool -> unit
(** [NBD.set_full_info t request]

    control whether NBD_OPT_GO requests extra details

    By default, when connecting to an export, libnbd only
    requests the details it needs to service data
    operations. The NBD protocol says that a server can
    supply optional information, such as a canonical name of
    the export (see nbd_get_canonical_export_name(3)) or a
    description of the export (see
    nbd_get_export_description(3)), but that a hint from the
    client makes it more likely for this extra information
    to be provided. This function controls whether libnbd
    will provide that hint.

    Note that even when full info is requested, the server
    is not obligated to reply with all information that
    libnbd requested. Similarly, libnbd will ignore any
    optional server information that libnbd has not yet been
    taught to recognize. Furthermore, the hint to request
    block sizes is independently controlled via
    nbd_set_request_block_size(3).
*)

val get_full_info : t -> bool
(** [NBD.get_full_info t]

    see if NBD_OPT_GO requests extra details

    Return the state of the full info request flag on this
    handle.
*)

val get_canonical_export_name : t -> string
(** [NBD.get_canonical_export_name t]

    return the canonical export name, if the server has one

    The NBD protocol permits a server to report an optional
    canonical export name, which may differ from the
    client's request (as set by nbd_set_export_name(3) or
    nbd_connect_uri(3)). This function accesses any name
    returned by the server; it may be the same as the client
    request, but is more likely to differ when the client
    requested a connection to the default export name (an
    empty string "").

    Some servers are unlikely to report a canonical name
    unless the client specifically hinted about wanting it,
    via nbd_set_full_info(3).
*)

val get_export_description : t -> string
(** [NBD.get_export_description t]

    return the export description, if the server has one

    The NBD protocol permits a server to report an optional
    export description. This function reports any
    description returned by the server.

    Some servers are unlikely to report a description unless
    the client specifically hinted about wanting it, via
    nbd_set_full_info(3). For qemu-nbd(8), a description is
    set with *-D*.
*)

val set_tls : t -> TLS.t -> unit
(** [NBD.set_tls t tls]

    enable or require TLS (authentication and encryption)

    Enable or require TLS (authenticated and encrypted
    connections) to the NBD server. The possible settings
    are:

    "LIBNBD_TLS_DISABLE"
        Disable TLS. (The default setting, unless using
        nbd_connect_uri(3) with a URI that requires TLS).

        This setting is also necessary if you use
        nbd_set_opt_mode(3) and want to interact in
        plaintext with a server that implements the NBD
        protocol's "SELECTIVETLS" mode, prior to enabling
        TLS with nbd_opt_starttls(3). Most NBD servers with
        TLS support prefer the NBD protocol's "FORCEDTLS"
        mode, so this sort of manual interaction tends to be
        useful mainly during integration testing.

    "LIBNBD_TLS_ALLOW"
        Enable TLS if possible.

        This option is insecure (or best effort) in that in
        some cases it will fall back to an unencrypted
        and/or unauthenticated connection if TLS could not
        be established. Use "LIBNBD_TLS_REQUIRE" below if
        the connection must be encrypted.

        Some servers will drop the connection if TLS fails
        so fallback may not be possible.

    "LIBNBD_TLS_REQUIRE"
        Require an encrypted and authenticated TLS
        connection. Always fail to connect if the connection
        is not encrypted and authenticated.

    As well as calling this you may also need to supply the
    path to the certificates directory
    (nbd_set_tls_certificates(3)), the username
    (nbd_set_tls_username(3)) and/or the Pre-Shared Keys
    (PSK) file (nbd_set_tls_psk_file(3)). For now, when
    using nbd_connect_uri(3), any URI query parameters
    related to TLS are not handled automatically. Setting
    the level higher than zero will fail if libnbd was not
    compiled against gnutls; you can test whether this is
    the case with nbd_supports_tls(3).
*)

val get_tls : t -> TLS.t
(** [NBD.get_tls t]

    get the TLS request setting

    Get the TLS request setting.

    Note: If you want to find out if TLS was actually
    negotiated on a particular connection use
    nbd_get_tls_negotiated(3) instead.
*)

val get_tls_negotiated : t -> bool
(** [NBD.get_tls_negotiated t]

    find out if TLS was negotiated on a connection

    After connecting you may call this to find out if the
    connection is using TLS.

    This is normally useful only if you set the TLS request
    mode to "LIBNBD_TLS_ALLOW" (see nbd_set_tls(3)), because
    in this mode we try to use TLS but fall back to
    unencrypted if it was not available. This function will
    tell you if TLS was negotiated or not.

    In "LIBNBD_TLS_REQUIRE" mode (the most secure) the
    connection would have failed if TLS could not be
    negotiated. With "LIBNBD_TLS_DISABLE" mode, TLS is not
    tried automatically; but if the NBD server uses the
    less-common "SELECTIVETLS" mode, this function reports
    whether a manual nbd_opt_starttls(3) enabled TLS or if
    the connection is still plaintext.
*)

val set_tls_certificates : t -> string -> unit
(** [NBD.set_tls_certificates t dir]

    set the path to the TLS certificates directory

    Set the path to the TLS certificates directory. If not
    set and TLS is used then a compiled in default is used.
    For root this is "/etc/pki/libnbd/". For non-root this
    is "$HOME/.pki/libnbd" and "$HOME/.config/pki/libnbd".
    If none of these directories can be found then the
    system trusted CAs are used.

    This function may be called regardless of whether TLS is
    supported, but will have no effect unless nbd_set_tls(3)
    is also used to request or require TLS.
*)

val set_tls_verify_peer : t -> bool -> unit
(** [NBD.set_tls_verify_peer t verify]

    set whether we verify the identity of the server

    Set this flag to control whether libnbd will verify the
    identity of the server from the server's certificate and
    the certificate authority. This defaults to true when
    connecting to TCP servers using TLS certificate
    authentication, and false otherwise.

    This function may be called regardless of whether TLS is
    supported, but will have no effect unless nbd_set_tls(3)
    is also used to request or require TLS.
*)

val get_tls_verify_peer : t -> bool
(** [NBD.get_tls_verify_peer t]

    get whether we verify the identity of the server

    Get the verify peer flag.
*)

val set_tls_username : t -> string -> unit
(** [NBD.set_tls_username t username]

    set the TLS username

    Set the TLS client username. This is used if
    authenticating with PSK over TLS is enabled. If not set
    then the local username is used.

    This function may be called regardless of whether TLS is
    supported, but will have no effect unless nbd_set_tls(3)
    is also used to request or require TLS.
*)

val get_tls_username : t -> string
(** [NBD.get_tls_username t]

    get the current TLS username

    Get the current TLS username.
*)

val set_tls_psk_file : t -> string -> unit
(** [NBD.set_tls_psk_file t filename]

    set the TLS Pre-Shared Keys (PSK) filename

    Set the TLS Pre-Shared Keys (PSK) filename. This is used
    if trying to authenticate to the server using with a
    pre-shared key. There is no default so if this is not
    set then PSK authentication cannot be used to connect to
    the server.

    This function may be called regardless of whether TLS is
    supported, but will have no effect unless nbd_set_tls(3)
    is also used to request or require TLS.
*)

val set_request_extended_headers : t -> bool -> unit
(** [NBD.set_request_extended_headers t request]

    control use of extended headers

    By default, libnbd tries to negotiate extended headers
    with the server, as this protocol extension permits the
    use of 64-bit zero, trim, and block status actions.
    However, for integration testing, it can be useful to
    clear this flag rather than find a way to alter the
    server to fail the negotiation request.

    For backwards compatibility, the setting of this knob is
    ignored if nbd_set_request_structured_replies(3) is also
    set to false, since the use of extended headers implies
    structured replies.
*)

val get_request_extended_headers : t -> bool
(** [NBD.get_request_extended_headers t]

    see if extended headers are attempted

    Return the state of the request extended headers flag on
    this handle.

    Note: If you want to find out if extended headers were
    actually negotiated on a particular connection use
    nbd_get_extended_headers_negotiated(3) instead.
*)

val get_extended_headers_negotiated : t -> bool
(** [NBD.get_extended_headers_negotiated t]

    see if extended headers are in use

    After connecting you may call this to find out if the
    connection is using extended headers. Note that this
    setting is sticky; this can return true even after a
    second nbd_opt_extended_headers(3) returns false because
    the server detected a duplicate request.

    When extended headers are not in use, commands are
    limited to a 32-bit length, even when the libnbd API
    uses a 64-bit parameter to express the length. But even
    when extended headers are supported, the server may
    enforce other limits, visible through
    nbd_get_block_size(3).

    Note that when extended headers are negotiated, you
    should prefer the use of nbd_block_status_64(3) instead
    of nbd_block_status(3) if any of the meta contexts you
    requested via nbd_add_meta_context(3) might return
    64-bit status values; however, all of the well-known
    meta contexts covered by current "LIBNBD_CONTEXT_*"
    constants only return 32-bit status.
*)

val set_request_structured_replies : t -> bool -> unit
(** [NBD.set_request_structured_replies t request]

    control use of structured replies

    By default, libnbd tries to negotiate structured replies
    with the server, as this protocol extension must be in
    use before nbd_can_meta_context(3) or nbd_can_df(3) can
    return true. However, for integration testing, it can be
    useful to clear this flag rather than find a way to
    alter the server to fail the negotiation request. It is
    also useful to set this to false prior to using
    nbd_set_opt_mode(3) if it is desired to control when to
    send nbd_opt_structured_reply(3) during negotiation.

    Note that setting this knob to false also disables any
    automatic request for extended headers.
*)

val get_request_structured_replies : t -> bool
(** [NBD.get_request_structured_replies t]

    see if structured replies are attempted

    Return the state of the request structured replies flag
    on this handle.

    Note: If you want to find out if structured replies were
    actually negotiated on a particular connection use
    nbd_get_structured_replies_negotiated(3) instead.
*)

val get_structured_replies_negotiated : t -> bool
(** [NBD.get_structured_replies_negotiated t]

    see if structured replies are in use

    After connecting you may call this to find out if the
    connection is using structured replies. Note that this
    setting is sticky; this can return true even after a
    second nbd_opt_structured_reply(3) returns false because
    the server detected a duplicate request.

    Note that if the connection negotiates extended headers,
    this function returns true (as extended headers imply
    structured replies) even if no explicit request for
    structured replies was attempted.
*)

val set_request_meta_context : t -> bool -> unit
(** [NBD.set_request_meta_context t request]

    control whether connect automatically requests meta contexts

    This function controls whether the act of connecting to
    an export (all "nbd_connect_*" calls when
    nbd_set_opt_mode(3) is false, or nbd_opt_go(3) and
    nbd_opt_info(3) when option mode is enabled) will also
    try to issue NBD_OPT_SET_META_CONTEXT when the server
    supports structured replies or extended headers and any
    contexts were registered by nbd_add_meta_context(3). The
    default setting is true; however the extra step of
    negotiating meta contexts is not always desirable:
    performing both info and go on the same export works
    without needing to re-negotiate contexts on the second
    call; integration testing of other servers may benefit
    from manual invocation of nbd_opt_set_meta_context(3) at
    other times in the negotiation sequence; and even when
    using just nbd_opt_info(3), it can be faster to collect
    the server's results by relying on the callback function
    passed to nbd_opt_list_meta_context(3) than a series of
    post-process calls to nbd_can_meta_context(3).

    Note that this control has no effect if the server does
    not negotiate structured replies or extended headers, or
    if the client did not request any contexts via
    nbd_add_meta_context(3). Setting this control to false
    may cause nbd_block_status(3) to fail.
*)

val get_request_meta_context : t -> bool
(** [NBD.get_request_meta_context t]

    see if connect automatically requests meta contexts

    Return the state of the automatic meta context request
    flag on this handle.
*)

val set_handshake_flags : t -> HANDSHAKE_FLAG.t list -> unit
(** [NBD.set_handshake_flags t flags]

    control use of handshake flags

    By default, libnbd tries to negotiate all possible
    handshake flags that are also supported by the server,
    since omitting a handshake flag can prevent the use of
    other functionality such as TLS encryption or structured
    replies. However, for integration testing, it can be
    useful to reduce the set of flags supported by the
    client to test that a particular server can handle
    various clients that were compliant to older versions of
    the NBD specification.

    The "flags" argument is a bitmask, including zero or
    more of the following handshake flags:

    "LIBNBD_HANDSHAKE_FLAG_FIXED_NEWSTYLE" = 1
        The server gracefully handles unknown option
        requests from the client, rather than disconnecting.
        Without this flag, a client cannot safely request to
        use extensions such as TLS encryption or structured
        replies, as the request may cause an older server to
        drop the connection.

    "LIBNBD_HANDSHAKE_FLAG_NO_ZEROES" = 2
        If the client is forced to use "NBD_OPT_EXPORT_NAME"
        instead of the preferred "NBD_OPT_GO", this flag
        allows the server to send fewer all-zero padding
        bytes over the connection.

    For convenience, the constant
    "LIBNBD_HANDSHAKE_FLAG_MASK" is available to describe
    all flags supported by this build of libnbd. Future NBD
    extensions may add further flags, which in turn may be
    enabled by default in newer libnbd. As such, when
    attempting to disable only one specific bit, it is wiser
    to first call nbd_get_handshake_flags(3) and modify that
    value, rather than blindly setting a constant value.
*)

val get_handshake_flags : t -> HANDSHAKE_FLAG.t list
(** [NBD.get_handshake_flags t]

    see which handshake flags are supported

    Return the state of the handshake flags on this handle.
    When the handle has not yet completed a connection (see
    nbd_aio_is_created(3)), this returns the flags that the
    client is willing to use, provided the server also
    advertises those flags. After the connection is ready
    (see nbd_aio_is_ready(3)), this returns the flags that
    were actually agreed on between the server and client.
    If the NBD protocol defines new handshake flags, then
    the return value from a newer library version may
    include bits that were undefined at the time of
    compilation.
*)

val set_pread_initialize : t -> bool -> unit
(** [NBD.set_pread_initialize t request]

    control whether libnbd pre-initializes read buffers

    By default, libnbd will pre-initialize the contents of a
    buffer passed to calls such as nbd_pread(3) to all
    zeroes prior to checking for any other errors, so that
    even if a client application passed in an uninitialized
    buffer but fails to check for errors, it will not result
    in a potential security risk caused by an accidental
    leak of prior heap contents (see CVE-2022-0485 in
    libnbd-security(3) for an example of a security hole in
    an application built against an earlier version of
    libnbd that lacked consistent pre-initialization).
    However, for a client application that has audited that
    an uninitialized buffer is never dereferenced, or which
    performs its own pre-initialization, libnbd's
    sanitization efforts merely pessimize performance
    (although the time spent in pre-initialization may pale
    in comparison to time spent waiting on network packets).

    Calling this function with "request" set to false tells
    libnbd to skip the buffer initialization step in read
    commands.
*)

val get_pread_initialize : t -> bool
(** [NBD.get_pread_initialize t]

    see whether libnbd pre-initializes read buffers

    Return whether libnbd performs a pre-initialization of a
    buffer passed to nbd_pread(3) and similar to all zeroes,
    as set by nbd_set_pread_initialize(3).
*)

val set_strict_mode : t -> STRICT.t list -> unit
(** [NBD.set_strict_mode t flags]

    control how strictly to follow NBD protocol

    By default, libnbd tries to detect requests that would
    trigger undefined behavior in the NBD protocol, and
    rejects them client side without causing any network
    traffic, rather than risking undefined server behavior.
    However, for integration testing, it can be handy to
    relax the strictness of libnbd, to coerce it into
    sending such requests over the network for testing the
    robustness of the server in dealing with such traffic.

    The "flags" argument is a bitmask, including zero or
    more of the following strictness flags:

    "LIBNBD_STRICT_COMMANDS" = 0x1
        If set, this flag rejects client requests that do
        not comply with the set of advertised server flags
        (for example, attempting a write on a read-only
        server, or attempting to use "LIBNBD_CMD_FLAG_FUA"
        when nbd_can_fua(3) returned false). If clear, this
        flag relies on the server to reject unexpected
        commands.

    "LIBNBD_STRICT_FLAGS" = 0x2
        If set, this flag rejects client requests that
        attempt to set a command flag not recognized by
        libnbd (those outside of "LIBNBD_CMD_FLAG_MASK"), or
        a flag not normally associated with a command (such
        as using "LIBNBD_CMD_FLAG_FUA" on a read command).
        If clear, all flags are sent on to the server, even
        if sending such a flag may cause the server to
        change its reply in a manner that confuses libnbd,
        perhaps causing deadlock or ending the connection.

        Flags that are known by libnbd as associated with a
        given command (such as "LIBNBD_CMD_FLAG_DF" for
        nbd_pread_structured(3) gated by nbd_can_df(3)) are
        controlled by "LIBNBD_STRICT_COMMANDS" instead; and
        "LIBNBD_CMD_FLAG_PAYLOAD_LEN" is managed
        automatically by libnbd unless
        "LIBNBD_STRICT_AUTO_FLAG" is disabled.

        Note that the NBD protocol only supports 16 bits of
        command flags, even though the libnbd API uses
        "uint32_t"; bits outside of the range permitted by
        the protocol are always a client-side error.

    "LIBNBD_STRICT_BOUNDS" = 0x4
        If set, this flag rejects client requests that would
        exceed the export bounds without sending any traffic
        to the server. If clear, this flag relies on the
        server to detect out-of-bounds requests.

    "LIBNBD_STRICT_ZERO_SIZE" = 0x8
        If set, this flag rejects client requests with
        length 0. If clear, this permits zero-length
        requests to the server, which may produce undefined
        results.

    "LIBNBD_STRICT_ALIGN" = 0x10
        If set, and the server provided minimum block sizes
        (see "LIBNBD_SIZE_MINIMUM" for
        nbd_get_block_size(3)), this flag rejects client
        requests that do not have length and offset aligned
        to the server's minimum requirements. If clear,
        unaligned requests are sent to the server, where it
        is up to the server whether to honor or reject the
        request.

    "LIBNBD_STRICT_PAYLOAD" = 0x20
        If set, the client refuses to send a command to the
        server with more than libnbd's outgoing payload
        maximum (see "LIBNBD_SIZE_PAYLOAD" for
        nbd_get_block_size(3)), whether or not the server
        advertised a block size maximum. If clear, oversize
        requests up to 64MiB may be attempted, although
        requests larger than 32MiB are liable to cause some
        servers to disconnect.

    "LIBNBD_STRICT_AUTO_FLAG" = 0x40
        If set, commands that accept the
        "LIBNBD_CMD_FLAG_PAYLOAD_LEN" flag (such as
        nbd_pwrite(3) and nbd_block_status_filter(3)) ignore
        the presence or absence of that flag from the
        caller, instead sending the value over the wire that
        matches the server's expectations based on whether
        extended headers were negotiated when the connection
        was made. If clear, the caller takes on the
        responsibility for whether the payload length flag
        is set or clear during the affected command, which
        can be useful during integration testing but is more
        likely to lead to undefined behavior.

    For convenience, the constant "LIBNBD_STRICT_MASK" is
    available to describe all strictness flags supported by
    this build of libnbd. Future versions of libnbd may add
    further flags, which are likely to be enabled by default
    for additional client-side filtering. As such, when
    attempting to relax only one specific bit while keeping
    remaining checks at the client side, it is wiser to
    first call nbd_get_strict_mode(3) and modify that value,
    rather than blindly setting a constant value.
*)

val get_strict_mode : t -> STRICT.t list
(** [NBD.get_strict_mode t]

    see which strictness flags are in effect

    Return flags indicating which protocol strictness items
    are being enforced locally by libnbd rather than the
    server. The return value from a newer library version
    may include bits that were undefined at the time of
    compilation.
*)

val set_opt_mode : t -> bool -> unit
(** [NBD.set_opt_mode t enable]

    control option mode, for pausing during option negotiation

    Set this flag to true in order to request that a
    connection command "nbd_connect_*" will pause for
    negotiation options rather than proceeding all the way
    to the ready state, when communicating with a newstyle
    server. This setting has no effect when connecting to an
    oldstyle server.

    Note that libnbd defaults to attempting
    "NBD_OPT_STARTTLS", "NBD_OPT_EXTENDED_HEADERS", and
    "NBD_OPT_STRUCTURED_REPLY" before letting you control
    remaining negotiation steps; if you need control over
    these steps as well, first set nbd_set_tls(3) to
    "LIBNBD_TLS_DISABLE", and
    nbd_set_request_extended_headers(3) or
    nbd_set_request_structured_replies(3) to false, before
    starting the connection attempt.

    When option mode is enabled, you have fine-grained
    control over which options are negotiated, compared to
    the default of the server negotiating everything on your
    behalf using settings made before starting the
    connection. To leave the mode and proceed on to the
    ready state, you must use nbd_opt_go(3) successfully; a
    failed nbd_opt_go(3) returns to the negotiating state to
    allow a change of export name before trying again. You
    may also use nbd_opt_abort(3) or nbd_shutdown(3) to end
    the connection without finishing negotiation.
*)

val get_opt_mode : t -> bool
(** [NBD.get_opt_mode t]

    return whether option mode was enabled

    Return true if option negotiation mode was enabled on
    this handle.
*)

val opt_go : t -> unit
(** [NBD.opt_go t]

    end negotiation and move on to using an export

    Request that the server finish negotiation and move on
    to serving the export previously specified by the most
    recent nbd_set_export_name(3) or nbd_connect_uri(3).
    This can only be used if nbd_set_opt_mode(3) enabled
    option mode.

    By default, libnbd will automatically request all meta
    contexts registered by nbd_add_meta_context(3) as part
    of this call; but this can be suppressed with
    nbd_set_request_meta_context(3), particularly if
    nbd_opt_set_meta_context(3) was used earlier in the
    negotiation sequence.

    If this fails, the server may still be in negotiation,
    where it is possible to attempt another option such as a
    different export name; although older servers will
    instead have killed the connection.
*)

val opt_abort : t -> unit
(** [NBD.opt_abort t]

    end negotiation and close the connection

    Request that the server finish negotiation, gracefully
    if possible, then close the connection. This can only be
    used if nbd_set_opt_mode(3) enabled option mode.
*)

val opt_starttls : t -> bool
(** [NBD.opt_starttls t]

    request the server to initiate TLS

    Request that the server initiate a secure TLS
    connection, by sending "NBD_OPT_STARTTLS". This can only
    be used if nbd_set_opt_mode(3) enabled option mode;
    furthermore, if you use nbd_set_tls(3) to request
    anything other than the default of "LIBNBD_TLS_DISABLE",
    then libnbd will have already attempted a TLS connection
    prior to allowing you control over option negotiation.
    This command is disabled if nbd_supports_tls(3) reports
    false.

    This function is mainly useful for integration testing
    of corner cases in server handling; in particular,
    misuse of this function when coupled with a server that
    is not careful about resetting stateful commands such as
    nbd_opt_structured_reply(3) could result in a security
    hole (see CVE-2021-3716 against nbdkit, for example).
    Thus, when security is a concern, you should instead
    prefer to use nbd_set_tls(3) with "LIBNBD_TLS_REQUIRE"
    and let libnbd negotiate TLS automatically.

    This function returns true if the server replies with
    success, false if the server replies with an error, and
    fails only if the server does not reply (such as for a
    loss of connection, which can include when the server
    rejects credentials supplied during the TLS handshake).
    Note that the NBD protocol documents that requesting TLS
    after it is already enabled is a client error; most
    servers will gracefully fail a second request, but that
    does not downgrade a TLS session that has already been
    established, as reported by nbd_get_tls_negotiated(3).
*)

val opt_extended_headers : t -> bool
(** [NBD.opt_extended_headers t]

    request the server to enable extended headers

    Request that the server use extended headers, by sending
    "NBD_OPT_EXTENDED_HEADERS". This can only be used if
    nbd_set_opt_mode(3) enabled option mode; furthermore,
    libnbd defaults to automatically requesting this unless
    you use nbd_set_request_extended_headers(3) or
    nbd_set_request_structured_replies(3) prior to
    connecting. This function is mainly useful for
    integration testing of corner cases in server handling.

    This function returns true if the server replies with
    success, false if the server replies with an error, and
    fails only if the server does not reply (such as for a
    loss of connection). Note that some servers fail a
    second request as redundant; libnbd assumes that once
    one request has succeeded, then extended headers are
    supported (as visible by
    nbd_get_extended_headers_negotiated(3)) regardless if
    later calls to this function return false. If this
    function returns true, the use of structured replies is
    implied.
*)

val opt_structured_reply : t -> bool
(** [NBD.opt_structured_reply t]

    request the server to enable structured replies

    Request that the server use structured replies, by
    sending "NBD_OPT_STRUCTURED_REPLY". This can only be
    used if nbd_set_opt_mode(3) enabled option mode;
    furthermore, libnbd defaults to automatically requesting
    this unless you use
    nbd_set_request_structured_replies(3) prior to
    connecting. This function is mainly useful for
    integration testing of corner cases in server handling.

    This function returns true if the server replies with
    success, false if the server replies with an error, and
    fails only if the server does not reply (such as for a
    loss of connection). Note that some servers fail a
    second request as redundant; libnbd assumes that once
    one request has succeeded, then structured replies are
    supported (as visible by
    nbd_get_structured_replies_negotiated(3)) regardless if
    later calls to this function return false. Similarly, a
    server may fail this request if extended headers are
    already negotiated, since extended headers take
    priority.
*)

val opt_list : t -> (string -> string -> int) -> int
(** [NBD.opt_list t list]

    request the server to list all exports during negotiation

    Request that the server list all exports that it
    supports. This can only be used if nbd_set_opt_mode(3)
    enabled option mode.

    The "list" function is called once per advertised
    export, with any "user_data" passed to this function,
    and with "name" and "description" supplied by the
    server. Many servers omit descriptions, in which case
    "description" will be an empty string. Remember that it
    is not safe to call nbd_set_export_name(3) from within
    the context of the callback function; rather, your code
    must copy any "name" needed for later use after this
    function completes. At present, the return value of the
    callback is ignored, although a return of -1 should be
    avoided.

    For convenience, when this function succeeds, it returns
    the number of exports that were advertised by the
    server.

    Not all servers understand this request, and even when
    it is understood, the server might intentionally send an
    empty list to avoid being an information leak, may
    encounter a failure after delivering partial results, or
    may refuse to answer more than one query per connection
    in the interest of avoiding negotiation that does not
    resolve. Thus, this function may succeed even when no
    exports are reported, or may fail but have a non-empty
    list. Likewise, the NBD protocol does not specify an
    upper bound for the number of exports that might be
    advertised, so client code should be aware that a server
    may send a lengthy list.

    For nbd-server(1) you will need to allow clients to make
    list requests by adding "allowlist=true" to the
    "[generic]" section of /etc/nbd-server/config. For
    qemu-nbd(8), a description is set with *-D*.
*)

val opt_info : t -> unit
(** [NBD.opt_info t]

    request the server for information about an export

    Request that the server supply information about the
    export name previously specified by the most recent
    nbd_set_export_name(3) or nbd_connect_uri(3). This can
    only be used if nbd_set_opt_mode(3) enabled option mode.

    If successful, functions like nbd_is_read_only(3) and
    nbd_get_size(3) will report details about that export.
    If nbd_set_request_meta_context(3) is set (the default)
    and structured replies or extended headers were
    negotiated, it is also valid to use
    nbd_can_meta_context(3) after this call. However, it may
    be more efficient to clear that setting and manually
    utilize nbd_opt_list_meta_context(3) with its callback
    approach, for learning which contexts an export
    supports. In general, if nbd_opt_go(3) is called next,
    that call will likely succeed with the details remaining
    the same, although this is not guaranteed by all
    servers.

    Not all servers understand this request, and even when
    it is understood, the server might fail the request even
    when a corresponding nbd_opt_go(3) would succeed.
*)

val opt_list_meta_context : t -> (string -> int) -> int
(** [NBD.opt_list_meta_context t context]

    list available meta contexts, using implicit query list

    Request that the server list available meta contexts
    associated with the export previously specified by the
    most recent nbd_set_export_name(3) or
    nbd_connect_uri(3), and with a list of queries from
    prior calls to nbd_add_meta_context(3) (see
    nbd_opt_list_meta_context_queries(3) if you want to
    supply an explicit query list instead). This can only be
    used if nbd_set_opt_mode(3) enabled option mode.

    The NBD protocol allows a client to decide how many
    queries to ask the server. Rather than taking that list
    of queries as a parameter to this function, libnbd
    reuses the current list of requested meta contexts as
    set by nbd_add_meta_context(3); you can use
    nbd_clear_meta_contexts(3) to set up a different list of
    queries. When the list is empty, a server will typically
    reply with all contexts that it supports; when the list
    is non-empty, the server will reply only with supported
    contexts that match the client's request. Note that a
    reply by the server might be encoded to represent
    several feasible contexts within one string, rather than
    multiple strings per actual context name that would
    actually succeed during nbd_opt_go(3); so it is still
    necessary to use nbd_can_meta_context(3) after
    connecting to see which contexts are actually supported.

    The "context" function is called once per server reply,
    with any "user_data" passed to this function, and with
    "name" supplied by the server. Remember that it is not
    safe to call nbd_add_meta_context(3) from within the
    context of the callback function; rather, your code must
    copy any "name" needed for later use after this function
    completes. At present, the return value of the callback
    is ignored, although a return of -1 should be avoided.

    For convenience, when this function succeeds, it returns
    the number of replies returned by the server.

    Not all servers understand this request, and even when
    it is understood, the server might intentionally send an
    empty list because it does not support the requested
    context, or may encounter a failure after delivering
    partial results. Thus, this function may succeed even
    when no contexts are reported, or may fail but have a
    non-empty list. Likewise, the NBD protocol does not
    specify an upper bound for the number of replies that
    might be advertised, so client code should be aware that
    a server may send a lengthy list.
*)

val opt_list_meta_context_queries : t -> string list -> (string -> int) -> int
(** [NBD.opt_list_meta_context_queries t queries context]

    list available meta contexts, using explicit query list

    Request that the server list available meta contexts
    associated with the export previously specified by the
    most recent nbd_set_export_name(3) or
    nbd_connect_uri(3), and with an explicit list of queries
    provided as a parameter (see
    nbd_opt_list_meta_context(3) if you want to reuse an
    implicit query list instead). This can only be used if
    nbd_set_opt_mode(3) enabled option mode.

    The NBD protocol allows a client to decide how many
    queries to ask the server. For this function, the list
    is explicit in the "queries" parameter. When the list is
    empty, a server will typically reply with all contexts
    that it supports; when the list is non-empty, the server
    will reply only with supported contexts that match the
    client's request. Note that a reply by the server might
    be encoded to represent several feasible contexts within
    one string, rather than multiple strings per actual
    context name that would actually succeed during
    nbd_opt_go(3); so it is still necessary to use
    nbd_can_meta_context(3) after connecting to see which
    contexts are actually supported.

    The "context" function is called once per server reply,
    with any "user_data" passed to this function, and with
    "name" supplied by the server. Remember that it is not
    safe to call nbd_add_meta_context(3) from within the
    context of the callback function; rather, your code must
    copy any "name" needed for later use after this function
    completes. At present, the return value of the callback
    is ignored, although a return of -1 should be avoided.

    For convenience, when this function succeeds, it returns
    the number of replies returned by the server.

    Not all servers understand this request, and even when
    it is understood, the server might intentionally send an
    empty list because it does not support the requested
    context, or may encounter a failure after delivering
    partial results. Thus, this function may succeed even
    when no contexts are reported, or may fail but have a
    non-empty list. Likewise, the NBD protocol does not
    specify an upper bound for the number of replies that
    might be advertised, so client code should be aware that
    a server may send a lengthy list.
*)

val opt_set_meta_context : t -> (string -> int) -> int
(** [NBD.opt_set_meta_context t context]

    select specific meta contexts, using implicit query list

    Request that the server supply all recognized meta
    contexts registered through prior calls to
    nbd_add_meta_context(3), in conjunction with the export
    previously specified by the most recent
    nbd_set_export_name(3) or nbd_connect_uri(3). This can
    only be used if nbd_set_opt_mode(3) enabled option mode.
    Normally, this function is redundant, as nbd_opt_go(3)
    automatically does the same task if structured replies
    or extended headers have already been negotiated. But
    manual control over meta context requests can be useful
    for fine-grained testing of how a server handles unusual
    negotiation sequences. Often, use of this function is
    coupled with nbd_set_request_meta_context(3) to bypass
    the automatic context request normally performed by
    nbd_opt_go(3).

    The NBD protocol allows a client to decide how many
    queries to ask the server. Rather than taking that list
    of queries as a parameter to this function, libnbd
    reuses the current list of requested meta contexts as
    set by nbd_add_meta_context(3); you can use
    nbd_clear_meta_contexts(3) to set up a different list of
    queries (see nbd_opt_set_meta_context_queries(3) to pass
    an explicit list of contexts instead). Since this
    function is primarily designed for testing servers,
    libnbd does not prevent the use of this function on an
    empty list or when nbd_set_request_structured_replies(3)
    has disabled structured replies, in order to see how a
    server behaves.

    The "context" function is called once per server reply,
    with any "user_data" passed to this function, and with
    "name" supplied by the server. Additionally, each server
    name will remain visible through nbd_can_meta_context(3)
    until the next attempt at nbd_set_export_name(3) or
    nbd_opt_set_meta_context(3), as well as nbd_opt_go(3) or
    nbd_opt_info(3) that trigger an automatic meta context
    request. Remember that it is not safe to call any
    "nbd_*" APIs from within the context of the callback
    function. At present, the return value of the callback
    is ignored, although a return of -1 should be avoided.

    For convenience, when this function succeeds, it returns
    the number of replies returned by the server.

    Not all servers understand this request, and even when
    it is understood, the server might intentionally send an
    empty list because it does not support the requested
    context, or may encounter a failure after delivering
    partial results. Thus, this function may succeed even
    when no contexts are reported, or may fail but have a
    non-empty list.
*)

val opt_set_meta_context_queries : t -> string list -> (string -> int) -> int
(** [NBD.opt_set_meta_context_queries t queries context]

    select specific meta contexts, using explicit query list

    Request that the server supply all recognized meta
    contexts passed in through "queries", in conjunction
    with the export previously specified by the most recent
    nbd_set_export_name(3) or nbd_connect_uri(3). This can
    only be used if nbd_set_opt_mode(3) enabled option mode.
    Normally, this function is redundant, as nbd_opt_go(3)
    automatically does the same task if structured replies
    or extended headers have already been negotiated. But
    manual control over meta context requests can be useful
    for fine-grained testing of how a server handles unusual
    negotiation sequences. Often, use of this function is
    coupled with nbd_set_request_meta_context(3) to bypass
    the automatic context request normally performed by
    nbd_opt_go(3).

    The NBD protocol allows a client to decide how many
    queries to ask the server. This function takes an
    explicit list of queries; to instead reuse an implicit
    list, see nbd_opt_set_meta_context(3). Since this
    function is primarily designed for testing servers,
    libnbd does not prevent the use of this function on an
    empty list or when nbd_set_request_structured_replies(3)
    has disabled structured replies, in order to see how a
    server behaves.

    The "context" function is called once per server reply,
    with any "user_data" passed to this function, and with
    "name" supplied by the server. Additionally, each server
    name will remain visible through nbd_can_meta_context(3)
    until the next attempt at nbd_set_export_name(3) or
    nbd_opt_set_meta_context(3), as well as nbd_opt_go(3) or
    nbd_opt_info(3) that trigger an automatic meta context
    request. Remember that it is not safe to call any
    "nbd_*" APIs from within the context of the callback
    function. At present, the return value of the callback
    is ignored, although a return of -1 should be avoided.

    For convenience, when this function succeeds, it returns
    the number of replies returned by the server.

    Not all servers understand this request, and even when
    it is understood, the server might intentionally send an
    empty list because it does not support the requested
    context, or may encounter a failure after delivering
    partial results. Thus, this function may succeed even
    when no contexts are reported, or may fail but have a
    non-empty list.
*)

val add_meta_context : t -> string -> unit
(** [NBD.add_meta_context t name]

    ask server to negotiate metadata context

    During connection libnbd can negotiate zero or more
    metadata contexts with the server. Metadata contexts are
    features (such as "base:allocation") which describe
    information returned by the nbd_block_status_64(3)
    command (for "base:allocation" this is whether blocks of
    data are allocated, zero or sparse).

    This call adds one metadata context to the list to be
    negotiated. You can call it as many times as needed. The
    list is initially empty when the handle is created; you
    can check the contents of the list with
    nbd_get_nr_meta_contexts(3) and nbd_get_meta_context(3),
    or clear it with nbd_clear_meta_contexts(3).

    The NBD protocol limits meta context names to 4096
    bytes, but servers may not support the full length. The
    encoding of meta context names is always UTF-8.

    Not all servers support all metadata contexts. To learn
    if a context was actually negotiated, call
    nbd_can_meta_context(3) after connecting.

    The single parameter is the name of the metadata
    context, for example "LIBNBD_CONTEXT_BASE_ALLOCATION".
    <libnbd.h> includes defined constants beginning with
    "LIBNBD_CONTEXT_" for some well-known contexts, but you
    are free to pass in other contexts.

    Other metadata contexts are server-specific, but include
    "qemu:dirty-bitmap:..." and "qemu:allocation-depth" for
    qemu-nbd (see qemu-nbd *-B* and *-A* options).
*)

val get_nr_meta_contexts : t -> int
(** [NBD.get_nr_meta_contexts t]

    return the current number of requested meta contexts

    During connection libnbd can negotiate zero or more
    metadata contexts with the server. Metadata contexts are
    features (such as "base:allocation") which describe
    information returned by the nbd_block_status_64(3)
    command (for "base:allocation" this is whether blocks of
    data are allocated, zero or sparse).

    This command returns how many meta contexts have been
    added to the list to request from the server via
    nbd_add_meta_context(3). The server is not obligated to
    honor all of the requests; to see what it actually
    supports, see nbd_can_meta_context(3).
*)

val get_meta_context : t -> int -> string
(** [NBD.get_meta_context t i]

    return the i'th meta context request

    During connection libnbd can negotiate zero or more
    metadata contexts with the server. Metadata contexts are
    features (such as "base:allocation") which describe
    information returned by the nbd_block_status_64(3)
    command (for "base:allocation" this is whether blocks of
    data are allocated, zero or sparse).

    This command returns the i'th meta context request, as
    added by nbd_add_meta_context(3), and bounded by
    nbd_get_nr_meta_contexts(3).
*)

val clear_meta_contexts : t -> unit
(** [NBD.clear_meta_contexts t]

    reset the list of requested meta contexts

    During connection libnbd can negotiate zero or more
    metadata contexts with the server. Metadata contexts are
    features (such as "base:allocation") which describe
    information returned by the nbd_block_status_64(3)
    command (for "base:allocation" this is whether blocks of
    data are allocated, zero or sparse).

    This command resets the list of meta contexts to request
    back to an empty list, for re-population by further use
    of nbd_add_meta_context(3). It is primarily useful when
    option negotiation mode is selected (see
    nbd_set_opt_mode(3)), for altering the list of attempted
    contexts between subsequent export queries.
*)

val set_uri_allow_transports : t -> ALLOW_TRANSPORT.t list -> unit
(** [NBD.set_uri_allow_transports t mask]

    set the allowed transports in NBD URIs

    Set which transports are allowed to appear in NBD URIs.
    The default is to allow any transport.

    The "mask" parameter may contain any of the following
    flags ORed together:

    "LIBNBD_ALLOW_TRANSPORT_TCP" = 0x1
    "LIBNBD_ALLOW_TRANSPORT_UNIX" = 0x2
    "LIBNBD_ALLOW_TRANSPORT_VSOCK" = 0x4

    For convenience, the constant
    "LIBNBD_ALLOW_TRANSPORT_MASK" is available to describe
    all transports recognized by this build of libnbd. A
    future version of the library may add new flags.
*)

val set_uri_allow_tls : t -> TLS.t -> unit
(** [NBD.set_uri_allow_tls t tls]

    set the allowed TLS settings in NBD URIs

    Set which TLS settings are allowed to appear in NBD
    URIs. The default is to allow either non-TLS or TLS
    URIs.

    The "tls" parameter can be:

    "LIBNBD_TLS_DISABLE"
        TLS URIs are not permitted, ie. a URI such as
        "nbds://..." will be rejected.

    "LIBNBD_TLS_ALLOW"
        This is the default. TLS may be used or not,
        depending on whether the URI uses "nbds" or "nbd".

    "LIBNBD_TLS_REQUIRE"
        TLS URIs are required. All URIs must use "nbds".
*)

val set_uri_allow_local_file : t -> bool -> unit
(** [NBD.set_uri_allow_local_file t allow]

    set the allowed transports in NBD URIs

    Allow NBD URIs to reference local files. This is
    *disabled* by default.

    Currently this setting only controls whether the
    "tls-psk-file" parameter in NBD URIs is allowed.
*)

val connect_uri : t -> string -> unit
(** [NBD.connect_uri t uri]

    connect to NBD URI

    Connect (synchronously) to an NBD server and export by
    specifying the NBD URI. This call parses the URI and
    calls nbd_set_export_name(3) and nbd_set_tls(3) and
    other calls as needed, followed by nbd_connect_tcp(3),
    nbd_connect_unix(3) or nbd_connect_vsock(3).

    This call returns when the connection has been made. By
    default, this proceeds all the way to transmission
    phase, but nbd_set_opt_mode(3) can be used for manual
    control over option negotiation performed before
    transmission phase.

  Example URIs supported
    "nbd://example.com"
        Connect over TCP, unencrypted, to "example.com" port
        10809.

    "nbds://example.com"
        Connect over TCP with TLS, to "example.com" port
        10809. If the server does not support TLS then this
        will fail.

    "nbd+unix:///foo?socket=/tmp/nbd.sock"
        Connect over the Unix domain socket /tmp/nbd.sock to
        an NBD server running locally. The export name is
        set to "foo" (note without any leading "/"
        character).

    "nbds+unix://alice@/?socket=/tmp/nbd.sock&tls-certificat
    es=certs"
        Connect over a Unix domain socket, enabling TLS and
        setting the path to a directory containing
        certificates and keys.

    "nbd+vsock:///"
        In this scenario libnbd is running in a virtual
        machine. Connect over "AF_VSOCK" to an NBD server
        running on the hypervisor.

  Supported URI formats
    The following schemes are supported in the current
    version of libnbd:

    "nbd:"
        Connect over TCP without using TLS.

    "nbds:"
        Connect over TCP. TLS is required and the connection
        will fail if the server does not support TLS.

    "nbd+unix:"
    "nbds+unix:"
        Connect over a Unix domain socket, without or with
        TLS respectively. The "socket" parameter is
        required.

    "nbd+vsock:"
    "nbds+vsock:"
        Connect over the "AF_VSOCK" transport, without or
        with TLS respectively. You can use
        nbd_supports_vsock(3) to see if this build of libnbd
        supports "AF_VSOCK".

    The authority part of the URI
    ("[username@][servername][:port]") is parsed depending
    on the transport. For TCP it specifies the server to
    connect to and optional port number. For "+unix" it
    should not be present. For "+vsock" the server name is
    the numeric CID (eg. 2 to connect to the host), and the
    optional port number may be present. If the "username"
    is present it is used for TLS authentication.

    For all transports, an export name may be present,
    parsed in accordance with the NBD URI specification.

    Finally the query part of the URI can contain:

    socket=SOCKET
        Specifies the Unix domain socket to connect on. Must
        be present for the "+unix" transport and must not be
        present for the other transports.

    tls-certificates=DIR
        Set the certificates directory. See
        nbd_set_tls_certificates(3). Note this is not
        allowed by default - see next section.

    tls-psk-file=PSKFILE
        Set the PSK file. See nbd_set_tls_psk_file(3). Note
        this is not allowed by default - see next section.

  Disable URI features
    For security reasons you might want to disable certain
    URI features. Pre-filtering URIs is error-prone and
    should not be attempted. Instead use the libnbd APIs
    below to control what can appear in URIs. Note you must
    call these functions on the same handle before calling
    nbd_connect_uri(3) or nbd_aio_connect_uri(3).

    TCP, Unix domain socket or "AF_VSOCK" transports
        Default: all allowed

        To select which transports are allowed call
        nbd_set_uri_allow_transports(3).

    TLS Default: both non-TLS and TLS connections allowed

        To force TLS off or on in URIs call
        nbd_set_uri_allow_tls(3).

    Connect to Unix domain socket in the local filesystem
        Default: allowed

        To prevent this you must disable the "+unix"
        transport using nbd_set_uri_allow_transports(3).

    Read from local files
        Default: denied

        To allow URIs to contain references to local files
        (eg. for parameters like "tls-psk-file") call
        nbd_set_uri_allow_local_file(3).

  Overriding the export name
    It is possible to override the export name portion of a
    URI by using nbd_set_opt_mode(3) to enable option mode,
    then using nbd_set_export_name(3) and nbd_opt_go(3) as
    part of subsequent negotiation.

  Optional features
    This call will fail if libnbd was not compiled with
    libxml2; you can test whether this is the case with
    nbd_supports_uri(3).

    Support for URIs that require TLS will fail if libnbd
    was not compiled with gnutls; you can test whether this
    is the case with nbd_supports_tls(3).

  Constructing a URI from an existing connection
    See nbd_get_uri(3).
*)

val connect_unix : t -> string -> unit
(** [NBD.connect_unix t unixsocket]

    connect to NBD server over a Unix domain socket

    Connect (synchronously) over the named Unix domain
    socket ("unixsocket") to an NBD server running on the
    same machine.

    This call returns when the connection has been made. By
    default, this proceeds all the way to transmission
    phase, but nbd_set_opt_mode(3) can be used for manual
    control over option negotiation performed before
    transmission phase.
*)

val connect_vsock : t -> int64 (* uint32_t *) -> int64 (* uint32_t *) -> unit
(** [NBD.connect_vsock t cid port]

    connect to NBD server over AF_VSOCK protocol

    Connect (synchronously) over the "AF_VSOCK" protocol
    from a virtual machine to an NBD server, usually running
    on the host. The "cid" and "port" parameters specify the
    server address. Usually "cid" should be 2 (to connect to
    the host), and "port" might be 10809 or another port
    number assigned to you by the host administrator.

    Not all systems support "AF_VSOCK"; to determine if
    libnbd was built on a system with vsock support, see
    nbd_supports_vsock(3).

    This call returns when the connection has been made. By
    default, this proceeds all the way to transmission
    phase, but nbd_set_opt_mode(3) can be used for manual
    control over option negotiation performed before
    transmission phase.
*)

val connect_tcp : t -> string -> string -> unit
(** [NBD.connect_tcp t hostname port]

    connect to NBD server over a TCP port

    Connect (synchronously) to the NBD server listening on
    "hostname:port". The "port" may be a port name such as
    "nbd", or it may be a port number as a string such as
    "10809".

    This call returns when the connection has been made. By
    default, this proceeds all the way to transmission
    phase, but nbd_set_opt_mode(3) can be used for manual
    control over option negotiation performed before
    transmission phase.
*)

val connect_socket : t -> Unix.file_descr -> unit
(** [NBD.connect_socket t sock]

    connect directly to a connected socket

    Pass a connected socket "sock" through which libnbd will
    talk to the NBD server.

    The caller is responsible for creating and connecting
    this socket by some method, before passing it to libnbd.

    If this call returns without error then socket ownership
    is passed to libnbd. Libnbd will close the socket when
    the handle is closed. The caller must not use the socket
    in any way.

    This call returns when the connection has been made. By
    default, this proceeds all the way to transmission
    phase, but nbd_set_opt_mode(3) can be used for manual
    control over option negotiation performed before
    transmission phase.
*)

val connect_command : t -> string list -> unit
(** [NBD.connect_command t argv]

    connect to NBD server command

    Run the command as a subprocess and connect to it over
    stdin/stdout. This is for use with NBD servers which can
    behave like inetd clients, such as nbdkit(1) using the
    *-s*/*--single* flag, and nbd-server(1) with port number
    set to 0.

    To run qemu-nbd(1), use
    nbd_connect_systemd_socket_activation(3) instead.

  Subprocess
    Libnbd will fork the "argv" command and pass the NBD
    socket to it using file descriptors 0 and 1
    (stdin/stdout):

     ┌─────────┬─────────┐    ┌────────────────┐
     │ program │ libnbd  │    │   NBD server   │
     │         │         │    │       (argv)   │
     │         │ socket ╍╍╍╍╍╍╍╍▶ stdin/stdout │
     └─────────┴─────────┘    └────────────────┘

    When the NBD handle is closed the server subprocess is
    killed.

    This call returns when the connection has been made. By
    default, this proceeds all the way to transmission
    phase, but nbd_set_opt_mode(3) can be used for manual
    control over option negotiation performed before
    transmission phase.
*)

val connect_systemd_socket_activation : t -> string list -> unit
(** [NBD.connect_systemd_socket_activation t argv]

    connect using systemd socket activation

    Run the command as a subprocess and connect to it using
    systemd socket activation.

    This is especially useful for running qemu-nbd(1) as a
    subprocess of libnbd, for example to use it to open
    qcow2 files.

    To run nbdkit as a subprocess, this function can be
    used, or nbd_connect_command(3).

    To run nbd-server(1) as a subprocess, this function
    cannot be used, you must use nbd_connect_command(3).

  Socket activation
    Libnbd will fork the "argv" command and pass an NBD
    socket to it using special "LISTEN_*" environment
    variables (as defined by the systemd socket activation
    protocol).

     ┌─────────┬─────────┐    ┌───────────────┐
     │ program │ libnbd  │    │  qemu-nbd or  │
     │         │         │    │  other server │
     │         │ socket ╍╍╍╍╍╍╍╍▶             │
     └─────────┴─────────┘    └───────────────┘

    When the NBD handle is closed the server subprocess is
    killed.

   Socket name
    The socket activation protocol lets you optionally give
    the socket a name. If used, the name is passed to the
    NBD server using the "LISTEN_FDNAMES" environment
    variable. To provide a socket name, call
    nbd_set_socket_activation_name(3) before calling the
    connect function.

    This call returns when the connection has been made. By
    default, this proceeds all the way to transmission
    phase, but nbd_set_opt_mode(3) can be used for manual
    control over option negotiation performed before
    transmission phase.
*)

val set_socket_activation_name : t -> string -> unit
(** [NBD.set_socket_activation_name t socket_name]

    set the socket activation name

    When running an NBD server using
    nbd_connect_systemd_socket_activation(3) you can
    optionally name the socket. Call this function before
    connecting to the server.

    Some servers such as qemu-storage-daemon(1) can use this
    information to associate the socket with a name used on
    the command line, but most servers will ignore it. The
    name is passed through the "LISTEN_FDNAMES" environment
    variable.

    The parameter "socket_name" can be a short alphanumeric
    string. If it is set to the empty string (also the
    default when the handle is created) then the name
    "unknown" will be seen by the server.
*)

val get_socket_activation_name : t -> string
(** [NBD.get_socket_activation_name t]

    get the socket activation name

    Return the socket name used when you call
    nbd_connect_systemd_socket_activation(3) on the same
    handle. By default this will return the empty string
    meaning that the server will see the name "unknown".
*)

val is_read_only : t -> bool
(** [NBD.is_read_only t]

    is the NBD export read-only?

    Returns true if the NBD export is read-only; writes and
    write-like operations will fail.

    This call does not block, because it returns data that
    is saved in the handle from the NBD protocol handshake.
*)

val can_flush : t -> bool
(** [NBD.can_flush t]

    does the server support the flush command?

    Returns true if the server supports the flush command
    (see nbd_flush(3), nbd_aio_flush(3)). Returns false if
    the server does not.

    This call does not block, because it returns data that
    is saved in the handle from the NBD protocol handshake.
*)

val can_fua : t -> bool
(** [NBD.can_fua t]

    does the server support the FUA flag?

    Returns true if the server supports the FUA flag on
    certain commands (see nbd_pwrite(3)).

    This call does not block, because it returns data that
    is saved in the handle from the NBD protocol handshake.
*)

val is_rotational : t -> bool
(** [NBD.is_rotational t]

    is the NBD disk rotational (like a disk)?

    Returns true if the disk exposed over NBD is rotational
    (like a traditional floppy or hard disk). Returns false
    if the disk has no penalty for random access (like an
    SSD or RAM disk).

    This call does not block, because it returns data that
    is saved in the handle from the NBD protocol handshake.
*)

val can_trim : t -> bool
(** [NBD.can_trim t]

    does the server support the trim command?

    Returns true if the server supports the trim command
    (see nbd_trim(3), nbd_aio_trim(3)). Returns false if the
    server does not.

    This call does not block, because it returns data that
    is saved in the handle from the NBD protocol handshake.
*)

val can_zero : t -> bool
(** [NBD.can_zero t]

    does the server support the zero command?

    Returns true if the server supports the zero command
    (see nbd_zero(3), nbd_aio_zero(3)). Returns false if the
    server does not.

    This call does not block, because it returns data that
    is saved in the handle from the NBD protocol handshake.
*)

val can_fast_zero : t -> bool
(** [NBD.can_fast_zero t]

    does the server support the fast zero flag?

    Returns true if the server supports the use of the
    "LIBNBD_CMD_FLAG_FAST_ZERO" flag to the zero command
    (see nbd_zero(3), nbd_aio_zero(3)). Returns false if the
    server does not.

    This call does not block, because it returns data that
    is saved in the handle from the NBD protocol handshake.
*)

val can_block_status_payload : t -> bool
(** [NBD.can_block_status_payload t]

    does the server support the block status payload flag?

    Returns true if the server supports the use of the
    "LIBNBD_CMD_FLAG_PAYLOAD_LEN" flag to allow filtering of
    the block status command (see
    nbd_block_status_filter(3)). Returns false if the server
    does not. Note that this will never return true if
    nbd_get_extended_headers_negotiated(3) is false.

    This call does not block, because it returns data that
    is saved in the handle from the NBD protocol handshake.
*)

val can_df : t -> bool
(** [NBD.can_df t]

    does the server support the don't fragment flag to pread?

    Returns true if the server supports structured reads
    with an ability to request a non-fragmented read (see
    nbd_pread_structured(3), nbd_aio_pread_structured(3)).
    Returns false if the server either lacks structured
    reads or if it does not support a non-fragmented read
    request.

    This call does not block, because it returns data that
    is saved in the handle from the NBD protocol handshake.
*)

val can_multi_conn : t -> bool
(** [NBD.can_multi_conn t]

    does the server support multi-conn?

    Returns true if the server supports multi-conn. Returns
    false if the server does not.

    It is not safe to open multiple handles connecting to
    the same server if you will write to the server and the
    server does not advertise multi-conn support. The safe
    way to check for this is to open one connection, check
    this flag is true, then open further connections as
    required.

    This call does not block, because it returns data that
    is saved in the handle from the NBD protocol handshake.
*)

val can_cache : t -> bool
(** [NBD.can_cache t]

    does the server support the cache command?

    Returns true if the server supports the cache command
    (see nbd_cache(3), nbd_aio_cache(3)). Returns false if
    the server does not.

    This call does not block, because it returns data that
    is saved in the handle from the NBD protocol handshake.
*)

val can_meta_context : t -> string -> bool
(** [NBD.can_meta_context t metacontext]

    does the server support a specific meta context?

    Returns true if the server supports the given meta
    context (see nbd_add_meta_context(3)). Returns false if
    the server does not. It is possible for this command to
    fail if meta contexts were requested but there is a
    missing or failed attempt at NBD_OPT_SET_META_CONTEXT
    during option negotiation.

    If the server supports block status filtering (see
    nbd_can_block_status_payload(3), this function must
    return true for any filter name passed to
    nbd_block_status_filter(3).

    The single parameter is the name of the metadata
    context, for example "LIBNBD_CONTEXT_BASE_ALLOCATION".
    <libnbd.h> includes defined constants for well-known
    namespace contexts beginning with "LIBNBD_CONTEXT_", but
    you are free to pass in other contexts.

    This call does not block, because it returns data that
    is saved in the handle from the NBD protocol handshake.
*)

val get_protocol : t -> string
(** [NBD.get_protocol t]

    return the NBD protocol variant

    Return the NBD protocol variant in use on the
    connection. At the moment this returns one of the
    strings "oldstyle", "newstyle" or "newstyle-fixed".
    Other strings might be returned in the future. Most
    modern NBD servers use "newstyle-fixed".

    This call does not block, because it returns data that
    is saved in the handle from the NBD protocol handshake.
*)

val get_size : t -> int64
(** [NBD.get_size t]

    return the export size

    Returns the size in bytes of the NBD export.

    Note that this call fails with "EOVERFLOW" for an
    unlikely server that advertises a size which cannot fit
    in a 64-bit signed integer.

    This call does not block, because it returns data that
    is saved in the handle from the NBD protocol handshake.
*)

val get_block_size : t -> SIZE.t -> int64
(** [NBD.get_block_size t size_type]

    return a specific server block size constraint

    Returns a specific size constraint advertised by the
    server, if any. If the return is zero, the server did
    not advertise a constraint. "size_type" must be one of
    the following constraints:

    "LIBNBD_SIZE_MINIMUM" = 0
        If non-zero, this will be a power of 2 between 1 and
        64k; any client request that is not aligned in
        length or offset to this size is likely to fail with
        "EINVAL". The image size will generally also be a
        multiple of this value (if not, the final few bytes
        are inaccessible while obeying alignment
        constraints). If zero, it is safest to assume a
        minimum block size of 512, although many servers
        support a minimum block size of 1. If the server
        provides a constraint, then libnbd defaults to
        honoring that constraint client-side unless
        "LIBNBD_STRICT_ALIGN" is cleared in
        nbd_set_strict_mode(3).

    "LIBNBD_SIZE_PREFERRED" = 1
        If non-zero, this is a power of 2 representing the
        preferred size for efficient I/O. Smaller requests
        may incur overhead such as read-modify-write cycles
        that will not be present when using I/O that is a
        multiple of this value. This value may be larger
        than the size of the export. If zero, using 4k as a
        preferred block size tends to give decent
        performance.

    "LIBNBD_SIZE_MAXIMUM" = 2
        If non-zero, this represents the maximum length that
        the server is willing to handle during nbd_pread(3)
        or nbd_pwrite(3). Other functions like nbd_zero(3)
        may still be able to use larger sizes. Note that
        this function returns what the server advertised,
        but libnbd itself imposes a maximum of 64M. If zero,
        some NBD servers will abruptly disconnect if a
        transaction involves more than 32M.

    "LIBNBD_SIZE_PAYLOAD" = 3
        This value is not advertised by the server, but
        rather represents the maximum outgoing payload size
        for a given connection that libnbd will enforce
        unless "LIBNBD_STRICT_PAYLOAD" is cleared in
        nbd_set_strict_mode(3). It is always non-zero: never
        smaller than 1M, never larger than 64M, and matches
        "LIBNBD_SIZE_MAXIMUM" when possible.

    Future NBD extensions may result in additional
    "size_type" values. Note that by default, libnbd
    requests all available block sizes, but that a server
    may differ in what sizes it chooses to report if
    nbd_set_request_block_size(3) alters whether the client
    requests sizes.

    This call does not block, because it returns data that
    is saved in the handle from the NBD protocol handshake.
*)

val pread : ?flags:CMD_FLAG.t list -> t -> bytes -> int64 -> unit
(** [NBD.pread t ?flags buf offset]

    read from the NBD server

    Issue a read command to the NBD server for the range
    starting at "offset" and ending at "offset" + "count" -
    1. NBD can only read all or nothing using this call. The
    call returns when the data has been read fully into
    "buf" or there is an error. See also
    nbd_pread_structured(3), if finer visibility is required
    into the server's replies, or if you want to use
    "LIBNBD_CMD_FLAG_DF".

    Note that libnbd currently enforces a maximum read
    buffer of 64MiB, even if the server would permit a
    larger buffer in a single transaction; attempts to
    exceed this will result in an "ERANGE" error. The server
    may enforce a smaller limit, which can be learned with
    nbd_get_block_size(3).

    The "flags" parameter must be 0 for now (it exists for
    future NBD protocol extensions).

    Note that if this command fails, and
    nbd_get_pread_initialize(3) returns true, then libnbd
    sanitized "buf", but it is unspecified whether the
    contents of "buf" will read as zero or as partial
    results from the server. If nbd_get_pread_initialize(3)
    returns false, then libnbd did not sanitize "buf", and
    the contents are undefined on failure.

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val pread_structured : ?flags:CMD_FLAG.t list -> t -> bytes -> int64 -> (bytes -> int64 -> int -> int ref -> int) -> unit
(** [NBD.pread_structured t ?flags buf offset chunk]

    read from the NBD server

    Issue a read command to the NBD server for the range
    starting at "offset" and ending at "offset" + "count" -
    1. The server's response may be subdivided into chunks
    which may arrive out of order before reassembly into the
    original buffer; the "chunk" callback is used for
    notification after each chunk arrives, and may perform
    additional sanity checking on the server's reply. The
    callback cannot call "nbd_*" APIs on the same handle
    since it holds the handle lock and will cause a
    deadlock. If the callback returns -1, and no earlier
    error has been detected, then the overall read command
    will fail with any non-zero value stored into the
    callback's "error" parameter (with a default of
    "EPROTO"); but any further chunks will still invoke the
    callback.

    The "chunk" function is called once per chunk of data
    received, with the "user_data" passed to this function.
    The "subbuf" and "count" parameters represent the subset
    of the original buffer which has just been populated by
    results from the server (in C, "subbuf" always points
    within the original "buf"; but this guarantee may not
    extend to other language bindings). The "offset"
    parameter represents the absolute offset at which
    "subbuf" begins within the image (note that this is not
    the relative offset of "subbuf" within the original
    buffer "buf"). Changes to "error" on output are ignored
    unless the callback fails. The input meaning of the
    "error" parameter is controlled by the "status"
    parameter, which is one of

    "LIBNBD_READ_DATA" = 1
        "subbuf" was populated with "count" bytes of data.
        On input, "error" contains the errno value of any
        earlier detected error, or zero.

    "LIBNBD_READ_HOLE" = 2
        "subbuf" represents a hole, and contains "count" NUL
        bytes. On input, "error" contains the errno value of
        any earlier detected error, or zero.

    "LIBNBD_READ_ERROR" = 3
        "count" is 0, so "subbuf" is unusable. On input,
        "error" contains the errno value reported by the
        server as occurring while reading that "offset",
        regardless if any earlier error has been detected.

    Future NBD extensions may permit other values for
    "status", but those will not be returned to a client
    that has not opted in to requesting such extensions. If
    the server is non-compliant, it is possible for the
    "chunk" function to be called more times than you expect
    or with "count" 0 for "LIBNBD_READ_DATA" or
    "LIBNBD_READ_HOLE". It is also possible that the "chunk"
    function is not called at all (in particular,
    "LIBNBD_READ_ERROR" is used only when an error is
    associated with a particular offset, and not when the
    server reports a generic error), but you are guaranteed
    that the callback was called at least once if the
    overall read succeeds. Libnbd does not validate that the
    server obeyed the requirement that a read call must not
    have overlapping chunks and must not succeed without
    enough chunks to cover the entire request.

    Note that libnbd currently enforces a maximum read
    buffer of 64MiB, even if the server would permit a
    larger buffer in a single transaction; attempts to
    exceed this will result in an "ERANGE" error. The server
    may enforce a smaller limit, which can be learned with
    nbd_get_block_size(3).

    The "flags" parameter may be 0 for no flags, or may
    contain "LIBNBD_CMD_FLAG_DF" meaning that the server
    should not reply with more than one fragment (if that is
    supported - some servers cannot do this, see
    nbd_can_df(3)). Libnbd does not validate that the server
    actually obeys the flag.

    Note that if this command fails, and
    nbd_get_pread_initialize(3) returns true, then libnbd
    sanitized "buf", but it is unspecified whether the
    contents of "buf" will read as zero or as partial
    results from the server. If nbd_get_pread_initialize(3)
    returns false, then libnbd did not sanitize "buf", and
    the contents are undefined on failure.

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val pwrite : ?flags:CMD_FLAG.t list -> t -> bytes -> int64 -> unit
(** [NBD.pwrite t ?flags buf offset]

    write to the NBD server

    Issue a write command to the NBD server, writing the
    data in "buf" to the range starting at "offset" and
    ending at "offset" + "count" - 1. NBD can only write all
    or nothing using this call. The call returns when the
    command has been acknowledged by the server, or there is
    an error. Note this will generally return an error if
    nbd_is_read_only(3) is true.

    Note that libnbd defaults to enforcing a maximum write
    buffer of the lesser of 64MiB or any maximum payload
    size advertised by the server; attempts to exceed this
    will generally result in a client-side "ERANGE" error,
    rather than a server-side disconnection. The actual
    limit can be learned with nbd_get_block_size(3).

    The "flags" parameter may be 0 for no flags, or may
    contain "LIBNBD_CMD_FLAG_FUA" meaning that the server
    should not return until the data has been committed to
    permanent storage (if that is supported - some servers
    cannot do this, see nbd_can_fua(3)). For convenience,
    unless nbd_set_strict_flags(3) was used to disable
    "LIBNBD_STRICT_AUTO_FLAG", libnbd ignores the presence
    or absence of the flag "LIBNBD_CMD_FLAG_PAYLOAD_LEN" in
    "flags", while correctly using the flag over the wire
    according to whether extended headers were negotiated.

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val shutdown : ?flags:SHUTDOWN.t list -> t -> unit
(** [NBD.shutdown t ?flags]

    disconnect from the NBD server

    Issue the disconnect command to the NBD server. This is
    a nice way to tell the server we are going away, but
    from the client's point of view has no advantage over
    abruptly closing the connection (see nbd_close(3)).

    This function works whether or not the handle is ready
    for transmission of commands. If more fine-grained
    control is needed, see nbd_aio_opt_abort(3) and
    nbd_aio_disconnect(3).

    The "flags" argument is a bitmask, including zero or
    more of the following shutdown flags:

    "LIBNBD_SHUTDOWN_ABANDON_PENDING" = 0x10000
        If there are any pending requests which have not yet
        been sent to the server (see nbd_aio_in_flight(3)),
        abandon them without sending them to the server,
        rather than the usual practice of issuing those
        commands before informing the server of the intent
        to disconnect.

    For convenience, the constant "LIBNBD_SHUTDOWN_MASK" is
    available to describe all shutdown flags recognized by
    this build of libnbd. A future version of the library
    may add new flags.
*)

val flush : ?flags:CMD_FLAG.t list -> t -> unit
(** [NBD.flush t ?flags]

    send flush command to the NBD server

    Issue the flush command to the NBD server. The function
    should return when all write commands which have
    completed have been committed to permanent storage on
    the server. Note this will generally return an error if
    nbd_can_flush(3) is false.

    The "flags" parameter must be 0 for now (it exists for
    future NBD protocol extensions).

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val trim : ?flags:CMD_FLAG.t list -> t -> int64 -> int64 -> unit
(** [NBD.trim t ?flags count offset]

    send trim command to the NBD server

    Issue a trim command to the NBD server, which if
    supported by the server causes a hole to be punched in
    the backing store starting at "offset" and ending at
    "offset" + "count" - 1. The call returns when the
    command has been acknowledged by the server, or there is
    an error. Note this will generally return an error if
    nbd_can_trim(3) is false or nbd_is_read_only(3) is true.

    Note that not all servers can support a "count" of 4GiB
    or larger; nbd_get_extended_headers_negotiated(3)
    indicates which servers will parse a request larger than
    32 bits. The NBD protocol does not yet have a way for a
    client to learn if the server will enforce an even
    smaller maximum trim size, although a future extension
    may add a constraint visible in nbd_get_block_size(3).

    The "flags" parameter may be 0 for no flags, or may
    contain "LIBNBD_CMD_FLAG_FUA" meaning that the server
    should not return until the data has been committed to
    permanent storage (if that is supported - some servers
    cannot do this, see nbd_can_fua(3)).

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val cache : ?flags:CMD_FLAG.t list -> t -> int64 -> int64 -> unit
(** [NBD.cache t ?flags count offset]

    send cache (prefetch) command to the NBD server

    Issue the cache (prefetch) command to the NBD server,
    which if supported by the server causes data to be
    prefetched into faster storage by the server, speeding
    up a subsequent nbd_pread(3) call. The server can also
    silently ignore this command. Note this will generally
    return an error if nbd_can_cache(3) is false.

    Note that not all servers can support a "count" of 4GiB
    or larger; nbd_get_extended_headers_negotiated(3)
    indicates which servers will parse a request larger than
    32 bits. The NBD protocol does not yet have a way for a
    client to learn if the server will enforce an even
    smaller maximum cache size, although a future extension
    may add a constraint visible in nbd_get_block_size(3).

    The "flags" parameter must be 0 for now (it exists for
    future NBD protocol extensions).

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val zero : ?flags:CMD_FLAG.t list -> t -> int64 -> int64 -> unit
(** [NBD.zero t ?flags count offset]

    send write zeroes command to the NBD server

    Issue a write zeroes command to the NBD server, which if
    supported by the server causes a zeroes to be written
    efficiently starting at "offset" and ending at "offset"
    + "count" - 1. The call returns when the command has
    been acknowledged by the server, or there is an error.
    Note this will generally return an error if
    nbd_can_zero(3) is false or nbd_is_read_only(3) is true.

    Note that not all servers can support a "count" of 4GiB
    or larger; nbd_get_extended_headers_negotiated(3)
    indicates which servers will parse a request larger than
    32 bits. The NBD protocol does not yet have a way for a
    client to learn if the server will enforce an even
    smaller maximum zero size, although a future extension
    may add a constraint visible in nbd_get_block_size(3).
    Also, some servers may permit a larger zero request only
    when the "LIBNBD_CMD_FLAG_FAST_ZERO" is in use.

    The "flags" parameter may be 0 for no flags, or may
    contain "LIBNBD_CMD_FLAG_FUA" meaning that the server
    should not return until the data has been committed to
    permanent storage (if that is supported - some servers
    cannot do this, see nbd_can_fua(3)),
    "LIBNBD_CMD_FLAG_NO_HOLE" meaning that the server should
    favor writing actual allocated zeroes over punching a
    hole, and/or "LIBNBD_CMD_FLAG_FAST_ZERO" meaning that
    the server must fail quickly if writing zeroes is no
    faster than a normal write (if that is supported - some
    servers cannot do this, see nbd_can_fast_zero(3)).

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val block_status : ?flags:CMD_FLAG.t list -> t -> int64 -> int64 -> (string -> int64 -> int64 (* uint32_t *) array -> int ref -> int) -> unit
(** [NBD.block_status t ?flags count offset extent]

    send block status command, with 32-bit callback

    Issue the block status command to the NBD server. If
    supported by the server, this causes metadata context
    information about blocks beginning from the specified
    offset to be returned. The "count" parameter is a hint:
    the server may choose to return less status, or the
    final block may extend beyond the requested range. If
    multiple contexts are supported, the number of blocks
    and cumulative length of those blocks need not be
    identical between contexts.

    Note that not all servers can support a "count" of 4GiB
    or larger; nbd_get_extended_headers_negotiated(3)
    indicates which servers will parse a request larger than
    32 bits. The NBD protocol does not yet have a way for a
    client to learn if the server will enforce an even
    smaller maximum block status size, although a future
    extension may add a constraint visible in
    nbd_get_block_size(3). Furthermore, this function is
    inherently limited to 32-bit values. If the server
    replies with a larger extent, the length of that extent
    will be truncated to just below 32 bits and any further
    extents from the server will be ignored. If the server
    replies with a status value larger than 32 bits (only
    possible when extended headers are in use), the callback
    function will be passed an "EOVERFLOW" error. To get the
    full extent information from a server that supports
    64-bit extents, you must use nbd_block_status_64(3).

    Depending on which metadata contexts were enabled before
    connecting (see nbd_add_meta_context(3)) and which are
    supported by the server (see nbd_can_meta_context(3))
    this call returns information about extents by calling
    back to the "extent" function. The callback cannot call
    "nbd_*" APIs on the same handle since it holds the
    handle lock and will cause a deadlock. If the callback
    returns -1, and no earlier error has been detected, then
    the overall block status command will fail with any
    non-zero value stored into the callback's "error"
    parameter (with a default of "EPROTO"); but any further
    contexts will still invoke the callback.

    The "extent" function is called once per type of
    metadata available, with the "user_data" passed to this
    function. The "metacontext" parameter is a string such
    as "base:allocation". The "entries" array is an array of
    pairs of integers with the first entry in each pair
    being the length (in bytes) of the block and the second
    entry being a status/flags field which is specific to
    the metadata context. The number of pairs passed to the
    function is "nr_entries/2". The NBD protocol document in
    the section about "NBD_REPLY_TYPE_BLOCK_STATUS"
    describes the meaning of this array; for contexts known
    to libnbd, <libnbd.h> contains constants beginning with
    "LIBNBD_STATE_" that may help decipher the values. On
    entry to the callback, the "error" parameter contains
    the errno value of any previously detected error, but
    even if an earlier error was detected, the current
    "metacontext" and "entries" are valid.

    It is possible for the extent function to be called more
    times than you expect (if the server is buggy), so
    always check the "metacontext" field to ensure you are
    receiving the data you expect. It is also possible that
    the extent function is not called at all, even for
    metadata contexts that you requested. This indicates
    either that the server doesn't support the context or
    for some other reason cannot return the data.

    The "flags" parameter may be 0 for no flags, or may
    contain "LIBNBD_CMD_FLAG_REQ_ONE" meaning that the
    server should return only one extent per metadata
    context where that extent does not exceed "count" bytes;
    however, libnbd does not validate that the server obeyed
    the flag.

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val block_status_64 : ?flags:CMD_FLAG.t list -> t -> int64 -> int64 -> (string -> int64 -> extent array -> int ref -> int) -> unit
(** [NBD.block_status_64 t ?flags count offset extent64]

    send block status command, with 64-bit callback

    Issue the block status command to the NBD server. If
    supported by the server, this causes metadata context
    information about blocks beginning from the specified
    offset to be returned. The "count" parameter is a hint:
    the server may choose to return less status, or the
    final block may extend beyond the requested range. When
    multiple contexts are supported, the number of blocks
    and cumulative length of those blocks need not be
    identical between contexts; this command generally
    returns the status of all negotiated contexts, while
    some servers also support a filtered request (see
    nbd_can_block_status_payload(3),
    nbd_block_status_filter(3)).

    Note that not all servers can support a "count" of 4GiB
    or larger; nbd_get_extended_headers_negotiated(3)
    indicates which servers will parse a request larger than
    32 bits. The NBD protocol does not yet have a way for a
    client to learn if the server will enforce an even
    smaller maximum block status size, although a future
    extension may add a constraint visible in
    nbd_get_block_size(3).

    Depending on which metadata contexts were enabled before
    connecting (see nbd_add_meta_context(3)) and which are
    supported by the server (see nbd_can_meta_context(3))
    this call returns information about extents by calling
    back to the "extent64" function. The callback cannot
    call "nbd_*" APIs on the same handle since it holds the
    handle lock and will cause a deadlock. If the callback
    returns -1, and no earlier error has been detected, then
    the overall block status command will fail with any
    non-zero value stored into the callback's "error"
    parameter (with a default of "EPROTO"); but any further
    contexts will still invoke the callback.

    The "extent64" function is called once per type of
    metadata available, with the "user_data" passed to this
    function. The "metacontext" parameter is a string such
    as "base:allocation". The "entries" array is an array of
    nbd_extent structs, containing length (in bytes) of the
    block and a status/flags field which is specific to the
    metadata context. The number of array entries passed to
    the function is "nr_entries". The NBD protocol document
    in the section about "NBD_REPLY_TYPE_BLOCK_STATUS"
    describes the meaning of this array; for contexts known
    to libnbd, <libnbd.h> contains constants beginning with
    "LIBNBD_STATE_" that may help decipher the values. On
    entry to the callback, the "error" parameter contains
    the errno value of any previously detected error.

    It is possible for the extent function to be called more
    times than you expect (if the server is buggy), so
    always check the "metacontext" field to ensure you are
    receiving the data you expect. It is also possible that
    the extent function is not called at all, even for
    metadata contexts that you requested. This indicates
    either that the server doesn't support the context or
    for some other reason cannot return the data.

    The "flags" parameter may be 0 for no flags, or may
    contain "LIBNBD_CMD_FLAG_REQ_ONE" meaning that the
    server should return only one extent per metadata
    context where that extent does not exceed "count" bytes;
    however, libnbd does not validate that the server obeyed
    the flag.

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val block_status_filter : ?flags:CMD_FLAG.t list -> t -> int64 -> int64 -> string list -> (string -> int64 -> extent array -> int ref -> int) -> unit
(** [NBD.block_status_filter t ?flags count offset contexts extent64]

    send filtered block status command, with 64-bit callback

    Issue a filtered block status command to the NBD server.
    If supported by the server (see
    nbd_can_block_status_payload(3)), this causes metadata
    context information about blocks beginning from the
    specified offset to be returned, and with the result
    limited to just the contexts specified in "filter". Note
    that all strings in "filter" must be supported by
    nbd_can_meta_context(3).

    All other parameters to this function have the same
    semantics as in nbd_block_status_64(3); except that for
    convenience, unless <nbd_set_strict_flags(3)> was used
    to disable "LIBNBD_STRICT_AUTO_FLAG", libnbd ignores the
    presence or absence of the flag
    "LIBNBD_CMD_FLAG_PAYLOAD_LEN" in "flags", while
    correctly using the flag over the wire.

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val poll : t -> int -> int
(** [NBD.poll t timeout]

    poll the handle once

    This is a simple implementation of poll(2) which is used
    internally by synchronous API calls. On success, it
    returns 0 if the "timeout" (in milliseconds) occurs, or
    1 if the poll completed and the state machine
    progressed. Set "timeout" to -1 to block indefinitely
    (but be careful that eventual action is actually
    expected - for example, if the connection is established
    but there are no commands in flight, using an infinite
    timeout will permanently block).

    This function is mainly useful as an example of how you
    might integrate libnbd with your own main loop, rather
    than being intended as something you would use.
*)

val poll2 : t -> Unix.file_descr -> int -> int
(** [NBD.poll2 t fd timeout]

    poll the handle once, with fd

    This is the same as nbd_poll(3), but an additional file
    descriptor parameter is passed. The additional fd is
    also polled (using "POLLIN"). One use for this is to
    wait for an eventfd(2).
*)

val aio_connect : t -> Unix.sockaddr -> unit
(** [NBD.aio_connect t addr]

    connect to the NBD server

    Begin connecting to the NBD server. The "addr" and
    "addrlen" parameters specify the address of the socket
    to connect to.

    You can check if the connection attempt is still
    underway by calling nbd_aio_is_connecting(3). If
    nbd_set_opt_mode(3) is enabled, the connection is ready
    for manual option negotiation once
    nbd_aio_is_negotiating(3) returns true; otherwise, the
    connection attempt will include the NBD handshake, and
    is ready for use once nbd_aio_is_ready(3) returns true.
*)

val aio_connect_uri : t -> string -> unit
(** [NBD.aio_connect_uri t uri]

    connect to an NBD URI

    Begin connecting to the NBD URI "uri". Parameters behave
    as documented in nbd_connect_uri(3).

    You can check if the connection attempt is still
    underway by calling nbd_aio_is_connecting(3). If
    nbd_set_opt_mode(3) is enabled, the connection is ready
    for manual option negotiation once
    nbd_aio_is_negotiating(3) returns true; otherwise, the
    connection attempt will include the NBD handshake, and
    is ready for use once nbd_aio_is_ready(3) returns true.
*)

val aio_connect_unix : t -> string -> unit
(** [NBD.aio_connect_unix t unixsocket]

    connect to the NBD server over a Unix domain socket

    Begin connecting to the NBD server over Unix domain
    socket ("unixsocket"). Parameters behave as documented
    in nbd_connect_unix(3).

    You can check if the connection attempt is still
    underway by calling nbd_aio_is_connecting(3). If
    nbd_set_opt_mode(3) is enabled, the connection is ready
    for manual option negotiation once
    nbd_aio_is_negotiating(3) returns true; otherwise, the
    connection attempt will include the NBD handshake, and
    is ready for use once nbd_aio_is_ready(3) returns true.
*)

val aio_connect_vsock : t -> int64 (* uint32_t *) -> int64 (* uint32_t *) -> unit
(** [NBD.aio_connect_vsock t cid port]

    connect to the NBD server over AF_VSOCK socket

    Begin connecting to the NBD server over the "AF_VSOCK"
    protocol to the server "cid:port". Parameters behave as
    documented in nbd_connect_vsock(3).

    You can check if the connection attempt is still
    underway by calling nbd_aio_is_connecting(3). If
    nbd_set_opt_mode(3) is enabled, the connection is ready
    for manual option negotiation once
    nbd_aio_is_negotiating(3) returns true; otherwise, the
    connection attempt will include the NBD handshake, and
    is ready for use once nbd_aio_is_ready(3) returns true.
*)

val aio_connect_tcp : t -> string -> string -> unit
(** [NBD.aio_connect_tcp t hostname port]

    connect to the NBD server over a TCP port

    Begin connecting to the NBD server listening on
    "hostname:port". Parameters behave as documented in
    nbd_connect_tcp(3).

    You can check if the connection attempt is still
    underway by calling nbd_aio_is_connecting(3). If
    nbd_set_opt_mode(3) is enabled, the connection is ready
    for manual option negotiation once
    nbd_aio_is_negotiating(3) returns true; otherwise, the
    connection attempt will include the NBD handshake, and
    is ready for use once nbd_aio_is_ready(3) returns true.
*)

val aio_connect_socket : t -> Unix.file_descr -> unit
(** [NBD.aio_connect_socket t sock]

    connect directly to a connected socket

    Begin connecting to the connected socket "fd".
    Parameters behave as documented in
    nbd_connect_socket(3).

    You can check if the connection attempt is still
    underway by calling nbd_aio_is_connecting(3). If
    nbd_set_opt_mode(3) is enabled, the connection is ready
    for manual option negotiation once
    nbd_aio_is_negotiating(3) returns true; otherwise, the
    connection attempt will include the NBD handshake, and
    is ready for use once nbd_aio_is_ready(3) returns true.
*)

val aio_connect_command : t -> string list -> unit
(** [NBD.aio_connect_command t argv]

    connect to the NBD server

    Run the command as a subprocess and begin connecting to
    it over stdin/stdout. Parameters behave as documented in
    nbd_connect_command(3).

    You can check if the connection attempt is still
    underway by calling nbd_aio_is_connecting(3). If
    nbd_set_opt_mode(3) is enabled, the connection is ready
    for manual option negotiation once
    nbd_aio_is_negotiating(3) returns true; otherwise, the
    connection attempt will include the NBD handshake, and
    is ready for use once nbd_aio_is_ready(3) returns true.
*)

val aio_connect_systemd_socket_activation : t -> string list -> unit
(** [NBD.aio_connect_systemd_socket_activation t argv]

    connect using systemd socket activation

    Run the command as a subprocess and begin connecting to
    it using systemd socket activation. Parameters behave as
    documented in nbd_connect_systemd_socket_activation(3).

    You can check if the connection attempt is still
    underway by calling nbd_aio_is_connecting(3). If
    nbd_set_opt_mode(3) is enabled, the connection is ready
    for manual option negotiation once
    nbd_aio_is_negotiating(3) returns true; otherwise, the
    connection attempt will include the NBD handshake, and
    is ready for use once nbd_aio_is_ready(3) returns true.
*)

val aio_opt_go : ?completion:(int ref -> int) -> t -> unit
(** [NBD.aio_opt_go t ?completion]

    end negotiation and move on to using an export

    Request that the server finish negotiation and move on
    to serving the export previously specified by the most
    recent nbd_set_export_name(3) or nbd_connect_uri(3).
    This can only be used if nbd_set_opt_mode(3) enabled
    option mode.

    To determine when the request completes, wait for
    nbd_aio_is_connecting(3) to return false. Or supply the
    optional "completion_callback" which will be invoked as
    described in "Completion callbacks" in libnbd(3), except
    that it is automatically retired regardless of return
    value. Note that directly detecting whether the server
    returns an error (as is done by the return value of the
    synchronous counterpart) is only possible with a
    completion callback; however it is also possible to
    indirectly detect an error when
    nbd_aio_is_negotiating(3) returns true.
*)

val aio_opt_abort : t -> unit
(** [NBD.aio_opt_abort t]

    end negotiation and close the connection

    Request that the server finish negotiation, gracefully
    if possible, then close the connection. This can only be
    used if nbd_set_opt_mode(3) enabled option mode.

    To determine when the request completes, wait for
    nbd_aio_is_connecting(3) to return false.
*)

val aio_opt_starttls : ?completion:(int ref -> int) -> t -> unit
(** [NBD.aio_opt_starttls t ?completion]

    request the server to initiate TLS

    Request that the server initiate a secure TLS
    connection, by sending "NBD_OPT_STARTTLS". This behaves
    like the synchronous counterpart nbd_opt_starttls(3),
    except that it does not wait for the server's response.

    To determine when the request completes, wait for
    nbd_aio_is_connecting(3) to return false. Or supply the
    optional "completion_callback" which will be invoked as
    described in "Completion callbacks" in libnbd(3), except
    that it is automatically retired regardless of return
    value. Note that detecting whether the server returns an
    error (as is done by the return value of the synchronous
    counterpart) is only possible with a completion
    callback.
*)

val aio_opt_extended_headers : ?completion:(int ref -> int) -> t -> unit
(** [NBD.aio_opt_extended_headers t ?completion]

    request the server to enable extended headers

    Request that the server use extended headers, by sending
    "NBD_OPT_EXTENDED_HEADERS". This behaves like the
    synchronous counterpart nbd_opt_extended_headers(3),
    except that it does not wait for the server's response.

    To determine when the request completes, wait for
    nbd_aio_is_connecting(3) to return false. Or supply the
    optional "completion_callback" which will be invoked as
    described in "Completion callbacks" in libnbd(3), except
    that it is automatically retired regardless of return
    value. Note that detecting whether the server returns an
    error (as is done by the return value of the synchronous
    counterpart) is only possible with a completion
    callback.
*)

val aio_opt_structured_reply : ?completion:(int ref -> int) -> t -> unit
(** [NBD.aio_opt_structured_reply t ?completion]

    request the server to enable structured replies

    Request that the server use structured replies, by
    sending "NBD_OPT_STRUCTURED_REPLY". This behaves like
    the synchronous counterpart nbd_opt_structured_reply(3),
    except that it does not wait for the server's response.

    To determine when the request completes, wait for
    nbd_aio_is_connecting(3) to return false. Or supply the
    optional "completion_callback" which will be invoked as
    described in "Completion callbacks" in libnbd(3), except
    that it is automatically retired regardless of return
    value. Note that detecting whether the server returns an
    error (as is done by the return value of the synchronous
    counterpart) is only possible with a completion
    callback.
*)

val aio_opt_list : ?completion:(int ref -> int) -> t -> (string -> string -> int) -> unit
(** [NBD.aio_opt_list t ?completion list]

    request the server to list all exports during negotiation

    Request that the server list all exports that it
    supports. This can only be used if nbd_set_opt_mode(3)
    enabled option mode.

    To determine when the request completes, wait for
    nbd_aio_is_connecting(3) to return false. Or supply the
    optional "completion_callback" which will be invoked as
    described in "Completion callbacks" in libnbd(3), except
    that it is automatically retired regardless of return
    value. Note that detecting whether the server returns an
    error (as is done by the return value of the synchronous
    counterpart) is only possible with a completion
    callback.
*)

val aio_opt_info : ?completion:(int ref -> int) -> t -> unit
(** [NBD.aio_opt_info t ?completion]

    request the server for information about an export

    Request that the server supply information about the
    export name previously specified by the most recent
    nbd_set_export_name(3) or nbd_connect_uri(3). This can
    only be used if nbd_set_opt_mode(3) enabled option mode.

    To determine when the request completes, wait for
    nbd_aio_is_connecting(3) to return false. Or supply the
    optional "completion_callback" which will be invoked as
    described in "Completion callbacks" in libnbd(3), except
    that it is automatically retired regardless of return
    value. Note that detecting whether the server returns an
    error (as is done by the return value of the synchronous
    counterpart) is only possible with a completion
    callback.
*)

val aio_opt_list_meta_context : ?completion:(int ref -> int) -> t -> (string -> int) -> int
(** [NBD.aio_opt_list_meta_context t ?completion context]

    request list of available meta contexts, using implicit query

    Request that the server list available meta contexts
    associated with the export previously specified by the
    most recent nbd_set_export_name(3) or
    nbd_connect_uri(3), and with a list of queries from
    prior calls to nbd_add_meta_context(3) (see
    nbd_aio_opt_list_meta_context_queries(3) if you want to
    supply an explicit query list instead). This can only be
    used if nbd_set_opt_mode(3) enabled option mode.

    To determine when the request completes, wait for
    nbd_aio_is_connecting(3) to return false. Or supply the
    optional "completion_callback" which will be invoked as
    described in "Completion callbacks" in libnbd(3), except
    that it is automatically retired regardless of return
    value. Note that detecting whether the server returns an
    error (as is done by the return value of the synchronous
    counterpart) is only possible with a completion
    callback.
*)

val aio_opt_list_meta_context_queries : ?completion:(int ref -> int) -> t -> string list -> (string -> int) -> int
(** [NBD.aio_opt_list_meta_context_queries t ?completion queries context]

    request list of available meta contexts, using explicit query

    Request that the server list available meta contexts
    associated with the export previously specified by the
    most recent nbd_set_export_name(3) or
    nbd_connect_uri(3), and with an explicit list of queries
    provided as a parameter (see
    nbd_aio_opt_list_meta_context(3) if you want to reuse an
    implicit query list instead). This can only be used if
    nbd_set_opt_mode(3) enabled option mode.

    To determine when the request completes, wait for
    nbd_aio_is_connecting(3) to return false. Or supply the
    optional "completion_callback" which will be invoked as
    described in "Completion callbacks" in libnbd(3), except
    that it is automatically retired regardless of return
    value. Note that detecting whether the server returns an
    error (as is done by the return value of the synchronous
    counterpart) is only possible with a completion
    callback.
*)

val aio_opt_set_meta_context : ?completion:(int ref -> int) -> t -> (string -> int) -> int
(** [NBD.aio_opt_set_meta_context t ?completion context]

    select specific meta contexts, with implicit query list

    Request that the server supply all recognized meta
    contexts registered through prior calls to
    nbd_add_meta_context(3), in conjunction with the export
    previously specified by the most recent
    nbd_set_export_name(3) or nbd_connect_uri(3). This can
    only be used if nbd_set_opt_mode(3) enabled option mode.
    Normally, this function is redundant, as nbd_opt_go(3)
    automatically does the same task if structured replies
    or extended headers have already been negotiated. But
    manual control over meta context requests can be useful
    for fine-grained testing of how a server handles unusual
    negotiation sequences. Often, use of this function is
    coupled with nbd_set_request_meta_context(3) to bypass
    the automatic context request normally performed by
    nbd_opt_go(3).

    To determine when the request completes, wait for
    nbd_aio_is_connecting(3) to return false. Or supply the
    optional "completion_callback" which will be invoked as
    described in "Completion callbacks" in libnbd(3), except
    that it is automatically retired regardless of return
    value. Note that detecting whether the server returns an
    error (as is done by the return value of the synchronous
    counterpart) is only possible with a completion
    callback.
*)

val aio_opt_set_meta_context_queries : ?completion:(int ref -> int) -> t -> string list -> (string -> int) -> int
(** [NBD.aio_opt_set_meta_context_queries t ?completion queries context]

    select specific meta contexts, with explicit query list

    Request that the server supply all recognized meta
    contexts passed in through "queries", in conjunction
    with the export previously specified by the most recent
    nbd_set_export_name(3) or nbd_connect_uri(3). This can
    only be used if nbd_set_opt_mode(3) enabled option mode.
    Normally, this function is redundant, as nbd_opt_go(3)
    automatically does the same task if structured replies
    or extended headers have already been negotiated. But
    manual control over meta context requests can be useful
    for fine-grained testing of how a server handles unusual
    negotiation sequences. Often, use of this function is
    coupled with nbd_set_request_meta_context(3) to bypass
    the automatic context request normally performed by
    nbd_opt_go(3).

    To determine when the request completes, wait for
    nbd_aio_is_connecting(3) to return false. Or supply the
    optional "completion_callback" which will be invoked as
    described in "Completion callbacks" in libnbd(3), except
    that it is automatically retired regardless of return
    value. Note that detecting whether the server returns an
    error (as is done by the return value of the synchronous
    counterpart) is only possible with a completion
    callback.
*)

val aio_pread : ?completion:(int ref -> int) -> ?flags:CMD_FLAG.t list -> t -> Buffer.t -> int64 -> cookie
(** [NBD.aio_pread t ?completion ?flags buf offset]

    read from the NBD server

    Issue a read command to the NBD server.

    To check if the command completed, call
    nbd_aio_command_completed(3). Or supply the optional
    "completion_callback" which will be invoked as described
    in "Completion callbacks" in libnbd(3).

    Note that you must ensure "buf" is valid until the
    command has completed. Furthermore, if the "error"
    parameter to "completion_callback" is set or if
    nbd_aio_command_completed(3) reports failure, and if
    nbd_get_pread_initialize(3) returns true, then libnbd
    sanitized "buf", but it is unspecified whether the
    contents of "buf" will read as zero or as partial
    results from the server. If nbd_get_pread_initialize(3)
    returns false, then libnbd did not sanitize "buf", and
    the contents are undefined on failure.

    Other parameters behave as documented in nbd_pread(3).

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val aio_pread_structured : ?completion:(int ref -> int) -> ?flags:CMD_FLAG.t list -> t -> Buffer.t -> int64 -> (bytes -> int64 -> int -> int ref -> int) -> cookie
(** [NBD.aio_pread_structured t ?completion ?flags buf offset chunk]

    read from the NBD server

    Issue a read command to the NBD server.

    To check if the command completed, call
    nbd_aio_command_completed(3). Or supply the optional
    "completion_callback" which will be invoked as described
    in "Completion callbacks" in libnbd(3).

    Note that you must ensure "buf" is valid until the
    command has completed. Furthermore, if the "error"
    parameter to "completion_callback" is set or if
    nbd_aio_command_completed(3) reports failure, and if
    nbd_get_pread_initialize(3) returns true, then libnbd
    sanitized "buf", but it is unspecified whether the
    contents of "buf" will read as zero or as partial
    results from the server. If nbd_get_pread_initialize(3)
    returns false, then libnbd did not sanitize "buf", and
    the contents are undefined on failure.

    Other parameters behave as documented in
    nbd_pread_structured(3).

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val aio_pwrite : ?completion:(int ref -> int) -> ?flags:CMD_FLAG.t list -> t -> Buffer.t -> int64 -> cookie
(** [NBD.aio_pwrite t ?completion ?flags buf offset]

    write to the NBD server

    Issue a write command to the NBD server.

    To check if the command completed, call
    nbd_aio_command_completed(3). Or supply the optional
    "completion_callback" which will be invoked as described
    in "Completion callbacks" in libnbd(3).

    Note that you must ensure "buf" is valid until the
    command has completed. Other parameters behave as
    documented in nbd_pwrite(3).

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val aio_disconnect : ?flags:CMD_FLAG.t list -> t -> unit
(** [NBD.aio_disconnect t ?flags]

    disconnect from the NBD server

    Issue the disconnect command to the NBD server. This is
    not a normal command because NBD servers are not obliged
    to send a reply. Instead you should wait for
    nbd_aio_is_closed(3) to become true on the connection.
    Once this command is issued, you cannot issue any
    further commands.

    Although libnbd does not prevent you from issuing this
    command while still waiting on the replies to previous
    commands, the NBD protocol recommends that you wait
    until there are no other commands in flight (see
    nbd_aio_in_flight(3)), to give the server a better
    chance at a clean shutdown.

    The "flags" parameter must be 0 for now (it exists for
    future NBD protocol extensions). There is no direct
    synchronous counterpart; however, nbd_shutdown(3) will
    call this function if appropriate.
*)

val aio_flush : ?completion:(int ref -> int) -> ?flags:CMD_FLAG.t list -> t -> cookie
(** [NBD.aio_flush t ?completion ?flags]

    send flush command to the NBD server

    Issue the flush command to the NBD server.

    To check if the command completed, call
    nbd_aio_command_completed(3). Or supply the optional
    "completion_callback" which will be invoked as described
    in "Completion callbacks" in libnbd(3).

    Other parameters behave as documented in nbd_flush(3).

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val aio_trim : ?completion:(int ref -> int) -> ?flags:CMD_FLAG.t list -> t -> int64 -> int64 -> cookie
(** [NBD.aio_trim t ?completion ?flags count offset]

    send trim command to the NBD server

    Issue a trim command to the NBD server.

    To check if the command completed, call
    nbd_aio_command_completed(3). Or supply the optional
    "completion_callback" which will be invoked as described
    in "Completion callbacks" in libnbd(3).

    Other parameters behave as documented in nbd_trim(3).

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val aio_cache : ?completion:(int ref -> int) -> ?flags:CMD_FLAG.t list -> t -> int64 -> int64 -> cookie
(** [NBD.aio_cache t ?completion ?flags count offset]

    send cache (prefetch) command to the NBD server

    Issue the cache (prefetch) command to the NBD server.

    To check if the command completed, call
    nbd_aio_command_completed(3). Or supply the optional
    "completion_callback" which will be invoked as described
    in "Completion callbacks" in libnbd(3).

    Other parameters behave as documented in nbd_cache(3).

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val aio_zero : ?completion:(int ref -> int) -> ?flags:CMD_FLAG.t list -> t -> int64 -> int64 -> cookie
(** [NBD.aio_zero t ?completion ?flags count offset]

    send write zeroes command to the NBD server

    Issue a write zeroes command to the NBD server.

    To check if the command completed, call
    nbd_aio_command_completed(3). Or supply the optional
    "completion_callback" which will be invoked as described
    in "Completion callbacks" in libnbd(3).

    Other parameters behave as documented in nbd_zero(3).

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val aio_block_status : ?completion:(int ref -> int) -> ?flags:CMD_FLAG.t list -> t -> int64 -> int64 -> (string -> int64 -> int64 (* uint32_t *) array -> int ref -> int) -> cookie
(** [NBD.aio_block_status t ?completion ?flags count offset extent]

    send block status command, with 32-bit callback

    Send the block status command to the NBD server.

    To check if the command completed, call
    nbd_aio_command_completed(3). Or supply the optional
    "completion_callback" which will be invoked as described
    in "Completion callbacks" in libnbd(3).

    Other parameters behave as documented in
    nbd_block_status(3).

    This function is inherently limited to 32-bit values. If
    the server replies with a larger extent, the length of
    that extent will be truncated to just below 32 bits and
    any further extents from the server will be ignored. If
    the server replies with a status value larger than 32
    bits (only possible when extended headers are in use),
    the callback function will be passed an "EOVERFLOW"
    error. To get the full extent information from a server
    that supports 64-bit extents, you must use
    nbd_aio_block_status_64(3).

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val aio_block_status_64 : ?completion:(int ref -> int) -> ?flags:CMD_FLAG.t list -> t -> int64 -> int64 -> (string -> int64 -> extent array -> int ref -> int) -> cookie
(** [NBD.aio_block_status_64 t ?completion ?flags count offset extent64]

    send block status command, with 64-bit callback

    Send the block status command to the NBD server.

    To check if the command completed, call
    nbd_aio_command_completed(3). Or supply the optional
    "completion_callback" which will be invoked as described
    in "Completion callbacks" in libnbd(3).

    Other parameters behave as documented in
    nbd_block_status_64(3).

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val aio_block_status_filter : ?completion:(int ref -> int) -> ?flags:CMD_FLAG.t list -> t -> int64 -> int64 -> string list -> (string -> int64 -> extent array -> int ref -> int) -> cookie
(** [NBD.aio_block_status_filter t ?completion ?flags count offset contexts extent64]

    send filtered block status command to the NBD server

    Send a filtered block status command to the NBD server.

    To check if the command completed, call
    nbd_aio_command_completed(3). Or supply the optional
    "completion_callback" which will be invoked as described
    in "Completion callbacks" in libnbd(3).

    Other parameters behave as documented in
    nbd_block_status_filter(3).

    By default, libnbd will reject attempts to use this
    function with parameters that are likely to result in
    server failure, such as requesting an unknown command
    flag. The nbd_set_strict_mode(3) function can be used to
    alter which scenarios should await a server reply rather
    than failing fast.
*)

val aio_get_fd : t -> Unix.file_descr
(** [NBD.aio_get_fd t]

    return file descriptor associated with this connection

    Return the underlying file descriptor associated with
    this connection. You can use this to check if the file
    descriptor is ready for reading or writing and call
    nbd_aio_notify_read(3) or nbd_aio_notify_write(3). See
    also nbd_aio_get_direction(3). Do not do anything else
    with the file descriptor.
*)

val aio_get_direction : t -> int
(** [NBD.aio_get_direction t]

    return the read or write direction

    Return the current direction of this connection, which
    means whether we are next expecting to read data from
    the server, write data to the server, or both. It
    returns

    0   We are not expected to interact with the server file
        descriptor from the current state. It is not worth
        attempting to use poll(2); if the connection is not
        dead, then state machine progress must instead come
        from some other means such as nbd_aio_connect(3).

    "LIBNBD_AIO_DIRECTION_READ" = 1
        We are expected next to read from the server. If
        using poll(2) you would set "events = POLLIN". If
        "revents" returns "POLLIN" or "POLLHUP" you would
        then call nbd_aio_notify_read(3).

        Note that once libnbd reaches nbd_aio_is_ready(3),
        this direction is returned even when there are no
        commands in flight (see nbd_aio_in_flight(3)). In a
        single-threaded use of libnbd, it is not worth
        polling until after issuing a command, as otherwise
        the server will never wake up the poll. In a
        multi-threaded scenario, you can have one thread
        begin a polling loop prior to any commands, but any
        other thread that issues a command will need a way
        to kick the polling thread out of poll in case
        issuing the command changes the needed polling
        direction. Possible ways to do this include polling
        for activity on a pipe-to-self, or using
        pthread_kill(3) to send a signal that is masked
        except during ppoll(2).

    "LIBNBD_AIO_DIRECTION_WRITE" = 2
        We are expected next to write to the server. If
        using poll(2) you would set "events = POLLOUT". If
        "revents" returns "POLLOUT" you would then call
        nbd_aio_notify_write(3).

    "LIBNBD_AIO_DIRECTION_BOTH" = 3
        We are expected next to either read or write to the
        server. If using poll(2) you would set "events =
        POLLIN|POLLOUT". If only one of "POLLIN" or
        "POLLOUT" is returned, then see above. However, if
        both are returned, it is better to call only
        nbd_aio_notify_read(3), as processing the server's
        reply may change the state of the connection and
        invalidate the need to write more commands.
*)

val aio_notify_read : t -> unit
(** [NBD.aio_notify_read t]

    notify that the connection is readable

    Send notification to the state machine that the
    connection is readable. Typically this is called after
    your main loop has detected that the file descriptor
    associated with this connection is readable.
*)

val aio_notify_write : t -> unit
(** [NBD.aio_notify_write t]

    notify that the connection is writable

    Send notification to the state machine that the
    connection is writable. Typically this is called after
    your main loop has detected that the file descriptor
    associated with this connection is writable.
*)

val aio_is_created : t -> bool
(** [NBD.aio_is_created t]

    check if the connection has just been created

    Return true if this connection has just been created.
    This is the state before the handle has started
    connecting to a server. In this state the handle can
    start to be connected by calling functions such as
    nbd_aio_connect(3).
*)

val aio_is_connecting : t -> bool
(** [NBD.aio_is_connecting t]

    check if the connection is connecting or handshaking

    Return true if this connection is connecting to the
    server or in the process of handshaking and negotiating
    options which happens before the handle becomes ready to
    issue commands (see nbd_aio_is_ready(3)).
*)

val aio_is_negotiating : t -> bool
(** [NBD.aio_is_negotiating t]

    check if connection is ready to send handshake option

    Return true if this connection is ready to start another
    option negotiation command while handshaking with the
    server. An option command will move back to the
    connecting state (see nbd_aio_is_connecting(3)). Note
    that this state cannot be reached unless requested by
    nbd_set_opt_mode(3), and even then it only works with
    newstyle servers; an oldstyle server will skip straight
    to nbd_aio_is_ready(3).
*)

val aio_is_ready : t -> bool
(** [NBD.aio_is_ready t]

    check if the connection is in the ready state

    Return true if this connection is connected to the NBD
    server, the handshake has completed, and the connection
    is idle or waiting for a reply. In this state the handle
    is ready to issue commands.
*)

val aio_is_processing : t -> bool
(** [NBD.aio_is_processing t]

    check if the connection is processing a command

    Return true if this connection is connected to the NBD
    server, the handshake has completed, and the connection
    is processing commands (either writing out a request or
    reading a reply).

    Note the ready state (nbd_aio_is_ready(3)) is not
    included. In the ready state commands may be *in flight*
    (the *server* is processing them), but libnbd is not
    processing them.
*)

val aio_is_dead : t -> bool
(** [NBD.aio_is_dead t]

    check if the connection is dead

    Return true if the connection has encountered a fatal
    error and is dead. In this state the handle may only be
    closed. There is no way to recover a handle from the
    dead state.
*)

val aio_is_closed : t -> bool
(** [NBD.aio_is_closed t]

    check if the connection is closed

    Return true if the connection has closed. There is no
    way to reconnect a closed connection. Instead you must
    close the whole handle.
*)

val aio_command_completed : t -> int64 -> bool
(** [NBD.aio_command_completed t cookie]

    check if the command completed

    Return true if the command completed. If this function
    returns true then the command was successful and it has
    been retired. Return false if the command is still in
    flight. This can also fail with an error in case the
    command failed (in this case the command is also
    retired). A command is retired either via this command,
    or by using a completion callback which returns 1.

    The "cookie" parameter is the positive unique 64 bit
    cookie for the command, as returned by a call such as
    nbd_aio_pread(3).
*)

val aio_peek_command_completed : t -> int64
(** [NBD.aio_peek_command_completed t]

    check if any command has completed

    Return the unique positive 64 bit cookie of the first
    non-retired but completed command, 0 if there are
    in-flight commands but none of them are awaiting
    retirement, or -1 on error including when there are no
    in-flight commands. Any cookie returned by this function
    must still be passed to nbd_aio_command_completed(3) to
    actually retire the command and learn whether the
    command was successful.
*)

val aio_in_flight : t -> int
(** [NBD.aio_in_flight t]

    check how many aio commands are still in flight

    Return the number of in-flight aio commands that are
    still awaiting a response from the server before they
    can be retired. If this returns a non-zero value when
    requesting a disconnect from the server (see
    nbd_aio_disconnect(3) and nbd_shutdown(3)), libnbd does
    not try to wait for those commands to complete
    gracefully; if the server strands commands while
    shutting down, nbd_aio_command_completed(3) will report
    those commands as failed with a status of "ENOTCONN".
*)

val connection_state : t -> string
(** [NBD.connection_state t]

    return string describing the state of the connection

    Returns a descriptive string for the state of the
    connection. This can be used for debugging or
    troubleshooting, but you should not rely on the state of
    connections since it may change in future versions.
*)

val get_package_name : t -> string
(** [NBD.get_package_name t]

    return the name of the library

    Returns the name of the library, always "libnbd" unless
    the library was modified with another name at compile
    time.
*)

val get_version : t -> string
(** [NBD.get_version t]

    return the version of the library

    Return the version of libnbd. This is returned as a
    string in the form "major.minor.release" where each of
    major, minor and release is a small positive integer.
    For example:

         minor
           ↓
        "1.0.3"
         ↑   ↑
     major   release

    major = 0
        The major number was 0 for the early experimental
        versions of libnbd where we still had an unstable
        API.

    major = 1
        The major number is 1 for the versions of libnbd
        with a long-term stable API and ABI. It is not
        anticipated that major will be any number other than
        1.

    minor = 0, 2, ... (even)
        The minor number is even for stable releases.

    minor = 1, 3, ... (odd)
        The minor number is odd for development versions.
        Note that new APIs added in a development version
        remain experimental and subject to change in that
        branch until they appear in a stable release.

    release
        The release number is incremented for each release
        along a particular branch.
*)

val kill_subprocess : t -> int -> unit
(** [NBD.kill_subprocess t signum]

    kill server running as a subprocess

    This call may be used to kill the server running as a
    subprocess that was previously created using
    nbd_connect_command(3). You do not need to use this
    call. It is only needed if the server does not exit when
    the socket is closed.

    The "signum" parameter is the optional signal number to
    send (see signal(7)). If "signum" is 0 then "SIGTERM" is
    sent.
*)

val supports_tls : t -> bool
(** [NBD.supports_tls t]

    true if libnbd was compiled with support for TLS

    Returns true if libnbd was compiled with gnutls which is
    required to support TLS encryption, or false if not.
*)

val supports_vsock : t -> bool
(** [NBD.supports_vsock t]

    true if libnbd was compiled with support for AF_VSOCK

    Returns true if libnbd was compiled with support for the
    "AF_VSOCK" family of sockets, or false if not.

    Note that on the Linux operating system, this returns
    true if there is compile-time support, but you may still
    need runtime support for some aspects of AF_VSOCK usage;
    for example, use of "VMADDR_CID_LOCAL" as the server
    name requires that the *vsock_loopback* kernel module is
    loaded.
*)

val supports_uri : t -> bool
(** [NBD.supports_uri t]

    true if libnbd was compiled with support for NBD URIs

    Returns true if libnbd was compiled with libxml2 which
    is required to support NBD URIs, or false if not.
*)

val get_uri : t -> string
(** [NBD.get_uri t]

    construct an NBD URI for a connection

    This makes a best effort attempt to construct an NBD URI
    which could be used to connect back to the same server
    (using nbd_connect_uri(3)).

    In some cases there is not enough information in the
    handle to successfully create a URI (eg. if you
    connected with nbd_connect_socket(3)). In such cases the
    call returns "NULL" and further diagnostic information
    is available via nbd_get_errno(3) and nbd_get_error(3)
    as usual.

    Even if a URI is returned it is not guaranteed to work,
    and it may not be optimal.
*)

