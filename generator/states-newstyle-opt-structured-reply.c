/* nbd client library in userspace: state machine
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

/* State machine for negotiating NBD_OPT_STRUCTURED_REPLY. */

STATE_MACHINE {
 NEWSTYLE.OPT_STRUCTURED_REPLY.START:
  assert (h->gflags & LIBNBD_HANDSHAKE_FLAG_FIXED_NEWSTYLE);
  if (h->opt_current == NBD_OPT_STRUCTURED_REPLY)
    assert (h->opt_mode);
  else {
    assert (CALLBACK_IS_NULL (h->opt_cb.completion));
    if (!h->request_sr || h->structured_replies) {
      if (h->opt_mode)
        SET_NEXT_STATE (%.NEGOTIATING);
      else
        SET_NEXT_STATE (%^OPT_META_CONTEXT.START);
      return 0;
    }
  }

  h->sbuf.option.version = htobe64 (NBD_NEW_VERSION);
  h->sbuf.option.option = htobe32 (NBD_OPT_STRUCTURED_REPLY);
  h->sbuf.option.optlen = htobe32 (0);
  h->chunks_sent++;
  h->wbuf = &h->sbuf;
  h->wlen = sizeof h->sbuf.option;
  SET_NEXT_STATE (%SEND);
  return 0;

 NEWSTYLE.OPT_STRUCTURED_REPLY.SEND:
  switch (send_from_wbuf (h)) {
  case -1: SET_NEXT_STATE (%.DEAD); return 0;
  case 0:
    h->rbuf = &h->sbuf;
    h->rlen = sizeof h->sbuf.or.option_reply;
    SET_NEXT_STATE (%RECV_REPLY);
  }
  return 0;

 NEWSTYLE.OPT_STRUCTURED_REPLY.RECV_REPLY:
  switch (recv_into_rbuf (h)) {
  case -1: SET_NEXT_STATE (%.DEAD); return 0;
  case 0:
    if (prepare_for_reply_payload (h, NBD_OPT_STRUCTURED_REPLY) == -1) {
      SET_NEXT_STATE (%.DEAD);
      return 0;
    }
    SET_NEXT_STATE (%RECV_REPLY_PAYLOAD);
  }
  return 0;

 NEWSTYLE.OPT_STRUCTURED_REPLY.RECV_REPLY_PAYLOAD:
  switch (recv_into_rbuf (h)) {
  case -1: SET_NEXT_STATE (%.DEAD); return 0;
  case 0:  SET_NEXT_STATE (%CHECK_REPLY);
  }
  return 0;

 NEWSTYLE.OPT_STRUCTURED_REPLY.CHECK_REPLY:
  uint32_t reply;
  int err = ENOTSUP;

  reply = be32toh (h->sbuf.or.option_reply.reply);
  switch (reply) {
  case NBD_REP_ACK:
    debug (h, "negotiated structured replies on this connection");
    h->structured_replies = true;
    err = 0;
    break;
  case NBD_REP_ERR_INVALID:
  case NBD_REP_ERR_EXT_HEADER_REQD:
    err = EINVAL;
    /* fallthrough */
  default:
    if (handle_reply_error (h) == -1) {
      SET_NEXT_STATE (%.DEAD);
      return 0;
    }

    if (h->structured_replies)
      debug (h, "structured replies already negotiated");
    else
      debug (h, "structured replies are not supported by this server");
    break;
  }

  /* Next option. */
  if (h->opt_mode)
    SET_NEXT_STATE (%.NEGOTIATING);
  else
    SET_NEXT_STATE (%^OPT_META_CONTEXT.START);
  CALL_CALLBACK (h->opt_cb.completion, &err);
  nbd_internal_free_option (h);
  return 0;

} /* END STATE MACHINE */
