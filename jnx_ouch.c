/* jnx_ouch.c
 * Routines for JNX OUCH Protocol dissection
 *
 * Copyright 1998 Gerald Combs <gerald@wireshark.org>
 * Copyright 2013 David Arnold <davida@pobox.com>
 * Copyright 2013 SBI Japannext Co., Ltd. <https://www.japannext.co.jp/>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Documentation:
 * https://www.japannext.co.jp/en/pub_data/pub_onboarding/Japannext_PTS_OUCH_v1.6.pdf
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/type_util.h>

static const value_string message_types_val[] = {
 { 'O', "Enter Order" },
 { 'U', "Replace(d) Order" },
 { 'X', "Cancel Order" },
 { 'S', "System Event" },
 { 'A', "Accepted" },
 { 'C', "Canceled" },
 { 'D', "AIQ Canceled" },
 { 'E', "Executed" },
 { 'e', "Executed with Counter Party" },
 { 'J', "Rejected" },
 { 0, NULL }
};

static const value_string system_event_code_val[] = {
 { 'S', "Start of Day" },
 { 'E', "End of Day" },
 { 0, NULL }
};

static const value_string capacity_val[] = {
 { 'A', "Agency" },
 { 'P', "Principal" },
 { 0, NULL }
};

static const value_string order_state_val[] = {
 { 'L', "Live" },
 { 'D', "Dead" },
 { 0, NULL }
};

static const value_string liquidity_flag_val[] = {
 { 'A', "Added" },
 { 'R', "Removed" },
 { 0, NULL }
};

static const value_string canceled_order_reason_val[] = {
 { 'U', "User request" },
 { 'I', "Immediate order" },
 { 'S', "Supervisory cancel" },
 { 'D', "Invalid display type" },
 { 'L', "User logged off" },
 { 'Z', "Invalid shares" },
 { 'R', "Order not allowed at this time" },
 { 'X', "Invalid price" },
 { 'N', "Invalid minimum quantity" },
 { 'Y', "Invalid order type" },
 { 'V', "Exceeded order value limit" },
 { 'M', "Order expired during match" },
 { 'F', "Flow control is enabled and this OUCH port is being throttled" },
 { 'i', "Short sell order restriction" },
 { 'O', "Other" },
 { 0, NULL }
};

static const value_string rejected_order_reason_val[] = {
 { 'H', "Trading halt" },
 { 'Z', "Invalid shares" },
 { 'S', "Invalid security identifier" },
 { 'D', "Invalid display type" },
 { 'R', "Order not allowed at this time" },
 { 'X', "Invalid price" },
 { 'N', "Invalid minimum quantity" },
 { 'Y', "Invalid order type" },
 { 'V', "Exceeded order value limit" },
 { 'L', "MPID not allowed for this port" },
 { 'F', "Flow control is enabled and this OUCH port is being throttled" },
 { 'c', "No access" },
 { 'i', "Short sell order restriction" },
 { 'O', "Other" },
 { 0, NULL }
};

static const value_string time_in_force_val[] = {
 { 0,     "Immediate" },
 { 99999, "DAY" },
};

static const value_string buy_sell_val[] = {
 { 'B', "Buy" },
 { 'S', "Sell" },
 { 'T', "Short sell" },
 { 'E', "Short sell exempt" },
 { 0, NULL}
};

/* Initialize the protocol and registered fields */
static int proto_jnx_ouch = -1;
static dissector_handle_t jnx_ouch_handle;

/* Initialize the subtree pointers */
static gint ett_jnx_ouch = -1;

static int hf_jnx_ouch_message_type = -1;
static int hf_jnx_ouch_group = -1;
static int hf_jnx_ouch_stock = -1;
static int hf_jnx_ouch_timestamp = -1;
static int hf_jnx_ouch_system_event_code = -1;
static int hf_jnx_ouch_canceled_reason = -1;
static int hf_jnx_ouch_rejected_reason = -1;
static int hf_jnx_ouch_order_token = -1;
static int hf_jnx_ouch_existing_order_token = -1;
static int hf_jnx_ouch_replacement_order_token = -1;
static int hf_jnx_ouch_previous_order_token = -1;
static int hf_jnx_ouch_client_reference = -1;
static int hf_jnx_ouch_order_reference_number = -1;
static int hf_jnx_ouch_buy_sell = -1;
static int hf_jnx_ouch_shares = -1;
static int hf_jnx_ouch_decrement_shares = -1;
static int hf_jnx_ouch_shares_prevented_from_trading = -1;
static int hf_jnx_ouch_executed_shares = -1;
static int hf_jnx_ouch_price = -1;
static int hf_jnx_ouch_execution_price = -1;
static int hf_jnx_ouch_time_in_force = -1;
static int hf_jnx_ouch_firm = -1;
static int hf_jnx_ouch_display = -1;
static int hf_jnx_ouch_capacity = -1;
static int hf_jnx_ouch_minimum_quantity = -1;
static int hf_jnx_ouch_order_state = -1;
static int hf_jnx_ouch_liquidity_flag = -1;
static int hf_jnx_ouch_counter_party = -1;
static int hf_jnx_ouch_match_number = -1;

static int hf_jnx_ouch_message = -1;

static range_t *global_soupbintcp_port_range = NULL;
static range_t *soupbintcp_port_range = NULL;

void proto_reg_handoff_jnx_ouch(void);

/* ---------------------- */
static int
order_token(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset, int col)
{
  if (jnx_ouch_tree) {
      guint32 value = tvb_get_ntohl(tvb, offset);

      proto_tree_add_uint(jnx_ouch_tree, col, tvb, offset, 4, value);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %u", value);
  }
  return offset + 4;
}

/* ---------------------- */
static int
order_ref_number(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset, int col)
{
  if (jnx_ouch_tree) {
      guint64 value = tvb_get_ntoh64(tvb, offset);

      proto_tree_add_uint64(jnx_ouch_tree, col, tvb, offset, 8, value);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %lu", value);
  }
  return offset + 8;
}

/* ---------------------- */
static int
match_number(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset, int col)
{
  if (jnx_ouch_tree) {
      guint64 value = tvb_get_ntoh64(tvb, offset);

      proto_tree_add_uint64(jnx_ouch_tree, col, tvb, offset, 8, value);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %lu", value);
  }
  return offset + 8;
}

/* -------------------------- */
static int
timestamp(tvbuff_t *tvb, proto_tree *jnx_ouch_tree, int id, int offset)
{

  if (jnx_ouch_tree) {
      guint64 value = tvb_get_ntoh64(tvb, offset);
      proto_tree_add_uint64(jnx_ouch_tree, id, tvb, offset, 8, value);
  }
  return offset + 8;
}

/* -------------------------- */
static int
number_of_shares(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int id, int offset, const char* qty)
{
  if (jnx_ouch_tree) {
      guint32 value = tvb_get_ntohl(tvb, offset);

      proto_tree_add_uint(jnx_ouch_tree, id, tvb, offset, 4, value);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s %u", qty, value);
  }
  return offset + 4;
}

/* -------------------------- */
static int
price(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int id, int offset)
{
  if (jnx_ouch_tree) {
      gdouble value = tvb_get_ntohl(tvb, offset) / 10.0;

      proto_tree_add_double(jnx_ouch_tree, id, tvb, offset, 4, value);
      col_append_fstr(pinfo->cinfo, COL_INFO, " price %g", value);
  }
  return offset + 4;
}

/* -------------------------- */
static int
stock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  if (jnx_ouch_tree) {
      guint32 stock_id = tvb_get_ntohl(tvb, offset);

      proto_tree_add_uint(jnx_ouch_tree, hf_jnx_ouch_stock, tvb, offset, 4, stock_id);
      col_append_fstr(pinfo->cinfo, COL_INFO, " <%d>", stock_id);
  }
  return offset + 4;
}

/* -------------------------- */
static int
proto_tree_add_char(proto_tree *jnx_tree, int hf_field, tvbuff_t *tvb, int offset, const value_string *v_str)
{
  char *vl;

  vl = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 1, ENC_ASCII);
  proto_tree_add_string_format_value(jnx_tree, hf_field, tvb,
        offset, 1, vl, "%s (%s)", vl, val_to_str_const(*vl, v_str, "Unknown"));

  return offset + 1;
}

/* -------------------------- */
static int
order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  guint32 time_in_force;
  guint32 firm;

  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_order_token);

  proto_tree_add_item(jnx_ouch_tree, hf_jnx_ouch_client_reference, tvb, offset, 10, ENC_ASCII|ENC_NA);
  offset += 10;

  col_append_fstr(pinfo->cinfo, COL_INFO, " %c", tvb_get_guint8(tvb, offset));
  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_buy_sell, tvb, offset, buy_sell_val);

  offset = number_of_shares(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_shares, offset, "qty");

  offset = stock(tvb, pinfo, jnx_ouch_tree, offset);

  proto_tree_add_item(jnx_ouch_tree, hf_jnx_ouch_group, tvb, offset, 4, ENC_ASCII|ENC_NA);
  offset += 4;

  offset = price(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_price, offset);

  time_in_force = tvb_get_ntohl(tvb, offset);
  proto_tree_add_uint(jnx_ouch_tree, hf_jnx_ouch_time_in_force, tvb, offset, 4, time_in_force);
  offset += 4;

  firm = tvb_get_ntohl(tvb, offset);
  proto_tree_add_uint(jnx_ouch_tree, hf_jnx_ouch_firm, tvb, offset, 4, firm);
  offset += 4;

  proto_tree_add_item(jnx_ouch_tree, hf_jnx_ouch_display, tvb, offset, 1, ENC_ASCII|ENC_NA);
  offset += 1;

  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_capacity, tvb, offset, capacity_val);

  offset = number_of_shares(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_minimum_quantity, offset, "minqty");

  return offset;
}

/* -------------------------- */
static int
replace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  guint32 time_in_force;

  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_existing_order_token);
  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_replacement_order_token);
  offset = number_of_shares(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_shares, offset, "qty");
  offset = price(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_price, offset);

  time_in_force = tvb_get_ntohl(tvb, offset);
  proto_tree_add_uint(jnx_ouch_tree, hf_jnx_ouch_time_in_force, tvb, offset, 4, time_in_force);
  offset += 4;

  proto_tree_add_item(jnx_ouch_tree, hf_jnx_ouch_display, tvb, offset, 1, ENC_ASCII|ENC_NA);
  offset += 1;

  offset = number_of_shares(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_minimum_quantity, offset, "minqty");

  return offset;
}

/* -------------------------- */
static int
cancel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_order_token);
  offset = number_of_shares(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_shares, offset, "qty");

  return offset;
}

/* -------------------------- */
static int
accepted(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  guint32 time_in_force;
  guint32 firm;

  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_order_token);

  proto_tree_add_item(jnx_ouch_tree, hf_jnx_ouch_client_reference, tvb, offset, 10, ENC_ASCII|ENC_NA);
  offset += 10;

  col_append_fstr(pinfo->cinfo, COL_INFO, " %c", tvb_get_guint8(tvb, offset));
  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_buy_sell, tvb, offset, buy_sell_val);

  offset = number_of_shares(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_shares, offset, "qty");
  offset = stock(tvb, pinfo, jnx_ouch_tree, offset);

  proto_tree_add_item(jnx_ouch_tree, hf_jnx_ouch_group, tvb, offset, 4, ENC_ASCII|ENC_NA);
  offset += 4;

  offset = price(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_price, offset);

  time_in_force = tvb_get_ntohl(tvb, offset);
  proto_tree_add_uint(jnx_ouch_tree, hf_jnx_ouch_time_in_force, tvb, offset, 4, time_in_force);
  offset += 4;

  firm = tvb_get_ntohl(tvb, offset);
  proto_tree_add_uint(jnx_ouch_tree, hf_jnx_ouch_firm, tvb, offset, 4, firm);
  offset += 4;

  proto_tree_add_item(jnx_ouch_tree, hf_jnx_ouch_display, tvb, offset, 1, ENC_ASCII|ENC_NA);
  offset += 1;

  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_capacity, tvb, offset, capacity_val);

  offset = order_ref_number(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_order_reference_number);
  offset = number_of_shares(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_minimum_quantity, offset, "minqty");

  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_order_state, tvb, offset, order_state_val);

  return offset;
}

/* -------------------------- */
static int
replaced(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  guint32 time_in_force;

  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_replacement_order_token);

  col_append_fstr(pinfo->cinfo, COL_INFO, " %c", tvb_get_guint8(tvb, offset));
  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_buy_sell, tvb, offset, buy_sell_val);

  offset = number_of_shares(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_shares, offset, "qty");
  offset = stock(tvb, pinfo, jnx_ouch_tree, offset);

  proto_tree_add_item(jnx_ouch_tree, hf_jnx_ouch_group, tvb, offset, 4, ENC_ASCII|ENC_NA);
  offset += 4;

  offset = price(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_price, offset);

  time_in_force = tvb_get_ntohl(tvb, offset);
  proto_tree_add_uint(jnx_ouch_tree, hf_jnx_ouch_time_in_force, tvb, offset, 4, time_in_force);
  offset += 4;

  proto_tree_add_item(jnx_ouch_tree, hf_jnx_ouch_display, tvb, offset, 1, ENC_ASCII|ENC_NA);
  offset += 1;

  offset = order_ref_number(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_order_reference_number);
  offset = number_of_shares(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_minimum_quantity, offset, "minqty");

  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_order_state, tvb, offset, order_state_val);

  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_previous_order_token);

  return offset;
}

/* -------------------------- */
static int
canceled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_order_token);
  offset = number_of_shares(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_decrement_shares, offset, "qty");

  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_canceled_reason, tvb, offset, canceled_order_reason_val);

  return offset;
}

/* -------------------------- */
static int
aiq_canceled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  offset = canceled(tvb, pinfo, jnx_ouch_tree, offset);

  offset = number_of_shares(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_shares_prevented_from_trading, offset, "qty");
  offset = price(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_execution_price, offset);
  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_liquidity_flag, tvb, offset, liquidity_flag_val);

  return offset;
}

/* -------------------------- */
static int
executed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_order_token);
  offset = number_of_shares(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_executed_shares, offset, "qty");
  offset = price(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_execution_price, offset);

  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_liquidity_flag, tvb, offset, liquidity_flag_val);

  offset = match_number(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_match_number);

  return offset;
}

/* -------------------------- */
static int
executed_with_counter_party(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_order_token);
  offset = number_of_shares(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_executed_shares, offset, "qty");
  offset = price(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_execution_price, offset);

  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_liquidity_flag, tvb, offset, liquidity_flag_val);

  proto_tree_add_item(jnx_ouch_tree, hf_jnx_ouch_counter_party, tvb, offset, 12, ENC_ASCII|ENC_NA);
  offset += 12;

  offset = match_number(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_match_number);

  return offset;
}

/* -------------------------- */
static int
rejected(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_order_token);

  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_rejected_reason, tvb, offset, rejected_order_reason_val);

  return offset;
}

/* ---------------------------- */
static int
dissect_jnx_ouch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    guint8 jnx_ouch_type;
    guint16 reported_len;
    proto_item *ti;
    proto_tree *jnx_ouch_tree = NULL;
    int  offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SBI Japannext OUCH");

    jnx_ouch_type = tvb_get_guint8(tvb, offset);
    reported_len = tvb_reported_length(tvb);

    if (tree) {
        const gchar *rep = val_to_str(jnx_ouch_type, message_types_val, "Unknown packet type (0x%02x) ");
        col_clear(pinfo->cinfo, COL_INFO);
        col_add_str(pinfo->cinfo, COL_INFO, rep);
        if (tree) {
            ti = proto_tree_add_protocol_format(tree, proto_jnx_ouch, tvb, offset, -1, "SBI Japannext OUCH %s",
                                                rep);

            jnx_ouch_tree = proto_item_add_subtree(ti, ett_jnx_ouch);
        }
    }

    offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_message_type, tvb, offset, message_types_val);

    switch (jnx_ouch_type) {
    case 'S': /* system event */
        offset = timestamp (tvb, jnx_ouch_tree, hf_jnx_ouch_timestamp, offset);
        offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_system_event_code, tvb, offset, system_event_code_val);
        break;

    case 'O':
       offset = order(tvb, pinfo, jnx_ouch_tree, offset);
       break;

    case 'U':
        if (reported_len == 26) {
            offset = replace(tvb, pinfo, jnx_ouch_tree, offset);
        } else {
            offset = timestamp (tvb, jnx_ouch_tree, hf_jnx_ouch_timestamp, offset);
            offset = replaced(tvb, pinfo, jnx_ouch_tree, offset);
        }
        break;

    case 'X':
       offset = cancel(tvb, pinfo, jnx_ouch_tree, offset);
       break;

    case 'A':
        offset = timestamp (tvb, jnx_ouch_tree, hf_jnx_ouch_timestamp, offset);
        offset = accepted(tvb, pinfo, jnx_ouch_tree, offset);
        break;

    case 'C':
        offset = timestamp (tvb, jnx_ouch_tree, hf_jnx_ouch_timestamp, offset);
        offset = canceled(tvb, pinfo, jnx_ouch_tree, offset);
        break;

    case 'D':
        offset = timestamp (tvb, jnx_ouch_tree, hf_jnx_ouch_timestamp, offset);
        offset = aiq_canceled(tvb, pinfo, jnx_ouch_tree, offset);
        break;

    case 'E' : /* Order executed */
        offset = timestamp (tvb, jnx_ouch_tree, hf_jnx_ouch_timestamp, offset);
        offset = executed(tvb, pinfo, jnx_ouch_tree, offset);
        break;

    case 'e' : /* Order executed with counter party*/
        offset = timestamp (tvb, jnx_ouch_tree, hf_jnx_ouch_timestamp, offset);
        offset = executed_with_counter_party(tvb, pinfo, jnx_ouch_tree, offset);
        break;

    case 'J' :
        offset = timestamp (tvb, jnx_ouch_tree, hf_jnx_ouch_timestamp, offset);
        offset = rejected(tvb, pinfo, jnx_ouch_tree, offset);
        break;

    default:
        /* unknown */
        proto_tree_add_item(jnx_ouch_tree, hf_jnx_ouch_message, tvb, offset, -1, ENC_ASCII|ENC_NA);
        break;
    }

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */

static void range_delete_soupbintcp_port_callback(guint32 port) {
    dissector_delete_uint("tcp.port", port, jnx_ouch_handle);
}

static void range_add_soupbintcp_port_callback(guint32 port) {
    dissector_add_uint("tcp.port", port, jnx_ouch_handle);
}

static void jnx_ouch_prefs(void)
{
    range_foreach(soupbintcp_port_range, range_delete_soupbintcp_port_callback);
    g_free(soupbintcp_port_range);
    soupbintcp_port_range = range_copy(global_soupbintcp_port_range);
    range_foreach(soupbintcp_port_range, range_add_soupbintcp_port_callback);
}

/** Returns a guess if a packet is OUCH or not
 *
 * Since SOUP doesn't have a sub-protocol type flag, we have to use a
 * heuristic decision to determine if the contained protocol is OUCH
 * or ITCH (or something else entirely).  We look at the message type
 * code, and since we know that we're being called from SOUP, we can
 * check the passed-in length too: if the type code and the length
 * match, we guess at OUCH. */
static gboolean
dissect_jnx_ouch_heur(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    void *data _U_)
{
    guint8 msg_type = tvb_get_guint8(tvb, 0);
    guint msg_len = tvb_reported_length(tvb);

    switch (msg_type) {
    case 'O': /* Enter order */
        if (msg_len != 46) {
            return FALSE;
        }
        break;

    case 'U': /* Replace order or Replaced */
        if (msg_len != 26 && msg_len != 52) {
            return FALSE;
        }
        break;

    case 'X': /* Cancel order */
        if (msg_len != 9) {
            return FALSE;
        }
        break;

    case 'S': /* System event */
        if (msg_len != 10) {
            return FALSE;
        }
        break;

    case 'A': /* Accepted */
        if (msg_len != 63 ) {
            return FALSE;
        }
        break;

    case 'C': /* Canceled */
        if (msg_len != 18) {
            return FALSE;
        }
        break;

    case 'D': /* AIQ Canceled */
        if (msg_len != 27) {
            return FALSE;
        }
        break;
    case 'E': /* Executed */
        if (msg_len != 30) {
            return FALSE;
        }
        break;

    case 'e': /* Executed with counter party*/
        if (msg_len != 42) {
            return FALSE;
        }
        break;

    case 'J': /* Rejected */
        if (msg_len != 14) {
            return FALSE;
        }
        break;

    default:
        /* Not a known OUCH message code */
        return FALSE;
    }

    /* Perform dissection of this (initial) packet */
    dissect_jnx_ouch(tvb, pinfo, tree, NULL);

    return TRUE;
}

void
proto_register_jnx_ouch(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
    { &hf_jnx_ouch_message_type,
      { "Message Type",         "jnx_ouch.message_type",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_timestamp,
      { "Timestamp",         "jnx_ouch.timestamp",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_stock,
      { "Stock",         "jnx_ouch.stock",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Unique security identifier", HFILL }},

    { &hf_jnx_ouch_group,
      { "Group",         "jnx_ouch.group",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Security group identifier", HFILL }},

    { &hf_jnx_ouch_system_event_code,
      { "Event Code",         "jnx_ouch.event_code",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_canceled_reason,
      { "Reason",         "jnx_ouch.reason",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_rejected_reason,
      { "Reason",         "jnx_ouch.reason",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_order_token,
      { "Order Token",         "jnx_ouch.order_token",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_client_reference,
      { "Client Reference",         "jnx_ouch.client_reference",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_existing_order_token,
      { "Existing Order Token",         "jnx_ouch.existing_order_token",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_replacement_order_token,
      { "Replacement Order Token",         "jnx_ouch.replacement_order_token",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_previous_order_token,
      { "Previous Order Token",         "jnx_ouch.previous_order_token",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Order Token of the replaced order", HFILL }},

    { &hf_jnx_ouch_order_reference_number,
      { "Order Reference",         "jnx_ouch.order_reference_number",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "Order reference number", HFILL }},

    { &hf_jnx_ouch_buy_sell,
      { "Buy/Sell Indicator",         "jnx_ouch.buy_sell",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_shares,
      { "Shares",         "jnx_ouch.shares",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        "Number of shares", HFILL }},

    { &hf_jnx_ouch_minimum_quantity,
      { "Minimum quantity",         "jnx_ouch.minimum_quantity",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        "Minimum acceptable quantity to execute", HFILL }},

    { &hf_jnx_ouch_price,
      { "Price",         "jnx_ouch.price",
        FT_DOUBLE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_execution_price,
      { "Execution Price",         "jnx_ouch.execution_price",
        FT_DOUBLE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_executed_shares,
      { "Executed Shares",         "jnx_ouch.executed_shares",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        "Number of shares executed", HFILL }},

    { &hf_jnx_ouch_decrement_shares,
      { "Decrement Shares",         "jnx_ouch.decrement_shares",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        "Number of shares decremented from the order", HFILL }},

    { &hf_jnx_ouch_shares_prevented_from_trading,
      { "Shares Prevented from Trading",         "jnx_ouch.shares_prevented_from_trading",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        "Shares that would have executed if the trade had occurred", HFILL }},

    { &hf_jnx_ouch_order_state,
      { "Order State",         "jnx_ouch.order_state",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_match_number,
      { "Match Number",         "jnx_ouch.match_number",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "Day unique match reference number", HFILL }},

    { &hf_jnx_ouch_time_in_force,
      { "Time in Force",         "jnx_ouch.time_in_force",
        FT_UINT32, BASE_DEC,  VALS(time_in_force_val), 0x0,
        "Specifies how long the order remains in effect", HFILL }},

    { &hf_jnx_ouch_firm,
      { "Firm",         "jnx_ouch.firm",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        "Firm identifier for the order entry firm", HFILL }},

    { &hf_jnx_ouch_display,
      { "Display",         "jnx_ouch.display",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_capacity,
      { "Capacity",         "jnx_ouch.capacity",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_liquidity_flag,
      { "Liquidity Flag",         "jnx_ouch.liquidity_flag",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_counter_party,
      { "Counter Party",         "jnx_ouch.counter_party",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_jnx_ouch_message,
      { "Message",         "jnx_ouch.message",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }}
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_jnx_ouch
    };

    module_t *jnx_ouch_module;

    /* Register the protocol name and description */
    proto_jnx_ouch = proto_register_protocol("SBI Japannext OUCH", "JNX-OUCH", "jnx_ouch");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_jnx_ouch, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    jnx_ouch_module = prefs_register_protocol(proto_jnx_ouch, jnx_ouch_prefs);

    prefs_register_range_preference(jnx_ouch_module, "tcp.port", "SoupBinTCP ports", "SoupBinTCP port range", &global_soupbintcp_port_range, 65535);
    soupbintcp_port_range = range_empty();

}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_jnx_ouch(void)
{
    jnx_ouch_handle = create_dissector_handle(dissect_jnx_ouch, proto_jnx_ouch);
    heur_dissector_add("soupbintcp", dissect_jnx_ouch_heur, "OUCH over SoupBinTCP", "jnx_ouch_soupbintcp", proto_jnx_ouch, HEURISTIC_ENABLE);
}
