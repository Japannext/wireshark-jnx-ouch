/* jnx_ouch.c
 * Routines for JNX OUCH Protocol dissection
 *
 * Copyright 1998 Gerald Combs <gerald@wireshark.org>
 * Copyright 2013 David Arnold <davida@pobox.com>
 * Copyright 2013-2018 SBI Japannext Co., Ltd. <https://www.japannext.co.jp/>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Documentation:
 * https://www.japannext.co.jp/library/
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/type_util.h>

#define ENTER_ORDER_MSG_LEN 46
#define ENTER_ORDER_WITH_ORDER_CLASSIFICATION_MSG_LEN 47
#define REPLACE_ORDER_MSG_LEN 26
#define CANCEL_ORDER_MSG_LEN 9
#define SYSTEM_EVENT_MSG_LEN 10
#define ORDER_ACCEPTED_MSG_LEN 63
#define ORDER_ACCEPTED_WITH_ORDER_CLASSIFICATION_MSG_LEN 64
#define ORDER_REPLACED_MSG_LEN 52
#define ORDER_CANCELED_MSG_LEN 18
#define ORDER_AIQ_CANCELED_MSG_LEN 27
#define ORDER_EXECUTED_MSG_LEN 30
#define ORDER_EXECUTED_WITH_COUNTER_PARTY_MSG_LEN 42
#define ORDER_REJECTED_MSG_LEN 14

// 8 byte Quantity fields
#define ENTER_ORDER_MSG_LEN_64 54
#define ENTER_ORDER_WITH_ORDER_CLASSIFICATION_MSG_LEN_64 55
#define REPLACE_ORDER_MSG_LEN_64 34
#define CANCEL_ORDER_MSG_LEN_64 13
#define ORDER_ACCEPTED_MSG_LEN_64 71
#define ORDER_ACCEPTED_WITH_ORDER_CLASSIFICATION_MSG_LEN_64 72
#define ORDER_REPLACED_MSG_LEN_64 60
#define ORDER_CANCELED_MSG_LEN_64 22
#define ORDER_AIQ_CANCELED_MSG_LEN_64 35
#define ORDER_EXECUTED_MSG_LEN_64 34
#define ORDER_EXECUTED_WITH_COUNTER_PARTY_MSG_LEN_64 46

static const value_string message_types_val[] = {
 { 'O', "Enter Order" },
 { 'U', "Replace Order" },
 { 'X', "Cancel Order" },
 { 'S', "System Event" },
 { 'A', "Order Accepted" },
 { 'R', "Order Replaced" }, /* 'U' on the wire, but use 'R' to disambiguate */
 { 'C', "Order Canceled" },
 { 'D', "Order AIQ Canceled" },
 { 'E', "Order Executed" },
 { 'e', "Order Executed with Counter Party" },
 { 'J', "Order Rejected" },
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
 { 'U', "User requested the order to be canceled" },
 { 'L', "User logged off" },
 { 'S', "This order was manually canceled by a supervisory terminal" },
 { 'I', "Order with 'Immediate' Time In Force was canceled " },
 { 'M', "Order expired during match" },
 { 'X', "Invalid price" },
 { 'Z', "Invalid quantity" },
 { 'N', "Invalid minimum quantity" },
 { 'Y', "Invalid order type" },
 { 'D', "Invalid display type" },
 { 'V', "Exceeded order value limit" },
 { 'i', "Short sell order restriction" },
 { 'R', "Order not allowed at this time" },
 { 'F', "Flow control is enabled and this OUCH port is being throttled" },
 { 'O', "Other" },
 { 0, NULL }
};

static const value_string rejected_order_reason_val[] = {
 { 'H', "Trading halt" },
 { 'S', "Invalid orderbook identifier" },
 { 'X', "Invalid price" },
 { 'Z', "Invalid quantity" },
 { 'N', "Invalid minimum quantity" },
 { 'Y', "Invalid order type" },
 { 'D', "Invalid display type" },
 { 'V', "Exceeded order value limit" },
 { 'i', "Short sell order restriction" },
 { 'R', "Order not allowed at this time" },
 { 'F', "Flow control is enabled and this OUCH port is being throttled" },
 { 'L', "MPID not allowed for this port" },
 { 'c', "User does not have permission to enter an order on the given board" },
 { 'O', "Other" },
 { 0, NULL }
};

static const value_string time_in_force_val[] = {
 { 0,     "Immediate" },
 { 99999, "Day" },
};

static const value_string buy_sell_val[] = {
 { 'B', "Buy" },
 { 'S', "Sell" },
 { 'T', "Short sell" },
 { 'E', "Short sell exempt" },
 { 0, NULL}
};

static const value_string order_classification_val[] = {
 { '1', "Non HFT" },
 { '3', "HFT market making strategy" },
 { '4', "HFT arbitrage strategy" },
 { '5', "HFT directional strategy" },
 { '6', "HFT other strategy" },
 { 0, NULL}
};

/* Initialize the protocol and registered fields */
static int proto_jnx_ouch = -1;
static dissector_handle_t jnx_ouch_handle;

/* Initialize the subtree pointers */
static gint ett_jnx_ouch = -1;

static int hf_jnx_ouch_message_type = -1;
static int hf_jnx_ouch_group = -1;
static int hf_jnx_ouch_orderbook = -1;
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
static int hf_jnx_ouch_quantity = -1;
static int hf_jnx_ouch_quantity_64 = -1;
static int hf_jnx_ouch_decrement_quantity = -1;
static int hf_jnx_ouch_decrement_quantity_64 = -1;
static int hf_jnx_ouch_quantity_prevented_from_trading = -1;
static int hf_jnx_ouch_quantity_prevented_from_trading_64 = -1;
static int hf_jnx_ouch_executed_quantity = -1;
static int hf_jnx_ouch_executed_quantity_64 = -1;
static int hf_jnx_ouch_price = -1;
static int hf_jnx_ouch_execution_price = -1;
static int hf_jnx_ouch_time_in_force = -1;
static int hf_jnx_ouch_firm = -1;
static int hf_jnx_ouch_display = -1;
static int hf_jnx_ouch_capacity = -1;
static int hf_jnx_ouch_minimum_quantity = -1;
static int hf_jnx_ouch_minimum_quantity_64 = -1;
static int hf_jnx_ouch_order_state = -1;
static int hf_jnx_ouch_liquidity_flag = -1;
static int hf_jnx_ouch_counter_party = -1;
static int hf_jnx_ouch_match_number = -1;
static int hf_jnx_ouch_order_classification = -1;

static int hf_jnx_ouch_message = -1;

static range_t *global_soupbintcp_port_range = NULL;
static range_t *soupbintcp_port_range = NULL;

void proto_reg_handoff_jnx_ouch(void);

/* -------------------------- */
static gboolean
detect_32bit_message(tvbuff_t *tvb)
{
    guint8 msg_type = tvb_get_guint8(tvb, 0);
    guint msg_len = tvb_reported_length(tvb);

    switch (msg_type) {
    case 'O':
        return msg_len == ENTER_ORDER_MSG_LEN || msg_len == ENTER_ORDER_WITH_ORDER_CLASSIFICATION_MSG_LEN;
    case 'U':
        return msg_len == REPLACE_ORDER_MSG_LEN || msg_len == ORDER_REPLACED_MSG_LEN;
    case 'X':
        return msg_len == CANCEL_ORDER_MSG_LEN;
    case 'S':
        return msg_len == SYSTEM_EVENT_MSG_LEN;
    case 'A':
        return msg_len == ORDER_ACCEPTED_MSG_LEN || msg_len == ORDER_ACCEPTED_WITH_ORDER_CLASSIFICATION_MSG_LEN;
    case 'C':
        return msg_len == ORDER_CANCELED_MSG_LEN;
    case 'D':
        return msg_len == ORDER_AIQ_CANCELED_MSG_LEN;
    case 'E':
        return msg_len == ORDER_EXECUTED_MSG_LEN;
    case 'e':
        return msg_len == ORDER_EXECUTED_WITH_COUNTER_PARTY_MSG_LEN;
    case 'J':
        return msg_len == ORDER_REJECTED_MSG_LEN;
    default:
        break;
    }
    return FALSE;
}

/* -------------------------- */
static gboolean
detect_64bit_message(tvbuff_t *tvb)
{
    guint8 msg_type = tvb_get_guint8(tvb, 0);
    guint msg_len = tvb_reported_length(tvb);

    switch (msg_type) {
    case 'O':
        return msg_len == ENTER_ORDER_MSG_LEN_64 || msg_len == ENTER_ORDER_WITH_ORDER_CLASSIFICATION_MSG_LEN_64;
    case 'U':
        return msg_len == REPLACE_ORDER_MSG_LEN_64;
    case 'X':
        return msg_len == CANCEL_ORDER_MSG_LEN_64;
    case 'A':
        return msg_len == ORDER_ACCEPTED_MSG_LEN_64 || msg_len == ORDER_ACCEPTED_WITH_ORDER_CLASSIFICATION_MSG_LEN_64;
    case 'R':
        return msg_len == ORDER_REPLACED_MSG_LEN_64;
    case 'C':
        return msg_len == ORDER_CANCELED_MSG_LEN_64;
    case 'D':
        return msg_len == ORDER_AIQ_CANCELED_MSG_LEN_64;
    case 'E':
        return msg_len == ORDER_EXECUTED_MSG_LEN_64;
    case 'e':
        return msg_len == ORDER_EXECUTED_WITH_COUNTER_PARTY_MSG_LEN_64;
    default:
        break;
    }
    return FALSE;
}
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
quantity(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int id, int id_64, int offset, const char* qty)
{
    if (jnx_ouch_tree) {
        if (detect_64bit_message(tvb)) {
            guint64 value = tvb_get_ntoh64(tvb, offset);

            proto_tree_add_uint64(jnx_ouch_tree, id_64, tvb, offset, 8, value);
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s %lu", qty, value);
            offset += 8;
        }
        else {
            guint32 value = tvb_get_ntohl(tvb, offset);

            proto_tree_add_uint(jnx_ouch_tree, id, tvb, offset, 4, value);
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s %u", qty, value);
            offset += 4;
        }
    }
    return offset;
}

/* -------------------------- */
static int
price(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int id, int offset)
{
  if (jnx_ouch_tree) {
      guint32 value = tvb_get_ntohl(tvb, offset);

      proto_tree_add_uint(jnx_ouch_tree, id, tvb, offset, 4, value);
      col_append_fstr(pinfo->cinfo, COL_INFO, " price %u", value);
  }
  return offset + 4;
}

/* -------------------------- */
static int
orderbook(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  if (jnx_ouch_tree) {
      guint32 orderbook_id = tvb_get_ntohl(tvb, offset);

      proto_tree_add_uint(jnx_ouch_tree, hf_jnx_ouch_orderbook, tvb, offset, 4, orderbook_id);
      col_append_fstr(pinfo->cinfo, COL_INFO, " <%d>", orderbook_id);
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
  guint16 reported_len;

  reported_len = tvb_reported_length(tvb);
  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_order_token);

  proto_tree_add_item(jnx_ouch_tree, hf_jnx_ouch_client_reference, tvb, offset, 10, ENC_ASCII|ENC_NA);
  offset += 10;

  col_append_fstr(pinfo->cinfo, COL_INFO, " %c", tvb_get_guint8(tvb, offset));
  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_buy_sell, tvb, offset, buy_sell_val);

  offset = quantity(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_quantity, hf_jnx_ouch_quantity_64, offset, "qty");

  offset = orderbook(tvb, pinfo, jnx_ouch_tree, offset);

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

  offset = quantity(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_minimum_quantity, hf_jnx_ouch_minimum_quantity_64, offset, "minqty");

  if (reported_len == ENTER_ORDER_WITH_ORDER_CLASSIFICATION_MSG_LEN)
    offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_order_classification, tvb, offset, order_classification_val);

  return offset;
}

/* -------------------------- */
static int
replace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  guint32 time_in_force;

  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_existing_order_token);
  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_replacement_order_token);
  offset = quantity(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_quantity, hf_jnx_ouch_quantity_64, offset, "qty");
  offset = price(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_price, offset);

  time_in_force = tvb_get_ntohl(tvb, offset);
  proto_tree_add_uint(jnx_ouch_tree, hf_jnx_ouch_time_in_force, tvb, offset, 4, time_in_force);
  offset += 4;

  proto_tree_add_item(jnx_ouch_tree, hf_jnx_ouch_display, tvb, offset, 1, ENC_ASCII|ENC_NA);
  offset += 1;

  offset = quantity(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_minimum_quantity, hf_jnx_ouch_minimum_quantity_64, offset, "minqty");

  return offset;
}

/* -------------------------- */
static int
cancel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_order_token);
  offset = quantity(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_quantity, hf_jnx_ouch_quantity_64, offset, "qty");

  return offset;
}

/* -------------------------- */
static int
accepted(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  guint32 time_in_force;
  guint32 firm;
  guint16 reported_len;

  reported_len = tvb_reported_length(tvb);

  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_order_token);

  proto_tree_add_item(jnx_ouch_tree, hf_jnx_ouch_client_reference, tvb, offset, 10, ENC_ASCII|ENC_NA);
  offset += 10;

  col_append_fstr(pinfo->cinfo, COL_INFO, " %c", tvb_get_guint8(tvb, offset));
  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_buy_sell, tvb, offset, buy_sell_val);

  offset = quantity(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_quantity, hf_jnx_ouch_quantity_64, offset, "qty");
  offset = orderbook(tvb, pinfo, jnx_ouch_tree, offset);

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
  offset = quantity(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_minimum_quantity, hf_jnx_ouch_minimum_quantity_64, offset, "minqty");

  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_order_state, tvb, offset, order_state_val);

  if (reported_len == ORDER_ACCEPTED_WITH_ORDER_CLASSIFICATION_MSG_LEN)
    offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_order_classification, tvb, offset, order_classification_val);

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

  offset = quantity(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_quantity, hf_jnx_ouch_quantity_64, offset, "qty");
  offset = orderbook(tvb, pinfo, jnx_ouch_tree, offset);

  proto_tree_add_item(jnx_ouch_tree, hf_jnx_ouch_group, tvb, offset, 4, ENC_ASCII|ENC_NA);
  offset += 4;

  offset = price(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_price, offset);

  time_in_force = tvb_get_ntohl(tvb, offset);
  proto_tree_add_uint(jnx_ouch_tree, hf_jnx_ouch_time_in_force, tvb, offset, 4, time_in_force);
  offset += 4;

  proto_tree_add_item(jnx_ouch_tree, hf_jnx_ouch_display, tvb, offset, 1, ENC_ASCII|ENC_NA);
  offset += 1;

  offset = order_ref_number(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_order_reference_number);
  offset = quantity(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_minimum_quantity, hf_jnx_ouch_minimum_quantity_64, offset, "minqty");

  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_order_state, tvb, offset, order_state_val);

  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_previous_order_token);

  return offset;
}

/* -------------------------- */
static int
canceled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_order_token);
  offset = quantity(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_decrement_quantity, hf_jnx_ouch_decrement_quantity_64, offset, "qty");

  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_canceled_reason, tvb, offset, canceled_order_reason_val);

  return offset;
}

/* -------------------------- */
static int
aiq_canceled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  offset = canceled(tvb, pinfo, jnx_ouch_tree, offset);

  offset = quantity(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_quantity_prevented_from_trading, hf_jnx_ouch_quantity_prevented_from_trading_64, offset, "qty");
  offset = price(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_execution_price, offset);
  offset = proto_tree_add_char(jnx_ouch_tree, hf_jnx_ouch_liquidity_flag, tvb, offset, liquidity_flag_val);

  return offset;
}

/* -------------------------- */
static int
executed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *jnx_ouch_tree, int offset)
{
  offset = order_token(tvb, pinfo, jnx_ouch_tree, offset, hf_jnx_ouch_order_token);
  offset = quantity(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_executed_quantity, hf_jnx_ouch_executed_quantity_64, offset, "qty");
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
  offset = quantity(tvb, pinfo, jnx_ouch_tree, hf_jnx_ouch_executed_quantity, hf_jnx_ouch_executed_quantity_64, offset, "qty");
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

    if (jnx_ouch_type == 'U' && reported_len == 52) {
        jnx_ouch_type = 'R';
    }

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
        offset = replace(tvb, pinfo, jnx_ouch_tree, offset);
        break;

    case 'X':
       offset = cancel(tvb, pinfo, jnx_ouch_tree, offset);
       break;

    case 'A':
        offset = timestamp (tvb, jnx_ouch_tree, hf_jnx_ouch_timestamp, offset);
        offset = accepted(tvb, pinfo, jnx_ouch_tree, offset);
        break;

    case 'R': /* Replaced */
        offset = timestamp (tvb, jnx_ouch_tree, hf_jnx_ouch_timestamp, offset);
        offset = replaced(tvb, pinfo, jnx_ouch_tree, offset);
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

static void range_delete_soupbintcp_port_callback(guint32 port, gpointer ptr _U_) {
    dissector_delete_uint("tcp.port", port, jnx_ouch_handle);
}

static void range_add_soupbintcp_port_callback(guint32 port, gpointer ptr _U_) {
    dissector_add_uint("tcp.port", port, jnx_ouch_handle);
}

static void jnx_ouch_prefs(void)
{
    range_foreach(soupbintcp_port_range, range_delete_soupbintcp_port_callback, NULL);
    wmem_free(wmem_epan_scope(), soupbintcp_port_range);
    soupbintcp_port_range = range_copy(wmem_epan_scope(), global_soupbintcp_port_range);
    range_foreach(soupbintcp_port_range, range_add_soupbintcp_port_callback, NULL);
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
    if (!detect_32bit_message(tvb) && !detect_64bit_message(tvb))
        return FALSE;

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

    { &hf_jnx_ouch_orderbook,
      { "Stock",         "jnx_ouch.orderbook",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Unique orderbook identifier", HFILL }},

    { &hf_jnx_ouch_group,
      { "Group",         "jnx_ouch.group",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Orderbook group identifier", HFILL }},

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

    { &hf_jnx_ouch_quantity,
      { "Quantity",         "jnx_ouch.quantity",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        "Quantity", HFILL }},

    { &hf_jnx_ouch_quantity_64,
      { "Quantity",         "jnx_ouch.quantity",
        FT_UINT64, BASE_DEC,  NULL, 0x0,
        "Quantity", HFILL }},

    { &hf_jnx_ouch_minimum_quantity,
      { "Minimum quantity",         "jnx_ouch.minimum_quantity",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        "Minimum acceptable quantity to execute", HFILL }},

    { &hf_jnx_ouch_minimum_quantity_64,
      { "Minimum quantity",         "jnx_ouch.minimum_quantity",
        FT_UINT64, BASE_DEC,  NULL, 0x0,
        "Minimum acceptable quantity to execute", HFILL }},

    { &hf_jnx_ouch_price,
      { "Price",         "jnx_itch.price",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Price", HFILL }},

    { &hf_jnx_ouch_execution_price,
      { "Execution Price",         "jnx_ouch.execution_price",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Execution Price", HFILL }},

    { &hf_jnx_ouch_executed_quantity,
      { "Executed Quantity",         "jnx_ouch.executed_quantity",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        "Quantity executed", HFILL }},

    { &hf_jnx_ouch_executed_quantity_64,
      { "Executed Quantity",         "jnx_ouch.executed_quantity",
        FT_UINT64, BASE_DEC,  NULL, 0x0,
        "Quantity executed", HFILL }},

    { &hf_jnx_ouch_decrement_quantity,
      { "Decrement Quantity",         "jnx_ouch.decrement_quantity",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        "Quantity decremented from the order", HFILL }},

    { &hf_jnx_ouch_decrement_quantity_64,
      { "Decrement Quantity",         "jnx_ouch.decrement_quantity",
        FT_UINT64, BASE_DEC,  NULL, 0x0,
        "Quantity decremented from the order", HFILL }},

    { &hf_jnx_ouch_quantity_prevented_from_trading,
      { "Quantity Prevented from Trading",         "jnx_ouch.quantity_prevented_from_trading",
        FT_UINT32, BASE_DEC,  NULL, 0x0,
        "Quantity that would have executed if the trade had occurred", HFILL }},

    { &hf_jnx_ouch_quantity_prevented_from_trading_64,
      { "Quantity Prevented from Trading",         "jnx_ouch.quantity_prevented_from_trading",
        FT_UINT64, BASE_DEC,  NULL, 0x0,
        "Quantity that would have executed if the trade had occurred", HFILL }},

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
        NULL, HFILL }},

    { &hf_jnx_ouch_order_classification,
      { "Order Classification",         "jnx_ouch.order_classification",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "High Frequency Trading (HFT) order classification", HFILL }}

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
    soupbintcp_port_range = range_empty(NULL);

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
