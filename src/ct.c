#include <string.h>
#include <arpa/inet.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <linux/netfilter/nf_conntrack_tcp.h>

#include "ct.h"

int family = AF_INET6;
struct nfct_handle *handle;
struct nf_conntrack *ct;

enum ct_flag result_flag;
uint32_t result[4];

int callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data) {
  if (result_flag == CT_QUERY_IGNORE) return NFCT_CB_CONTINUE;
  struct nf_conntrack *obj = data;
  if (!nfct_cmp(obj, ct, NFCT_CMP_ALL | NFCT_CMP_MASK)) return NFCT_CB_CONTINUE;
  int query;
  if (result_flag == CT_QUERY_SRC) {
    query = ATTR_IPV6_SRC;
  } else {
    query = ATTR_IPV6_DST;
  }
  const void *res = nfct_get_attr(ct, query);
  memcpy(&result, res, sizeof(result));
  result_flag = CT_QUERY_IGNORE;
  return NFCT_CB_CONTINUE;
}

int ct_init() {
  handle = nfct_open(CONNTRACK, 0);
  ct = nfct_new();
  if (!handle || !ct) return -1;
  nfct_callback_register(handle, NFCT_T_ALL, callback, ct);
  return 0;
}

void ct_close() {
  nfct_close(handle);
  nfct_destroy(ct);
}

int ct_query(int flag, int l4proto, void* src, void *dst, uint16_t sport, uint16_t dport) {
  result_flag = flag;
  if (flag == CT_QUERY_DST) {
    nfct_set_attr(ct, ATTR_IPV6_SRC, src);
    nfct_attr_unset(ct, ATTR_IPV6_DST);
  } else {
    nfct_set_attr(ct, ATTR_IPV6_DST, dst);
    nfct_attr_unset(ct, ATTR_IPV6_SRC);
  }
  nfct_set_attr_u8(ct, ATTR_L4PROTO, l4proto);
  nfct_set_attr_u16(ct, ATTR_PORT_SRC, sport);
  nfct_set_attr_u16(ct, ATTR_PORT_DST, dport);
  int ret = nfct_query(handle, NFCT_Q_DUMP, &family);
  if (ret != 0 || result_flag != CT_QUERY_IGNORE) {
    return -1;
  }
  if (flag == CT_QUERY_SRC) {
    memcpy(src, result, sizeof(result));
  } else {
    memcpy(dst, result, sizeof(result));
  }
  return 0;
}

int ct_create(int l4proto, void *src, void *dst, uint16_t sport, uint16_t dport) {
  struct nf_conntrack *ct = nfct_new();
  nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET6);
  nfct_set_attr(ct, ATTR_IPV6_SRC, src);
  nfct_set_attr(ct, ATTR_IPV6_DST, dst);
  nfct_set_attr_u8(ct, ATTR_L4PROTO, l4proto);
  nfct_set_attr_u16(ct, ATTR_PORT_SRC, sport);
  nfct_set_attr_u16(ct, ATTR_PORT_DST, dport);
  nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);
  nfct_set_attr_u8(ct, ATTR_TCP_STATE, TCP_CONNTRACK_SYN_SENT);
  nfct_set_attr_u32(ct, ATTR_TIMEOUT, 100);
  int ret = nfct_query(handle, NFCT_Q_CREATE, ct);
  nfct_destroy(ct);
  return ret;
}
