#ifndef __CT_H__
#define __CT_H_

enum ct_flag {
  CT_QUERY_IGNORE,
  CT_QUERY_SRC,
  CT_QUERY_DST
};

int ct_init();
void ct_close();
int ct_query(int flag, int l4proto, void *src, void *dst, uint16_t sport, uint16_t dport);
int ct_create(int l4proto, void *src, void *dst, uint16_t sport, uint16_t dport);

#endif
