#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <linux/netfilter.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "ct.h"

#define verdict(cond) if (cond) return nfq_set_verdict(nqh, ntohl(ph -> packet_id), NF_ACCEPT, 0, NULL);

enum cb_type {
  IN, OUT
};

int urandom;

uint8_t in_src[16];
uint8_t prefix[16];
int prefix_length;

int handle_packet(enum cb_type type, uint8_t proto, struct ip6_hdr *ip6, struct pkt_buff *buff) {
  nfq_ip6_set_transport_header(buff, ip6, proto);
  uint16_t sport, dport;
  struct tcphdr *tcp;
  struct udphdr *udp;
  switch (proto) {
    case IPPROTO_TCP:
      tcp = nfq_tcp_get_hdr(buff);
      if (!tcp) return -1;
      sport = tcp -> source;
      dport = tcp -> dest;
      break;
    case IPPROTO_UDP:
      udp = nfq_udp_get_hdr(buff);
      if (!udp) return -1;
      sport = udp -> source;
      dport = udp -> dest;
      break;
    default:
      return -1;
  }
  if (type == IN) {
    memcpy(&(ip6 -> ip6_dst), in_src, sizeof(in_src));
  } else {
    uint8_t src[16];
    if (ct_query(CT_QUERY_SRC, proto, src, &(ip6 -> ip6_dst), sport, dport) == 0) {
      // query conntrack
      memcpy(&(ip6 -> ip6_src), src, sizeof(src));
    } else {
      // random src
      memcpy(&(ip6 -> ip6_src), prefix, prefix_length / 8);
      int res = read(urandom, ((uint8_t *)&(ip6 -> ip6_src)) + prefix_length / 8, (128 - prefix_length) / 8);
      if (res != (128 - prefix_length) / 8) {
        printf("error while reading urandom\n");
        return -1;
      }
      ct_create(proto, &(ip6 -> ip6_src), &(ip6 -> ip6_dst), sport, dport);
    }
  }
  switch (proto) {
    case IPPROTO_TCP:
      nfq_tcp_compute_checksum_ipv6(tcp, ip6);
      break;
    case IPPROTO_UDP:
      nfq_udp_compute_checksum_ipv6(udp, ip6);
      break;
    default:
      return -1;
  }
  return 0;
}

int cb(struct nfq_q_handle *nqh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data) {
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad); verdict(!ph)
  uint8_t *raw;
  int len = nfq_get_payload(nfad, &raw); verdict(len < 0)
  struct pkt_buff *buff = pktb_alloc(AF_INET6, raw, len, 0x1000); verdict(!buff)
  struct ip6_hdr *ip6 = nfq_ip6_get_hdr(buff); verdict(!ip6)
  uint8_t proto = (*ip6).ip6_nxt;
  verdict(proto != IPPROTO_TCP && proto != IPPROTO_UDP)
  verdict(handle_packet((int) data, proto, ip6, buff) != 0)
  return nfq_set_verdict(nqh, ntohl(ph -> packet_id), NF_ACCEPT, pktb_len(buff), pktb_data(buff));
}

int start_queue() {
  struct nfq_handle *nh = nfq_open();
  if (!nh) {
    printf("failed to init nfq_handle\n");
    return -1;
  }
  nfq_bind_pf(nh, AF_INET6);
  struct nfq_q_handle *nqh_in  = nfq_create_queue(nh, 114, cb, IN);
  struct nfq_q_handle *nqh_out = nfq_create_queue(nh, 514, cb, OUT);
  if (!nqh_in || !nqh_out) {
    printf("failed to init nfq_q_handle\n");
    return -1;
  };
  if (nfq_set_mode(nqh_in,  NFQNL_COPY_PACKET, 0xffff) < 0 ||
      nfq_set_mode(nqh_out, NFQNL_COPY_PACKET, 0xffff) < 0) {
    printf("failed to set the mode of queue");
    return -1;
  }
  int fd = nfq_fd(nh);
  uint8_t buf[10000];
  for(;;) {
    int len = read(fd, buf, sizeof(buf));
    if (len < 0) {
      printf("error occured while reading\n");
      return -1;
    }
    nfq_handle_packet(nh, buf, len);
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 4) {
    printf("usage: %s <in_src> <prefix> <prefix_length>\n", *argv);
    return -1;
  }
  if (ct_init() != 0) {
    printf("failed to init libnetfilter_conntrack\n");
    return -1;
  }
  int res =    inet_pton(AF_INET6, argv[1], in_src);
  res = res && inet_pton(AF_INET6, argv[2], prefix);
  if (!res) {
    printf("failed to parse in_src or prefix\n");
    return -1;
  }
  prefix_length = atoi(argv[3]);
  if (prefix_length < 0 || prefix_length > 128 || prefix_length % 8 != 0) {
    printf("wrong prefix length (prefix length should be divisible by 8)\n");
    return -1;
  }
  urandom = open("/dev/urandom", O_RDONLY);
  if (urandom < 0) {
    printf("failed to read /dev/urandom\n");
    return -1;
  }
  start_queue();
  return 0;
}
