# random-src

从一个前缀随机一个 ip 对数据包进行修改，实现每次请求都有一个随机的 src

(仅支持 ipv6)

## usage

首先给 iptables 或者 nftables 添加规则 (参考 [nf.rules](./nf.rules))

usage: `random-src <in_src> <prefix> <prefix_length>`

对于经过 nfqueue num 114 的 tcp/udp 包将会把 `dst` 改为 `in_src`

对于经过 nfqueue num 514 的 tcp/udp 包将会修改 `src` 为指定 prefix 中的一个 ip

请写好 iptables/nftable 规则以防止断网，推荐放在一个单独的 netns 运行