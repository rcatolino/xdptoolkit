#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/tcp.h>
#include <linux/bpf.h>

struct ipv4hdr {
	__u8	ihl:4,
		version:4;
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	unsigned char saddr[4];
	unsigned char daddr[4];
	/*The options start here. */
};

struct ipv6hdr {
	__u32	    flow_lbl:20,
	            traffic_class:8,
				version:4;

	__be16			payload_len;
	__u8			nexthdr;
	__u8			hop_limit;

    unsigned char saddr[16];
    unsigned char daddr[16];
};

