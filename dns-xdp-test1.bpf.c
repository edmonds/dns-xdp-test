#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <xdp/parsing_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xsks_map SEC(".maps");

#ifndef IP_OFFMASK
# define IP_OFFMASK 0x1fff
#endif

#ifndef IP_MF
# define IP_MF 0x2000
#endif

#define DNS_RRTYPE_OPT 41
#define EDNS_OPT_CODE_COOKIE 10

struct dnshdr {
	__u16 id;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	__u8 rd : 1;
	__u8 tc : 1;
	__u8 aa : 1;
	__u8 opcode : 4;
	__u8 qr : 1;

	__u8 rcode: 4;
	__u8 cd : 1;
	__u8 ad : 1;
	__u8 z : 1;
	__u8 ra : 1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	__u8 qr : 1;
	__u8 opcode : 4;
	__u8 aa : 1;
	__u8 tc : 1;
	__u8 rd : 1;

	__u8 ra : 1;
	__u8 z : 1;
	__u8 ad : 1;
	__u8 cd : 1;
	__u8 rcode: 4;
#else
# error
#endif
	__u16 qdcount;
	__u16 ancount;
	__u16 nscount;
	__u16 arcount;
} __attribute__((packed));
_Static_assert(sizeof(struct dnshdr) == 12, "struct dnshdr is correct size");

static __always_inline
int parse_dnshdr(struct hdr_cursor *nh, void *data_end, struct dnshdr **dnshdr)
{
	struct dnshdr *dns = nh->pos;

	if (dns + 1 > data_end) {
		return -1;
	}

	nh->pos = dns + 1;
	*dnshdr = dns;

	return 0;
}

SEC("xdp")
int xdp_dns_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct hdr_cursor nh = {
		.pos = data,
	};

	struct ethhdr *ethhdr;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct dnshdr *dnshdr;

	int eth_type;
	int ip_type;

	// Ethernet.
	eth_type = parse_ethhdr(&nh, data_end, &ethhdr);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		// IPv4
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_UDP) {
			goto out;
		}
		if ((bpf_htons(iphdr->frag_off) & (IP_MF | IP_OFFMASK)) != 0) {
			// Discard fragments.
			goto out;
		}
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		// IPv6
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_UDP) {
			goto out;
		}
	} else {
		goto out;
	}

	// UDP.
	if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
		goto out;
	}
	if (udphdr->dest != bpf_htons(53)) {
		goto out;
	}

	// DNS header.
	if (parse_dnshdr(&nh, data_end, &dnshdr) < 0) {
		return XDP_DROP;
	}
	if (dnshdr->qr) {
		// DNS response message. We only want to handle queries (QR = 0).
		return XDP_DROP;
	}
	if (dnshdr->qdcount != bpf_htons(1) ||
	    dnshdr->ancount != 0 ||
	    dnshdr->nscount != 0 ||
	    dnshdr->arcount > bpf_htons(2))
	{
		return XDP_DROP;
	}

	// More parsing here...

	// Redirect to userspace.
	int index = ctx->rx_queue_index;
	if (bpf_map_lookup_elem(&xsks_map, &index)) {
		return bpf_redirect_map(&xsks_map, index, 0);
	}

out:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
