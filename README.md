UDP DNS query packet test in eBPF/XDP
=====================================

Three variants of a UDP DNS query packet dissector implemented in eBPF/XDP:

[`dns-xdp-test1.bpf.c`](dns-xdp-test1.bpf.c): Parses the fixed-length Ethernet, IPv4/IPv6, UDP, and DNS headers only. Does not attempt to parse the question section.
```
verification time 27160 usec
stack depth 8
processed 14292 insns (limit 1000000) max_states_per_insn 11 total_states 775 peak_states 162 mark_read 10
```


[`dns-xdp-test2.bpf.c`](dns-xdp-test2.bpf.c): Additionally tries to parse the variable length DNS question section, using a bounded for-loop to process the question name, taken from the `skip_dname()` function given in this blog post: https://blog.nlnetlabs.nl/journeying-into-xdp-fully-fledged-dns-service-augmentation/. This takes a fairly long time to verify and consumes a quarter of the 1M instruction limit:
```
verification time 960153 usec
stack depth 8
processed 245741 insns (limit 1000000) max_states_per_insn 12 total_states 12734 peak_states 197 mark_read 12
```


[`dns-xdp-test3.bpf.c`](dns-xdp-test3.bpf.c): Identical to `dns-xdp-test2.c` except the for-loop is replaced with `bpf_repeat()`:
```diff
--- dns-xdp-test2.bpf.c	2024-12-28 22:04:29.621285342 -0500
+++ dns-xdp-test3.bpf.c	2024-12-28 22:04:49.925103310 -0500
@@ -69,7 +69,7 @@
 static __always_inline
 int skip_dns_name(struct hdr_cursor *nh, void *data_end)
 {
-	for (__u8 i = 0; i < MAX_DNS_LABELS; i++) {
+	bpf_repeat(MAX_DNS_LABELS) {
 		// Confirm that the next 1-octet length field can be read.
 		if (nh->pos + 1 > data_end) {
 			return -1;
```

But this results in a verification failure. Why?
```
from 170 to 171: R0_w=rdonly_mem(id=5118,ref_obj_id=2,sz=4) R6=pkt_end() R7=pkt(id=5117,off=1073,r=0,smin=smin32=0,smax=umax=smax32=umax32=0xfbfd,var_off=(0x0; 0xffff)) R8=ctx() R9=192 R10=fp0 fp-8=iter_num(ref_id=2,state=active,depth=1024) refs=2
171: R0_w=rdonly_mem(id=5118,ref_obj_id=2,sz=4) R6=pkt_end() R7=pkt(id=5117,off=1073,r=0,smin=smin32=0,smax=umax=smax32=umax32=0xfbfd,var_off=(0x0; 0xffff)) R8=ctx() R9=192 R10=fp0 fp-8=iter_num(ref_id=2,state=active,depth=1024) refs=2
; bpf_repeat(MAX_DNS_LABELS) { @ dns-xdp-test3.bpf.c:89
171: (15) if r0 == 0x0 goto pc+6      ; R0_w=rdonly_mem(id=5118,ref_obj_id=2,sz=4) refs=2
; if (nh->pos + 1 > data_end) { @ dns-xdp-test3.bpf.c:91
172: (bf) r2 = r7                     ; R2_w=pkt(id=5117,off=1073,r=0,smin=smin32=0,smax=umax=smax32=umax32=0xfbfd,var_off=(0x0; 0xffff)) R7=pkt(id=5117,off=1073,r=0,smin=smin32=0,smax=umax=smax32=umax32=0xfbfd,var_off=(0x0; 0xffff)) refs=2
173: (07) r2 += 1                     ; R2_w=pkt(id=5117,off=1074,r=0,smin=smin32=0,smax=umax=smax32=umax32=0xfbfd,var_off=(0x0; 0xffff)) refs=2
174: (2d) if r2 > r6 goto pc+27       ; R2_w=pkt(id=5117,off=1074,r=0,smin=smin32=0,smax=umax=smax32=umax32=0xfbfd,var_off=(0x0; 0xffff)) R6=pkt_end() refs=2
; __u8 o =  *(__u8 *)nh->pos; @ dns-xdp-test3.bpf.c:96
175: (71) r1 = *(u8 *)(r7 +0)
invalid access to packet, off=1073 size=1, R7(id=5117,off=1073,r=0)
R7 offset is outside of the packet
verification time 68077 usec
stack depth 16
processed 46186 insns (limit 1000000) max_states_per_insn 65 total_states 2067 peak_states 1051 mark_read 10
-- END PROG LOAD LOG --
libbpf: prog 'xdp_dns_prog': failed to load: -13
libbpf: failed to load object './dns-xdp-test3.bpf.o'
```
