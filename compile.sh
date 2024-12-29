#!/bin/sh
clang -O2 -g -target bpf -Wall -c -o dns-xdp-test1.bpf.o dns-xdp-test1.bpf.c
clang -O2 -g -target bpf -Wall -c -o dns-xdp-test2.bpf.o dns-xdp-test2.bpf.c
clang -O2 -g -target bpf -Wall -c -o dns-xdp-test3.bpf.o dns-xdp-test3.bpf.c
