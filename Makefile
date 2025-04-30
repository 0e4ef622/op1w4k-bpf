.PHONY: default

default: op1w4k-bpf

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

op1w4k.bpf.tmp.o: op1w4k.bpf.c vmlinux.h
	clang -O2 -target bpf -g -c op1w4k.bpf.c -o op1w4k.bpf.tmp.o
	llvm-strip -g op1w4k.bpf.tmp.o

op1w4k.bpf.o: op1w4k.bpf.tmp.o
	bpftool gen object op1w4k.bpf.o op1w4k.bpf.tmp.o

op1w4k.skel.h: op1w4k.bpf.o
	bpftool gen skeleton op1w4k.bpf.o > op1w4k.skel.h

op1w4k-bpf: main.c op1w4k.skel.h
	clang main.c -lbpf -o op1w4k-bpf

.PHONY: clean

clean:
	rm vmlinux.h op1w4k.bpf.tmp.o op1w4k.bpf.o op1w4k.skel.h op1w4k-bpf
