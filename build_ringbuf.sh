clang -O2 -g -target bpf -c latency_ringbuf.bpf.c -o latency_ringbuf.bpf.o
gcc -O2 -o loader_ringbuf loader_ringbuf.c -lbpf -lelf -lz