all:
	clang -O2 -g -Wall -target bpf \
	-D__KERNEL__ -D__BPF_TRACING__ \
	-I/usr/include \
	-I/usr/include/x86_64-linux-gnu \
	-I/lib/modules/$(shell uname -r)/build/include/uapi \
	-I/lib/modules/$(shell uname -r)/build/include/generated/uapi \
	-c drop_4040.c -o drop_4040.o

clean:
	rm -f *.o

