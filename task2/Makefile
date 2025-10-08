all:
	clang -O2 -g -Wall -target bpf \
	-I/usr/include \
	-I/usr/include/x86_64-linux-gnu \
	-I/lib/modules/$(uname -r)/build/include/uapi \
	-I/lib/modules/$(uname -r)/build/include/generated/uapi \
	-c drop_by_process_name.c -o drop_by_process_name.o

clean:
	rm -f *.o
