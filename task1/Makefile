all:
	clang -O2 -g -Wall -target bpf \
	-I/usr/include \
	-I/usr/include/x86_64-linux-gnu \
	-I/lib/modules/$(uname -r)/build/include/uapi \
	-I/lib/modules/$(uname -r)/build/include/generated/uapi \
	-c drop_4040.c -o drop_4040.o

clean:
	rm -f *.o
