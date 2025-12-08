CC=gcc
CXX=g++

all: crackme.bin myfunc.bin crackme32.bin myfunc32.bin

crackme.bin: crackme.c
	$(CC) -z lazy $^ -o $@

crackme32.bin: crackme.c
	$(CC) -m32 -z lazy $^ -o $@

myfunc.bin: myfunc.c
# 	$(CC) -Wl,-T script.ld -fno-stack-protector -nostdlib -nodefaultlibs -fPIC -Wl,-shared $^ -o $@
	$(CC) -nostdlib -nodefaultlibs -fPIC -Wl,-shared $^ -o $@

myfunc32.bin: myfunc.c
	$(CC) -m32 -nostdlib -nodefaultlibs -fPIC -Wl,-shared $^ -o $@

.PHONY: clean
clean:
	rm -rf *.bin
