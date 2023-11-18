
all : testcc.so

testcc.o:testcc.cc
	gcc -c -o $@ $^ -m32

testcc.so:testcc.o
	gcc  -o $@ $^ -m32 --shared

clean:
	rm -f testcc.o testcc.so
