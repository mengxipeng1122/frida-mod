
all : testcc_x86.so testcc_x64.so

testcc_x86.o:testcc.cc
	gcc -c -o $@ $^ -m32

testcc_x86.so:testcc_x86.o
	gcc  -o $@ $^ -m32 --shared

testcc_x64.o:testcc.cc
	gcc -c -o $@ $^ 

testcc_x64.so:testcc_x64.o
	gcc -o $@ $^  --shared


clean:
	rm -f *.o *.so
