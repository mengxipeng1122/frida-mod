
all : testcc_x86.so testcc_x64.so testcc_arm32.so testcc_thumb.so testcc_aarch64.so
	cp $^ /tmp

testcc_x86.o:testcc.cc
	gcc -c -o $@ $^ -m32

testcc_x86.so:testcc_x86.o
	gcc  -o $@ $^ -m32 --shared

testcc_x64.o:testcc.cc
	gcc -c -o $@ $^ 

testcc_x64.so:testcc_x64.o
	gcc -o $@ $^  --shared

testcc_arm32.o:testcc.cc
	arm-linux-gnueabihf-gcc -marm -c -o $@ $^ 

testcc_arm32.so:testcc_arm32.o
	arm-linux-gnueabihf-gcc -marm -o $@ $^  --shared

testcc_thumb.o:testcc.cc
	arm-linux-gnueabihf-gcc -mthumb -c -o $@ $^

testcc_thumb.so:testcc_thumb.o
	arm-linux-gnueabihf-gcc -mthumb -o $@ $^  --shared

testcc_aarch64.o:testcc.cc
	aarch64-linux-gnu-gcc  -c -o $@ $^ 

testcc_aarch64.so:testcc_aarch64.o
	aarch64-linux-gnu-gcc  -o $@ $^ --shared

clean:
	rm -f *.o *.so

