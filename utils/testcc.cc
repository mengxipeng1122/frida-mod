
#include <stdio.h>

extern "C" int test0(){
    asm("nop");
    puts("test0");
    asm("nop");
    printf("111222");
    asm("nop");
    return 0;
}
