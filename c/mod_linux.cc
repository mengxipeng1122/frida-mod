
#include <stdio.h>

#include "frida_funs.h"


static void __attribute__((constructor)) init (void)
{
    _frida_puts(" run constructor function in module ");
}

static void __attribute__((destructor)) deinit (void)
{
    _frida_puts(" run destructor function in module \n");
}

// exported functions 
extern "C" int add (int a, int b)
{
    return a + b;
}


