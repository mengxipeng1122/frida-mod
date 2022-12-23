
#include <stdio.h>

#include "frida_funs.h"



// exported functions 
extern "C" __declspec(dllexport) int add (int a, int b)
{
    return a + b;
}


