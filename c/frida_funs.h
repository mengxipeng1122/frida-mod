

#pragma once 
//////////////////////////////////////////////////
// this module define all frida functions, and this module will not been loaded,
// It only help to generate relocation entries.

#ifdef __cplusplus

extern "C"  {

#endif 

void _frida_puts(const char*);
void _frida_err();

#ifdef __cplusplus

}

#endif 

