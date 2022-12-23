


#ifndef __LIBC__
#define __LIBC__

#define SIZE_T int

typedef unsigned int size_t;

void * memcpy (void * __dest, void * __src, size_t __n);
int sprintf(char *str, const char *format, ...);
int snprintf(char *str, size_t size, const char *format, ...);


void *malloc(size_t size);
void free(void *ptr);


#endif

