


#ifndef __LIBC__
#define __LIBC__

#define SIZE_T int

typedef unsigned int size_t;
typedef unsigned int ssize_t;

void * memcpy (void * __dest, void * __src, size_t __n);
int sprintf(char *str, const char *format, ...);
//int snprintf(char *str, size_t size, const char *format, ...);


//void *malloc(size_t size);
//void free(void *ptr);

ssize_t send(int sockfd, const void *buf, size_t len, int flags);

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
        const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
        struct sockaddr *src_addr, socklen_t *addrlen);


#endif

