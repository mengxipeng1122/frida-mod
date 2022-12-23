
#define LOG_INFO(fmt, args...) do { printf("[%s:%d]" fmt "\n", __FILE__, __LINE__, ##args); }while(0)

#include <stdio.h>
#include <unistd.h>

int main()
{
    LOG_INFO(" start ");
    while (1) {usleep(10000000);}
    return 0;
}
