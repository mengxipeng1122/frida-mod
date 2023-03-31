
#pragma once 

#include <sys/stat.h>
#include <sys/types.h>
#include "frida_funs.h"

#define NO_LOG 0
#define USING_PRINTF_LOG 1
#define USING_FRIDA_LOG 2
#define USING_ANDROID_LOG 3

#ifndef LOG_OUTPUT
    #define LOG_OUTPUT NO_LOG
#endif

#define ALIGNED(x) __attribute__((aligned(x)))


#if LOG_OUTPUT == USING_PRINTF_LOG
    #define LOG_INFO(fmt, args...)                                   \
    do{                                                               \
        fprintf(stdout,    "[%s:%d]" fmt "\n", __FILE__, __LINE__, ##args); \
        fflush(stdout);                                               \
    }while(0)
    
    #define LOG_ERR(fmt, args...)                                        \
    do{                                                                   \
        fprintf(stderr,    "[%s@%s:%d]" fmt, strerror(errno),__FILE__, __LINE__, ##args); \
        fflush(stderr);                                               \
        exit(-errno);                                                     \
    }while(0)
#elif LOG_OUTPUT ==  USING_FRIDA_LOG
    #include "frida_funs.h"

    #define LOG_INFOS_WITH_N(N, fmt, args...)                         \
    do{                                                               \
        char buff[N];                                                 \
        snprintf(buff, N, "[%s:%d]" fmt , __FILE__, __LINE__, ##args);\
        _frida_log(buff);                                             \
    }while(0)
    
    #define LOG_INFO(fmt, args...)  LOG_INFOS_WITH_N(0x800, fmt, ##args)
    
    #define LOG_ERR(fmt, args...)                                         \
    do{                                                                   \
        LOG_INFOS_WITH_N(0x800, fmt, ##args);                             \
        _frida_err();                                                     \
    }while(0)
#elif LOG_OUTPUT ==  USING_ANDROID_LOG
    #include <android/log.h>
    #define LOG_INFOS_WITH_N(N, fmt, args...)                         \
    do{                                                               \
        __android_log_print(8,"test","[%s:%d]" fmt , __FILE__, __LINE__, ##args);\
    }while(0)
    
    #define LOG_INFO(fmt, args...)  LOG_INFOS_WITH_N(0x800, fmt, ##args)
    
    #define LOG_ERR(fmt, args...)                                        \
    do{                                                                   \
        LOG_INFOS_WITH_N(0x200, fmt, ##args);                             \
        _frida_err();                                                     \
    }while(0)
#else 
    #define LOG_INFOS_WITH_N(N, fmt, args...)                         \
    do{                                                               \
    }while(0)
    
    #define LOG_INFO(fmt, args...)  LOG_INFOS_WITH_N(0x800, fmt, ##args)
    
    #define LOG_ERR(fmt, args...)                                        \
    do{                                                                   \
        LOG_INFOS_WITH_N(0x200, fmt, ##args);                             \
        exit(-1);                                                         \
    }while(0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

int dumpSelfMap();
void hexdump(void *ptr, int buflen);
int readDataFromFile(const char* fn, unsigned char* data, unsigned int size, unsigned int offset=0);
int writeDataToFile(const char* fn, unsigned char* data, unsigned int size, unsigned int offset=0);
int createDirForFile(const char* fn);
int xis_dir (const char *d);
int do_mkdir(const char *path, mode_t mode);
int isPathExist(const char* fn);
unsigned char* readFile(const char* fn, unsigned long* sz);
int writeFile(const char* fn, unsigned char* p, unsigned long sz);
int mkdirs(const char *dir);
time_t now_time(void);
void* get_library_address(const char*  libname);
void* alignAddress(void* p, int align=0x10);
const char* findBaseNameInPath(char* a_str);

/* limits.h defines "PATH_MAX". */
#include <limits.h>
extern char found_dir_path[PATH_MAX];
void find_dir_recursively (const char * dir_name, const char* findname);

int showThumbSp(unsigned long sp);
int showAarch64Sp(unsigned long sp);

extern "C" int printv(char* fmt, ...);
#ifdef __cplusplus
}
#endif
