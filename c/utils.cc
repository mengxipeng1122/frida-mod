
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/stat.h>
#include <stdarg.h>


#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>

#include <ctype.h>
#include <string.h>
#include <time.h>


////////////////////////////////////////////////////////////////////////////////
// string obfuscation functions
#define HIDE_LETTER(a)   ((a) + 0x50)
#define UNHIDE_STRING(str)  do { char * ptr = str ; while (*ptr) *ptr++ -= 0x50; } while(0)
#define HIDE_STRING(str)  do {char * ptr = str ; while (*ptr) *ptr++ += 0x50;} while(0)

#define Q(x) #x
#define QUOTE(x) Q(x)

#include "utils.h"

void*  get_library_address(const char*  libname)
{
    char path[256];
    char buff[256];
    int len_libname = strlen(libname);
    FILE* file;
    size_t  addr = 0;

    snprintf(path, sizeof path, "/proc/self/smaps");
    file = fopen(path, "rt");
    if (file == NULL)
        return NULL;

    while (fgets(buff, sizeof buff, file) != NULL) {
        int  len = strlen(buff);
        if (len > 0 && buff[len-1] == '\n') {
            buff[--len] = '\0';
        }
        if (len <= len_libname || memcmp(buff + len - len_libname, libname, len_libname)) {
            continue;
        }
        size_t start, end, offset;
        char flags[4];
        if (sscanf(buff, "%zx-%zx %c%c%c%c %zx", &start, &end,
                   &flags[0], &flags[1], &flags[2], &flags[3], &offset) != 7) {
            continue;
        }
        if (flags[0] != 'r' || flags[2] != 'x') {
            continue;
        }
        addr = start - offset;
        break;
    }
    fclose(file);
    return (void*)addr;
}

int dumpSelfMap()
{
    char line[0x200];
    FILE* fp= fopen("/proc/self/maps", "r");
    if(fp!=NULL) {
        while (fgets(line, 0x200, fp)!=NULL){
#if LOG_OUTPUT == USING_PRINTF_LOG
            fprintf(stdout, "%s",line);
#elif  LOG_OUTPUT == USING_FRIDA_LOG
            _frida_log(line);
#endif
        }
        fclose(fp);
    }
    else{
#if LOG_OUTPUT == USING_PRINTF_LOG
        fprintf(stdout,"can not open /proc/self/maps");
#elif  LOG_OUTPUT == USING_FRIDA_LOG
        _frida_log("can not open /proc/self/maps");
#endif
    }
    return 0;
}


void hexdump(void *ptr, int buflen) 
{
  unsigned char *buf = (unsigned char*)ptr;
  int i, j;
  char line[0x200];
  size_t offset = 0;
  for (i=0; i<buflen; i+=16) {
      sprintf(line+offset,"%06x: ", i); offset = strlen(line);
      for (j=0; j<16; j++)
      {
          if (i+j < buflen)
              sprintf(line+offset,"%02x ", buf[i+j]);
          else
              sprintf(line+offset,"   ");
          offset= strlen(line);
      }
      sprintf(line+offset," "); offset= strlen(line);
      for (j=0; j<16; j++)
      {
          if (i+j < buflen)
          {
              sprintf(line+offset,"%c", isprint(buf[i+j]) ? buf[i+j] : '.');
              offset= strlen(line);
          }
      }
#if ANDROID
      _frida_log(line);
#else
      printf("%s\n", line);
#endif
      offset = 0;
  }
}

int writeDataToFile(const char* fn, unsigned char* data, unsigned int size, unsigned int offset)
{
    FILE* fp = fopen(fn,"wb");
    if(!fp) LOG_ERR(" open file %s for writing failed", fn);
    fseek(fp, offset, SEEK_SET);
    int wrote = fwrite(data, 1, size, fp);
    if(wrote != size) LOG_ERR(" write data %p %d to file %s failed ret %d", data, size, fn, wrote);
    fclose(fp);
    return 0;
}

int readDataFromFile(const char* fn, unsigned char* data, unsigned int size, unsigned int offset)
{
    FILE* fp = fopen(fn,"rb");
    if(!fp) LOG_ERR(" open file %s for readding failed", fn);
    fseek(fp, offset, SEEK_SET);
    int read = fread(data, 1, size, fp);
    if(read != size) LOG_ERR(" read data %p %d from file %s failed ret %d", data, size, fn, read);
    fclose(fp);
    return 0;
}


/* test that dir exists (1 success, -1 does not exist, -2 not dir) */
int xis_dir (const char *d)
{
    DIR *dirptr;

    if (access ( d, F_OK ) != -1 ) {
        // file exists
        if ((dirptr = opendir (d)) != NULL) {
            closedir (dirptr); /* d exists and is a directory */
        } else {
            return -2; /* d exists but is not a directory */
        }
    } else {
        return -1;     /* d does not exist */
    }

    return 1;
}


int do_mkdir(const char *path, mode_t mode)
{
    struct stat            st;
    int             status = 0;

    if (stat(path, &st) != 0)
    {
        /* Directory does not exist. EEXIST for race condition */
        if (mkdir(path, mode) != 0 && errno != EEXIST)
            status = -1;
    }
    else if (!S_ISDIR(st.st_mode))
    {
        errno = ENOTDIR;
        status = -1;
    }

    return(status);
}

int isPathExist(const char* fn)
{
    if( access( fn, F_OK ) == 0 ) {
        // file exists
        return 1;
    } else {
        // file doesn't exist
        return 0;
    }
}

unsigned char* readFile(const char* fn, unsigned long* sz)
{
    FILE* fp= fopen(fn, "rb");
    if(fp==NULL) { LOG_ERR(" can not open file %s ", fn); }
    fseek(fp, 0, SEEK_END);
    *sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char* content = (unsigned char*)malloc(*sz+0x10);
    memset(content, 0, *sz+0x10);
    int read  = fread(content, 1, *sz, fp);
    //LOG_INFO(" read %d/%lu", read,sz);
    fclose(fp);
    return content;
}

int writeFile(const char* fn, unsigned char* p, unsigned long sz)
{
    FILE* fp= fopen(fn, "wb");
    if(fp==NULL) { LOG_ERR(" can not open file %s ", fn); }
    int wrote = fwrite(p, 1, sz, fp);
    LOG_INFO(" wrote %d/%lu", wrote,sz);
    fclose(fp);
    return wrote;
}


int mkdirs(const char *dir) 
{
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len;
    int ret;

    snprintf(tmp, sizeof(tmp),"%s",dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            ret = mkdir(tmp, S_IRWXU);
            //if(ret) LOG_INFO(" create %d failed with error %s", ret, strerror(errno));
            *p = '/';
        }
    ret = mkdir(tmp, S_IRWXU);
    //if(ret) LOG_INFO(" create %d failed with error %s", ret, strerror(errno));
    return 0;
}

int createDirForFile(const char* fn)
{
    const char* d = dirname((char*)fn);
    if(xis_dir(d)==1) return 0;
    mkdirs(d);
    return 0;
}

// from android samples
time_t now_time(void) 
{
    return time(NULL);
}

//
void* alignAddress(void* p, int align)
{
    unsigned long np = (unsigned long)p;
    while((np%align)!=0) np++;
    return (void*)np;
}


int showThumbSp(unsigned long sp)
{
    LOG_INFO(" CPSR  %0x", ((unsigned int*)sp)[0]);
    LOG_INFO(" R8    %0x", ((unsigned int*)sp)[1]);
    LOG_INFO(" R9    %0x", ((unsigned int*)sp)[2]);
    LOG_INFO(" R10   %0x", ((unsigned int*)sp)[3]);
    LOG_INFO(" R11   %0x", ((unsigned int*)sp)[4]);
    LOG_INFO(" R12   %0x", ((unsigned int*)sp)[5]);
    LOG_INFO(" LR    %0x", ((unsigned int*)sp)[6]);

    LOG_INFO(" R0    %0x", ((unsigned int*)sp)[7 ]);
    LOG_INFO(" R1    %0x", ((unsigned int*)sp)[8 ]);
    LOG_INFO(" R2    %0x", ((unsigned int*)sp)[9 ]);
    LOG_INFO(" R3    %0x", ((unsigned int*)sp)[10]);
    LOG_INFO(" R4    %0x", ((unsigned int*)sp)[11]);
    LOG_INFO(" R5    %0x", ((unsigned int*)sp)[12]);
    LOG_INFO(" R6    %0x", ((unsigned int*)sp)[13]);
    LOG_INFO(" R7    %0x", ((unsigned int*)sp)[14]);
    return 0;
}

int showAarch64Sp(unsigned long sp)
{
    LOG_INFO(" NZCV  %0lx", ((unsigned long*)sp)[0]);
    LOG_INFO(" X30  %0lx", ((unsigned long*)sp)[1 ]);
    LOG_INFO(" X29  %0lx", ((unsigned long*)sp)[2 ]);
    LOG_INFO(" X28  %0lx", ((unsigned long*)sp)[3 ]);
    LOG_INFO(" X27  %0lx", ((unsigned long*)sp)[4 ]);
    LOG_INFO(" X26  %0lx", ((unsigned long*)sp)[5 ]);
    LOG_INFO(" X25  %0lx", ((unsigned long*)sp)[6 ]);
    LOG_INFO(" X24  %0lx", ((unsigned long*)sp)[7 ]);
    LOG_INFO(" X23  %0lx", ((unsigned long*)sp)[8 ]);
    LOG_INFO(" X22  %0lx", ((unsigned long*)sp)[9 ]);
    LOG_INFO(" X21  %0lx", ((unsigned long*)sp)[10]);
    LOG_INFO(" X20  %0lx", ((unsigned long*)sp)[11]);
    LOG_INFO(" X19  %0lx", ((unsigned long*)sp)[12]);
    LOG_INFO(" X18  %0lx", ((unsigned long*)sp)[13]);
    LOG_INFO(" X17  %0lx", ((unsigned long*)sp)[14]);
    LOG_INFO(" X16  %0lx", ((unsigned long*)sp)[15]);
    LOG_INFO(" X15  %0lx", ((unsigned long*)sp)[16]);
    LOG_INFO(" X14  %0lx", ((unsigned long*)sp)[17]);
    LOG_INFO(" X13  %0lx", ((unsigned long*)sp)[18]);
    LOG_INFO(" X12  %0lx", ((unsigned long*)sp)[19]);
    LOG_INFO(" X11  %0lx", ((unsigned long*)sp)[20]);
    LOG_INFO(" X10  %0lx", ((unsigned long*)sp)[21]);
    LOG_INFO(" X9   %0lx", ((unsigned long*)sp)[22]);
    LOG_INFO(" X8   %0lx", ((unsigned long*)sp)[23]);
    LOG_INFO(" X7   %0lx", ((unsigned long*)sp)[24]);
    LOG_INFO(" X6   %0lx", ((unsigned long*)sp)[25]);
    LOG_INFO(" X5   %0lx", ((unsigned long*)sp)[26]);
    LOG_INFO(" X4   %0lx", ((unsigned long*)sp)[27]);
    LOG_INFO(" X3   %0lx", ((unsigned long*)sp)[28]);
    LOG_INFO(" X2   %0lx", ((unsigned long*)sp)[29]);
    LOG_INFO(" X1   %0lx", ((unsigned long*)sp)[30]);
    LOG_INFO(" X0   %0lx", ((unsigned long*)sp)[31]);
    return 0;
}


const char* findBaseNameInPath(char* a_str)
{
    char* ret = NULL;
    char*p = a_str+strlen(a_str)-1;
    while(p>a_str && *p!='/') p--;
    if( *p == '/') ret = strdup(p+1);
    else  ret = strdup(p);
    if (ret== NULL) LOG_ERR(" can not found base name in path %s ", a_str);
    return ret;
}


char found_dir_path[PATH_MAX];

void find_dir_recursively (const char * dir_name, const char* findname)
{
    DIR * d;

    /* Open the directory specified by "dir_name". */

    d = opendir (dir_name);

    /* Check it was opened. */
    if (! d) {
        fprintf (stderr, "Cannot open directory '%s': %s\n",
                 dir_name, strerror (errno));
        exit (EXIT_FAILURE);
    }
    while (1) {
        struct dirent * entry;
        const char * d_name;

        /* "Readdir" gets subsequent entries from "d". */
        entry = readdir (d);
        if (! entry) {
            /* There are no more entries in this directory, so break
               out of the while loop. */
            break;
        }
        d_name = entry->d_name;
        /* Print the name of the file and directory. */

	/* If you don't want to print the directories, use the
	   following line: */

        if ( (entry->d_type & DT_DIR)) {
            if(!strcmp(d_name, findname)){
                //printf ("%s/%s\n", dir_name, d_name);
                sprintf(found_dir_path, "%s/%s", dir_name, d_name);
            }
	    }



        if (entry->d_type & DT_DIR) {

            /* Check that the directory is not "d" or d's parent. */

            if (strcmp (d_name, "..") != 0 &&
                strcmp (d_name, ".") != 0) {
                int path_length;
                char path[PATH_MAX];

                path_length = snprintf (path, PATH_MAX,
                                        "%s/%s", dir_name, d_name);
                //printf ("%s\n", path);
                if (path_length >= PATH_MAX) {
                    fprintf (stderr, "Path length has got too long.\n");
                    exit (EXIT_FAILURE);
                }
                /* Recursively call "list_dir" with the new path. */
                find_dir_recursively (path, findname);
            }
	}
    }
    /* After going through all the entries, close the directory. */
    if (closedir (d)) {
        fprintf (stderr, "Could not close '%s': %s\n",
                 dir_name, strerror (errno));
        exit (EXIT_FAILURE);
    }
}


extern "C" int printv(char* fmt, ...)
{
#define BUFSZ 0x400
    static  char buff[BUFSZ];
    va_list ap;
    va_start(ap, fmt);
    size_t size = vsnprintf(buff, BUFSZ, fmt, ap);
#if LOG_OUTPUT == USING_PRINTF_LOG
#elif LOG_OUTPUT == USING_FRIDA_LOG
    _frida_log(buff);
#endif
    va_end(ap);

    return 0;
}

