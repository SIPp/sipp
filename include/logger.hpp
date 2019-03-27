#ifndef __SIPP_LOGGER_H__
#define __SIPP_LOGGER_H__

/************************** Trace Files ***********************/

#include <time.h>
#include "sipp.hpp"

#ifdef GLOBALS_FULL_DEFINITION
#define extern
#define DEFVAL(value) = value
#else
#define DEFVAL(value)
#endif

extern FILE * screenf                             DEFVAL(0);
extern FILE * countf                              DEFVAL(0);
extern FILE * codesf                              DEFVAL(0);
// extern FILE * timeoutf                            DEFVAL(0);
extern bool   useMessagef                         DEFVAL(0);
extern bool   useErrorCodesf                      DEFVAL(0);
extern bool   useCallDebugf                       DEFVAL(0);
extern bool   useShortMessagef                    DEFVAL(0);
extern bool   useScreenf                          DEFVAL(0);
extern bool   useLogf                             DEFVAL(0);
// extern bool   useTimeoutf                         DEFVAL(0);
extern bool   dumpInFile                          DEFVAL(0);
extern bool   dumpInRtt                           DEFVAL(0);
extern bool   useCountf                           DEFVAL(0);
extern char * slave_cfg_file;

extern unsigned long long max_log_size            DEFVAL(0);
extern unsigned long long ringbuffer_size         DEFVAL(0);
extern int    ringbuffer_files                    DEFVAL(0);

extern char   screen_last_error[32768];
extern char   screen_logfile[MAX_PATH]            DEFVAL("");
/* Log Rotation Functions. */
struct logfile_id {
    time_t start;
    int n;
};

struct logfile_info {
    const char *name;
    bool check;
    FILE *fptr;
    int nfiles;
    struct logfile_id *ftimes;
    char file_name[MAX_PATH];
    bool overwrite;
    bool fixedname;
    time_t starttime;
    unsigned int count;
};

void print_header_line(FILE *f);
void print_bottom_line(FILE *f, int last);
void print_variable_list();
void print_tdm_map();
void print_screens(void);

void log_off(struct logfile_info *lfi);

#ifdef GLOBALS_FULL_DEFINITION
#define LOGFILE(name, s, check) \
        struct logfile_info name = { s, check, NULL, 0, NULL, "", true, false, 0, 0}
#else
#define LOGFILE(name, s, check) \
        extern struct logfile_info name
#endif
LOGFILE(calldebug_lfi, "calldebug", true);
LOGFILE(message_lfi, "messages", true);
LOGFILE(screen_lfi, "screen", true);
LOGFILE(shortmessage_lfi, "shortmessages", true);
LOGFILE(log_lfi, "logs", true);
LOGFILE(error_lfi, "errors", false);

void rotate_logfile();
void rotate_shortmessagef();
void rotate_errorf();
void rotate_messagef();
void rotate_screenf();
void rotate_calldebugf();

/* Screen/Statistics Printing Functions. */
void print_statistics(int last);
void print_count_file(FILE* f, int header);
void print_error_codes_file(FILE* f);

/* This must go after the GLOBALS_FULL_DEFINITION, because we need the extern keyword. */
int TRACE_MSG(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
int TRACE_CALLDEBUG(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
int TRACE_SHORTMSG(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
int LOG_MSG(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

#endif /* __SIPP_LOGGER_H__ */
