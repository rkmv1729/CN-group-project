#ifndef TLOG_H
#define TLOG_H

typedef enum { LOGLVL_ERROR, LOGLVL_WARN, LOGLVL_INFO, LOGLVL_DEBUG, LOGLVL_TRACE } log_level;

int  log_init(const char *path, log_level lvl);   /* path NULL = stderr */
void log_close(void);
int  log_level_from_str(const char *s, log_level *out);
void log_msg(log_level lvl, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#define LOGE(...) log_msg(LOGLVL_ERROR, __VA_ARGS__)
#define LOGW(...) log_msg(LOGLVL_WARN,  __VA_ARGS__)
#define LOGI(...) log_msg(LOGLVL_INFO,  __VA_ARGS__)
#define LOGD(...) log_msg(LOGLVL_DEBUG, __VA_ARGS__)
#define LOGT(...) log_msg(LOGLVL_TRACE, __VA_ARGS__)

#endif
