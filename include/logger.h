#ifndef LOGGER_H
#define LOGGER_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_WARN  = 2,
    LOG_LEVEL_ERROR = 3
} log_level_t;

int logger_init(const char *filename, log_level_t min_level);
void logger_close(void);
void logger_set_level(log_level_t level);

void logger_log(log_level_t level, const char *file, const char *func, int line, const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));

void logger_banner(const char *title, const char *subtitle);
void logger_section(const char *label);

void logger_segment(int outbound, uint8_t flags, uint32_t seq, uint32_t ack,
                    const unsigned char *data, size_t data_len, int has_ack);

const char *tcp_flags_to_str(uint8_t flags, char *buf, size_t buf_len);

#define LOG_DEBUG(fmt, ...) logger_log(LOG_LEVEL_DEBUG, __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  logger_log(LOG_LEVEL_INFO,  __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  logger_log(LOG_LEVEL_WARN,  __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) logger_log(LOG_LEVEL_ERROR, __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)

#endif /* LOGGER_H */
