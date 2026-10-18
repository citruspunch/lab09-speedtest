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

#define ANSI_RESET       "\x1b[0m"
#define ANSI_BOLD        "\x1b[1m"
#define ANSI_DIM         "\x1b[2m"
#define ANSI_RED         "\x1b[31m"
#define ANSI_GREEN       "\x1b[32m"
#define ANSI_YELLOW      "\x1b[33m"
#define ANSI_BLUE        "\x1b[34m"
#define ANSI_MAGENTA     "\x1b[35m"
#define ANSI_CYAN        "\x1b[36m"
#define ANSI_WHITE       "\x1b[37m"
#define ANSI_BOLD_RED    "\x1b[1;31m"
#define ANSI_BOLD_GREEN  "\x1b[1;32m"
#define ANSI_BOLD_YELLOW "\x1b[1;33m"
#define ANSI_BOLD_BLUE   "\x1b[1;34m"
#define ANSI_BOLD_MAGENTA "\x1b[1;35m"
#define ANSI_BOLD_CYAN   "\x1b[1;36m"
#define ANSI_BOLD_WHITE  "\x1b[1;37m"

int logger_use_color(void);

const char *tcp_flags_to_str(uint8_t flags, char *buf, size_t buf_len);

#define LOG_DEBUG(fmt, ...) logger_log(LOG_LEVEL_DEBUG, __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  logger_log(LOG_LEVEL_INFO,  __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  logger_log(LOG_LEVEL_WARN,  __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) logger_log(LOG_LEVEL_ERROR, __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)

#endif /* LOGGER_H */
