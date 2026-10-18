#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include "tcp_header.h"

static FILE *log_file = NULL;
static log_level_t current_level = LOG_LEVEL_INFO;

#define ANSI_RESET   "\x1b[0m"
#define ANSI_RED     "\x1b[31m"
#define ANSI_GREEN   "\x1b[32m"
#define ANSI_YELLOW  "\x1b[33m"
#define ANSI_BLUE    "\x1b[34m"
#define ANSI_MAGENTA "\x1b[35m"
#define ANSI_CYAN    "\x1b[36m"
#define ANSI_BOLD    "\x1b[1m"
#define ANSI_DIM     "\x1b[2m"

static int is_tty(void) {
    static int cached = -1;
    if (cached == -1) cached = isatty(fileno(stdout));
    return cached;
}

int logger_init(const char *filename, log_level_t min_level) {
    current_level = min_level;
    if (filename != NULL) {
        log_file = fopen(filename, "w");
        if (!log_file) {
            perror("[logger] Error opening log file");
            return -1;
        }
    }
    return 0;
}

void logger_close(void) {
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
}

void logger_set_level(log_level_t level) {
    current_level = level;
}

static void get_timestamp(char *buf, size_t buf_len) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm_buf;
    localtime_r(&tv.tv_sec, &tm_buf);
    int written = strftime(buf, buf_len, "%Y-%m-%d %H:%M:%S", &tm_buf);
    if (written > 0 && (size_t)written < buf_len) {
        snprintf(buf + written, buf_len - written, ".%03d", (int)(tv.tv_usec / 1000));
    }
}

void logger_log(log_level_t level, const char *file, const char *func, int line, const char *fmt, ...) {
    if (level < current_level) return;

    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    const char *lvl_str = "INFO ";
    const char *color   = ANSI_GREEN;
    switch (level) {
        case LOG_LEVEL_DEBUG: lvl_str = "DEBUG"; color = ANSI_DIM; break;
        case LOG_LEVEL_INFO:  lvl_str = "INFO "; color = ANSI_GREEN; break;
        case LOG_LEVEL_WARN:  lvl_str = "WARN "; color = ANSI_YELLOW; break;
        case LOG_LEVEL_ERROR: lvl_str = "ERROR"; color = ANSI_RED; break;
    }

    char message[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    const char *base_file = strrchr(file, '/');
    base_file = base_file ? base_file + 1 : file;

    if (is_tty()) {
        printf("%s%s %s.%s():%d\t%s%s : %s%s\n",
               ANSI_DIM, timestamp, base_file, func, line,
               color, lvl_str, message, ANSI_RESET);
    } else {
        printf("%s %s.%s():%d\t%s : %s\n",
               timestamp, base_file, func, line, lvl_str, message);
    }
    fflush(stdout);

    if (log_file) {
        fprintf(log_file, "%s %s.%s():%d\t%s : %s\n",
                timestamp, base_file, func, line, lvl_str, message);
        fflush(log_file);
    }
}

void logger_banner(const char *title, const char *subtitle) {
    if (is_tty()) {
        printf("\n%s%s╔════════════════════════════════════════════════════════════╗%s\n", ANSI_CYAN, ANSI_BOLD, ANSI_RESET);
        printf("%s%s║ %-58s ║%s\n", ANSI_CYAN, ANSI_BOLD, title, ANSI_RESET);
        if (subtitle && *subtitle) {
            printf("%s%s║ %-58s ║%s\n", ANSI_CYAN, ANSI_DIM, subtitle, ANSI_RESET);
        }
        printf("%s%s╚════════════════════════════════════════════════════════════╝%s\n\n", ANSI_CYAN, ANSI_BOLD, ANSI_RESET);
    } else {
        printf("\n╔════════════════════════════════════════════════════════════╗\n");
        printf("║ %-58s ║\n", title);
        if (subtitle && *subtitle) printf("║ %-58s ║\n", subtitle);
        printf("╚════════════════════════════════════════════════════════════╝\n\n");
    }
    fflush(stdout);
}

void logger_section(const char *label) {
    char line[80];
    int label_len = (int)strlen(label);
    int total_width = 62;
    int side = (total_width - label_len - 2) / 2;
    if (side < 3) side = 3;

    char dashes[40];
    if (side >= (int)sizeof(dashes)) side = sizeof(dashes) - 1;
    for (int i = 0; i < side; i++) dashes[i] = '-';
    dashes[side] = '\0';

    snprintf(line, sizeof(line), "%s %s %s", dashes, label, dashes);

    if (is_tty()) {
        printf("%s%s%s%s\n", ANSI_CYAN, ANSI_BOLD, line, ANSI_RESET);
    } else {
        printf("%s\n", line);
    }
    fflush(stdout);

    if (log_file) {
        fprintf(log_file, "%s\n", line);
        fflush(log_file);
    }
}

const char *tcp_flags_to_str(uint8_t flags, char *buf, size_t buf_len) {
    buf[0] = '\0';
    int first = 1;
    struct { uint8_t flag; const char *name; } items[] = {
        {TCP_SYN, "SYN"}, {TCP_ACK, "ACK"}, {TCP_PSH, "PSH"},
        {TCP_FIN, "FIN"}, {TCP_RST, "RST"}, {TCP_URG, "URG"}
    };

    for (size_t i = 0; i < sizeof(items)/sizeof(items[0]); i++) {
        if (flags & items[i].flag) {
            if (!first) strncat(buf, ", ", buf_len - strlen(buf) - 1);
            strncat(buf, items[i].name, buf_len - strlen(buf) - 1);
            first = 0;
        }
    }
    return buf;
}

void logger_segment(int outbound, uint8_t flags, uint32_t seq, uint32_t ack,
                    const unsigned char *data, size_t data_len, int has_ack) {
    char flags_str[32];
    tcp_flags_to_str(flags, flags_str, sizeof(flags_str));

    const char *dir_str = outbound ? "Client -> Server" : "Server -> Client";
    const char *dir_color = outbound ? ANSI_BLUE : ANSI_YELLOW;

    char ack_part[32] = "";
    if (has_ack) {
        snprintf(ack_part, sizeof(ack_part), " ACK=%u", ack);
    }

    char len_part[32] = "";
    if (data_len > 0) {
        snprintf(len_part, sizeof(len_part), " LEN=%zu", data_len);
    }

    char desc_part[64] = "";
    if (data_len > 0 && data != NULL) {
        snprintf(desc_part, sizeof(desc_part), " (1 KB Payload)");
    }

    if (is_tty()) {
        printf("%s%-16s%s [%s%s%s] SEQ=%u%s%s%s\n",
               dir_color, dir_str, ANSI_RESET,
               ANSI_BOLD, flags_str, ANSI_RESET,
               seq, ack_part, len_part, desc_part);
    } else {
        printf("%-16s [%s] SEQ=%u%s%s%s\n",
               dir_str, flags_str, seq, ack_part, len_part, desc_part);
    }
    fflush(stdout);

    if (log_file) {
        fprintf(log_file, "%-16s [%s] SEQ=%u%s%s%s\n",
                dir_str, flags_str, seq, ack_part, len_part, desc_part);
        fflush(log_file);
    }
}
