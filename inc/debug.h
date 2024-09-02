#ifndef DEBUG_H
#define DEBUG_H

#define DEBUG_FLAG 1
#define INFO_FLAG 1
#define MSG_FLAG 1

#include <stdio.h>
#include <time.h>
#include <sys/time.h>

static inline void get_formatted_time(char *buffer, size_t buffer_size, int include_microseconds) {
    struct timeval tv;
    struct tm *timeinfo;

    gettimeofday(&tv, NULL);
    timeinfo = localtime(&tv.tv_sec);
    
    if (include_microseconds) {
        strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", timeinfo);
        snprintf(buffer + 19, buffer_size - 19, ".%06ld", tv.tv_usec);
    } else {
        strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", timeinfo);
    }
}

#define _info_(format, ...)                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        if (INFO_FLAG)                                                                                                 \
        {                                                                                                              \
            char buffer[40];                                                                                           \
            get_formatted_time(buffer, sizeof(buffer), 1);                                                             \
            printf("\33[1;34m [INFO] [%s] \33[0m" format " \n", buffer, ##__VA_ARGS__);                                \
        }                                                                                                              \
    } while (0)

#define _msg_(format, ...)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        if (MSG_FLAG)                                                                                                  \
        {                                                                                                              \
            char buffer[40];  /* Increased buffer size to 40 */                                                        \
            get_formatted_time(buffer, sizeof(buffer), 1);                                                             \
            printf("\33[1;32m [MSG] [%s] \33[0m" format " \n", buffer, ##__VA_ARGS__);                                 \
        }                                                                                                              \
    } while (0)

#define _debug_(format, ...)                                                                                           \
    do                                                                                                                 \
    {                                                                                                                  \
        if (DEBUG_FLAG)                                                                                                \
        {                                                                                                              \
            char buffer[40];                                                                                           \
            get_formatted_time(buffer, sizeof(buffer), 1);                                                             \
            printf("\33[1;91m [DEBUG] [%s] \33[0m" format " \n", buffer, ##__VA_ARGS__);                               \
        }                                                                                                              \
    } while (0)


#define STATE_TO_STRING(state)                                                                                         \
    ((state) == CLOSED        ? "CLOSED"                                                                               \
     : (state) == LISTEN      ? "LISTEN"                                                                               \
     : (state) == SYN_SENT    ? "SYN_SENT"                                                                             \
     : (state) == SYN_RECV    ? "SYN_RECV"                                                                             \
     : (state) == ESTABLISHED ? "ESTABLISHED"                                                                          \
     : (state) == FIN_WAIT_1  ? "FIN_WAIT_1"                                                                           \
     : (state) == FIN_WAIT_2  ? "FIN_WAIT_2"                                                                           \
     : (state) == CLOSE_WAIT  ? "CLOSE_WAIT"                                                                           \
     : (state) == CLOSING     ? "CLOSING"                                                                              \
     : (state) == LAST_ACK    ? "LAST_ACK"                                                                             \
     : (state) == TIME_WAIT   ? "TIME_WAIT"                                                                            \
                              : "UNKNOWN")

#endif