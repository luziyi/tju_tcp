#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>

#define _info_(format, ...) \
    printf("\33[1;34m [INFO] \33[0m" format "\n", ##__VA_ARGS__)

#define _msg_(format, ...)\
    printf("\33[1;32m [MSG] \33[0m" format "\n", ##__VA_ARGS__)

#define _debug_(format,...)\
    printf("\33[1;91m [DEBUG] \33[0m" format "\n",##__VA_ARGS__)

#define STATE_TO_STRING(state) \
    ((state) == CLOSED ? "CLOSED" : \
    (state) == LISTEN ? "LISTEN" : \
    (state) == SYN_SENT ? "SYN_SENT" : \
    (state) == SYN_RECV ? "SYN_RECV" : \
    (state) == ESTABLISHED ? "ESTABLISHED" : \
    (state) == FIN_WAIT_1 ? "FIN_WAIT_1" : \
    (state) == FIN_WAIT_2 ? "FIN_WAIT_2" : \
    (state) == CLOSE_WAIT ? "CLOSE_WAIT" : \
    (state) == CLOSING ? "CLOSING" : \
    (state) == LAST_ACK ? "LAST_ACK" : \
    (state) == TIME_WAIT ? "TIME_WAIT" : "UNKNOWN")

#endif