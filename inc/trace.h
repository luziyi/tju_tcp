#ifndef TRAC_H
#define TRACE_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

static long getCurrentTime()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}

static void log_event(FILE *file, const char *event_type, const char *format, ...)
{
    long timestamp = getCurrentTime();
    fprintf(file, "[%lu] [%s] ", timestamp, event_type);
    va_list args;
    va_start(args, format);
    vfprintf(file, format, args);
    va_end(args);
    fprintf(file, "\n");
    fflush(file);
}

/*
    log_event(file, "SEND", "seq:%d ack:%d flag:%d length:%d", 33, 66, 0, 111);
    log_event(file, "RECV", "seq:%d ack:%d flag:%d length:%d", 44, 88, 4, 222);
    log_event(file, "CWND", "type:%d size:%d", 0, 1);
    log_event(file, "RWND", "size:%d", 3);
    log_event(file, "SWND", "size:%d", 5);
    log_event(file, "DELV", "seq:%d size:%d", 55, 1000);
    log_event(file, "RTTS", "SampleRTT:%f EstimatedRTT:%f DeviationRTT:%f TimeoutInterval:%f",
              12.5, 12.562665, 0.407346, 14.192051);

    event= SEND/ RECV/ CWND/ RWND/ SWND / RTTS / DELV

    [info]
info是event的更详细的信息，不同的event有不同的描述信息：
SEND事件应包括：发送的包的序列号，确认号，标志位和payload的长度，即“seq:%d ack:%d
flag:%d length:%d”
seq:%d、ack:%d、flag:%s和length:%d之间用一个空格分隔开
flag标志位用数字表示：
0 —> NO_FLAG
1 —> 没有对应
2 —> FIN
4 —> ACK
8 —> SYN
12 —> SYN|ACK
RECV事件应包括：接收的包的序列号，确认号，标志位和payload的长度，即“seq:%d ack:%d
flag:%d length:%d”
seq:%d、ack:%d和、flag:%s和length:%d之间用一个空格分隔开
CWND事件应包括：引起拥塞窗口变化的原因类型和窗口大小变化后的值，即“type:%d size:%d”
type:%d和size:%d之间用一个空格分隔开
type分为4类，用数字0,1,2,3分别表示slow start、congestion avoidance、fast retransmit和
timeout
size的单位是byte=segment*1375
RWND事件应包括：当前接收方可用缓冲区的大小，即“size:%d”
size的单位是byte=segment*1375
SWND事件应包括：当前发送窗口的窗口大小，即“size:%d”
size的单位是byte=segment*1375
RTTS事件应包括：当前SampleRTT、EstimatedRTT、DeviationRTT、TimeoutInterval的值，即
“SampleRTT:%f EstimatedRTT:%f DeviationRTT:%f TimeoutInterval:%f”
SampleRTT:%f、EstimatedRTT:%f、DeviationRTT:%f、TimeoutInterval:%f之间用一个空格分隔
开
SampleRTT、EstimatedRTT、DeviationRTT、TimeoutInterval的单位都是ms
DELV事件应包括：每次接收窗口交付按序到达的数据时，包的序列号和交付的数据量，即"seq:%d
size:%d"
seq:%d和size:%d之间用一个空格分隔开
size的单位是byte
*/

#endif