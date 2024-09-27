#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "global.h"
#include <pthread.h>
#include <sys/select.h>
#include <arpa/inet.h>

#define SERVER_IP "172.17.0.3"
#define CLIENT_IP "172.17.0.2"

// 单位是byte
#define SIZE32 4
#define SIZE16 2
#define SIZE8 1

// 一些Flag
#define NO_FLAG 0
#define NO_WAIT 1
#define TIMEOUT 2
#define TRUE 1
#define FALSE 0

// 定义最大包长 防止IP层分片
#define MAX_DLEN 1375 // 最大包内数据长度
#define MAX_LEN 1400  // 最大包长度

// TCP socket 状态定义
#define CLOSED 0
#define LISTEN 1
#define SYN_SENT 2
#define SYN_RECV 3
#define ESTABLISHED 4
#define FIN_WAIT_1 5
#define FIN_WAIT_2 6
#define CLOSE_WAIT 7
#define CLOSING 8
#define LAST_ACK 9
#define TIME_WAIT 10

// TCP 拥塞控制状态
#define SLOW_START 0
#define CONGESTION_AVOIDANCE 1
#define FAST_RECOVERY 2
#define timeout 3


// TCP 接受窗口大小
#define TCP_RECVWN_SIZE 24 * MAX_DLEN // 比如最多放32个满载数据包

// TCP 发送和接收缓冲区大小
#define TCP_SEND_BUFFER_SIZE 128 * MAX_DLEN
#define TCP_RECV_BUFFER_SIZE 128 * MAX_DLEN

#define IW 6 * MAX_DLEN
#define MSS 1 * MAX_DLEN
//INT16_MAX

// TCP 发送窗口
// 注释的内容如果想用就可以用 不想用就删掉 仅仅提供思路和灵感
typedef struct
{
	uint32_t window_size;

	uint32_t base;
	uint32_t nextseq;
	long estmated_rtt;
	long sample_rtt;
	long deviation_rtt;
	long timeout_interval;
	int ack_cnt;
	pthread_mutex_t ack_cnt_lock;
	struct timeval send_time;
	uint16_t rwnd;

	int congestion_status; // 拥塞控制中的状态
	uint16_t cwnd; // 拥塞窗口大小
	uint16_t ssthresh; // 拥塞阈值
	int status_type;
} sender_window_t;

typedef struct received_packet_t received_packet_t;
struct received_packet_t
{
	char* data;
	uint32_t seq;
	uint32_t nextseq;
	uint32_t len;
	struct received_packet_t* next;
};

// TCP 接受窗口
// 注释的内容如果想用就可以用 不想用就删掉 仅仅提供思路和灵感
typedef struct
{
	// char received[TCP_RECVWN_SIZE];
	// received_packet_t* head;
	// char buf[TCP_RECVWN_SIZE];
	// uint8_t marked[TCP_RECVWN_SIZE];
	pthread_mutex_t buf_queue_lock;
	received_packet_t* head;
	uint32_t expect_seq;
	uint16_t buffered_size;
	int buf_packet_cnt;
} receiver_window_t;

// TCP 窗口 每个建立了连接的TCP都包括发送和接受两个窗口
typedef struct
{
	sender_window_t* wnd_send;
	receiver_window_t* wnd_recv;
} window_t;

typedef struct
{
	uint32_t ip;
	uint16_t port;
} tju_sock_addr;

typedef struct {
	int timer_state;
	long start_time;
	long cur_time;
	// long RTO;
} timers;

// typedef struct sock_node sock_node;
// typedef struct sock_queue sock_queue;


// TJU_TCP 结构体 保存TJU_TCP用到的各种数据
typedef struct {
	int state; // TCP的状态

	tju_sock_addr bind_addr; // 存放bind和listen时该socket绑定的IP和端口
	tju_sock_addr established_local_addr; // 存放建立连接后 本机的 IP和端口
	tju_sock_addr established_remote_addr; // 存放建立连接后 连接对方的 IP和端口

	pthread_mutex_t send_lock; // 发送数据锁
	char* sending_buf; // 发送数据缓存区
	int sending_len; // 发送数据缓存长度
	int sending_capacity; // 发送数据缓冲区的容量

	pthread_mutex_t recv_lock; // 接收数据锁
	char* received_buf; // 接收数据缓存区
	int received_len; // 接收数据缓存长度
	int received_capacity; // 接收数据缓冲区的容量

	pthread_cond_t wait_cond; // 可以被用来唤醒recv函数调用时等待的线程

	window_t window; // 发送和接受窗口

	timers htimer;
	timers timer;
	// struct sock_queue* half_established_sock;
	// struct sock_queue* established_sock;

} tju_tcp_t;
pthread_mutex_t sended_lock;

#endif