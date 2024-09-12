#ifndef _TJU_TCP_H_
#define _TJU_TCP_H_

#include "global.h"
#include "tju_packet.h"
#include "kernel.h"

/*
创建 TCP socket
初始化对应的结构体
设置初始状态为 CLOSED
*/
tju_tcp_t* tju_socket();

/*
绑定监听的地址 包括ip和端口
*/
int tju_bind(tju_tcp_t* sock, tju_sock_addr bind_addr);

/*
被动打开 监听bind的地址和端口
设置socket的状态为LISTEN
*/
int tju_listen(tju_tcp_t* sock);

/*
接受连接
返回与客户端通信用的socket
这里返回的socket一定是已经完成3次握手建立了连接的socket
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
tju_tcp_t* tju_accept(tju_tcp_t* sock);


/*
连接到服务端
该函数以一个socket为参数
调用函数前, 该socket还未建立连接
函数正常返回后, 该socket一定是已经完成了3次握手, 建立了连接
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
int tju_connect(tju_tcp_t* sock, tju_sock_addr target_addr);


int tju_send(tju_tcp_t* sock, const void* buffer, int len);
int tju_recv(tju_tcp_t* sock, void* buffer, int len);

/*
关闭一个TCP连接
这里涉及到四次挥手
*/
int tju_close(tju_tcp_t* sock);


int tju_handle_packet(tju_tcp_t* sock, char* pkt);

// typedef struct {
//     tju_tcp_t *sock;
//     tju_packet_t *pkt;
// } timer_param;

int resent_pkt(tju_tcp_t* sock);
void* timeout_thread(void *arg);

// int queue_init(sock_queue** queue);
// int queue_empty(sock_queue* queue);
// tju_tcp_t* queue_pop(sock_queue* queue);
// int queue_push(sock_queue* queue, sock_node* sock);

static tju_tcp_t* esock_queue[32];
static tju_tcp_t* hesock_queue[32];
static int esock_pointer = 0;
static int hesock_pointer = 0;

// static char* send_queue[128];
static tju_packet_t* sended_queue[128];
static int sended_pointer = 0;

// static tju_packet_t* client_sended_queue[128];
// static int client_sended_pointer = 0;
static tju_packet_t* server_sended_queue[128];
static int server_sended_pointer = 0;

tju_packet_t* zero_window_probe;

#define SENT 0
#define RECV 1
#define CWND 2
#define RWND 3
#define SWND 4
#define RTTS 5
#define DELV 6

#define ALPHA 0.125
#define BETA 0.25
long getCurrentTime();
void trace_write(int EVENT, char* pkt, tju_tcp_t* sock);

void* sender_thread(void* arg);

void handle_loss_ack(tju_tcp_t* sock);
void handle_valid_ack(tju_tcp_t* sock);
void handle_dup_ack(tju_tcp_t* sock);

#endif

