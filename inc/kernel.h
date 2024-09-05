#ifndef _KERNEL_H_
#define _KERNEL_H_

#include "debug.h"
#include "global.h"
#include "tju_packet.h"
#include "tju_tcp.h"
#include <unistd.h>

#define MAX_SOCK 32
tju_tcp_t *listen_socks[MAX_SOCK];
tju_tcp_t *established_socks[MAX_SOCK];

typedef struct
{
    tju_tcp_t *data[MAX_SOCK]; // 存放队列元素的数组
    int front;                 // 指向队首的索引
    int rear;                  // 指向队尾的索引
    int size;                  // 队列当前的元素数量
} queue;

queue accept_queue;
/*
模拟Linux内核收到一份TCP报文的处理函数
*/
void onTCPPocket(char *pkt);

/*
以用户填写的TCP报文为参数
根据用户填写的TCP的目的IP和目的端口,向该地址发送数据报
*/
void sendToLayer3(char *packet_buf, int packet_len);

/*
开启仿真, 运行起后台线程
*/
void startSimulation();

/*
 使用UDP进行数据接收的线程
*/
void *receive_thread(void *in);

// 接受UDP的socket的标识符
int BACKEND_UDPSOCKET_ID;

/*
 linux内核会根据
 本地IP 本地PORT 远端IP 远端PORT 计算hash值 四元组
 找到唯一的那个socket

 (实际上真正区分socket的是五元组
  还有一个协议字段
  不过由于本项目是TCP 协议都一样, 就没必要了)
*/
int cal_hash(uint32_t local_ip, uint16_t local_port, uint32_t remote_ip, uint16_t remote_port);

// 用于将IP地址转换为字符串
const char *intToIp(uint32_t ip);

// 初始化server接收连接队列
void initQueue(queue *q);

// 检查队列是否为空
int isEmpty(queue *q);

// 检查队列是否已满
int isFull(queue *q);

// 元素加入队列
void enqueue(queue *q, tju_tcp_t *value);

// 元素出队列
tju_tcp_t *dequeue(queue *q);

// 获取队首元素但不出队
tju_tcp_t *peek(queue *q);

void send_pkt(tju_tcp_t *sock, char *pkt, int len);

#endif