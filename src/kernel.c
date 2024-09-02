#include "kernel.h"
#include "stdio.h"
/*
模拟Linux内核收到一份TCP报文的处理函数
*/
void onTCPPocket(char *pkt)
{
    // 当我们收到TCP包时 包中 源IP 源端口 是发送方的 也就是我们眼里的
    // 远程(remote) IP和端口
    uint16_t remote_port = get_src(pkt);
    uint16_t local_port = get_dst(pkt);
    // remote ip 和 local ip 是读IP 数据包得到的
    // 仿真的话这里直接根据hostname判断

    char hostname[8];
    gethostname(hostname, 8);
    uint32_t remote_ip, local_ip;
    if(strcmp(hostname,"server")==0){ // 自己是服务端 远端就是客户端
        local_ip = inet_network(SERVER_IP);
        remote_ip = inet_network(CLIENT_IP);
    }else if(strcmp(hostname,"client")==0){ // 自己是客户端 远端就是服务端 
        local_ip = inet_network(CLIENT_IP);
        remote_ip = inet_network(SERVER_IP);
    }

    int hashval;
    // 根据4个ip port 组成四元组 查找有没有已经建立连接的socket
    hashval = cal_hash(local_ip, local_port, remote_ip, remote_port);
    // 首先查找已经建立连接的socket哈希表
    if (established_socks[hashval] != NULL)
    {
        tju_handle_packet(established_socks[hashval], pkt);
        return;
    }
    // 没有的话再查找监听中的socket哈希表
    hashval = cal_hash(local_ip, local_port, 0,
                       0); // 监听的socket只有本地监听ip和端口 没有远端
    if (listen_socks[hashval] != NULL)
    {
        tju_handle_packet(listen_socks[hashval], pkt);
        return;
    }

    // 都没找到 丢掉数据包
    printf("找不到能够处理该TCP数据包的socket, 丢弃该数据包\n");
    return;
}

/*
以用户填写的TCP报文为参数
根据用户填写的TCP的目的IP和目的端口,向该地址发送数据报
不可以修改此函数实现
*/
void sendToLayer3(char *packet_buf, int packet_len)
{
    if (packet_len > MAX_LEN)
    {
        printf("ERROR: 不能发送超过 MAX_LEN 长度的packet, 防止IP层进行分片\n");
        return;
    }

    // 获取hostname 根据hostname 判断是客户端还是服务端
    char hostname[8];
    gethostname(hostname, 8);
    // printf("sendToLayer3 on hostname: %s\n", hostname);
    struct sockaddr_in conn;
    conn.sin_family = AF_INET;
    conn.sin_port = htons(20218);
    int rst;
    if(strcmp(hostname,"server")==0){
        conn.sin_addr.s_addr = inet_addr(CLIENT_IP);
        rst = sendto(BACKEND_UDPSOCKET_ID, packet_buf, packet_len, 0, (struct sockaddr*)&conn, sizeof(conn));
    }else if(strcmp(hostname,"client")==0){       
        conn.sin_addr.s_addr = inet_addr(SERVER_IP);
        rst = sendto(BACKEND_UDPSOCKET_ID, packet_buf, packet_len, 0, (struct sockaddr*)&conn, sizeof(conn));
    }else{
        printf("请不要改动hostname...\n");
        exit(-1);
    }
}

/*
 仿真接受数据线程
 不断调用server或client监听在20218端口的UDPsocket的recvfrom
 一旦收到了大于TCPheader长度的数据
 则接受整个TCP包并调用onTCPPocket()
*/
void *receive_thread(void *arg)
{
    char hdr[DEFAULT_HEADER_LEN];
    char *pkt;

    uint32_t plen = 0, buf_size = 0, n = 0;
    int len;

    struct sockaddr_in from_addr;
    int from_addr_size = sizeof(from_addr);

    while (1)
    {
        // MSG_PEEK 表示看一眼 不会把数据从缓冲区删除
        len = recvfrom(BACKEND_UDPSOCKET_ID, hdr, DEFAULT_HEADER_LEN, MSG_PEEK, (struct sockaddr *)&from_addr,
                       &from_addr_size);
        // 一旦收到了大于header长度的数据 则接受整个TCP包
        if (len >= DEFAULT_HEADER_LEN)
        {
            plen = get_plen(hdr);
            pkt = malloc(plen);
            buf_size = 0;
            while (buf_size < plen)
            { // 直到接收到 plen 长度的数据 接受的数据全部存在pkt中
                n = recvfrom(BACKEND_UDPSOCKET_ID, pkt + buf_size, plen - buf_size, NO_FLAG,
                             (struct sockaddr *)&from_addr, &from_addr_size);
                buf_size = buf_size + n;
            }
            // printf("receive_thread: received a packet\n");
            // 通知内核收到一个完整的TCP报文
            onTCPPocket(pkt);
            free(pkt);
        }
    }
}

/*
 仿真发送数据线程
*/
void *send_thread(void *arg)
{
    // 检查 sock->sending_buf
    // 如果不为空 则调用sendToLayer3发送数据
    // 发送完毕后 释放sock->sending_buf
    while (1)
    {
        int index;
        for (index = 0; index < MAX_SOCK; index++)
        {
            if (established_socks[index] != NULL)
            {
                tju_tcp_t *sock = established_socks[index];
                while (pthread_mutex_lock(&(sock->send_lock)) != 0)
                    ; // 加锁

                if(sock->sending_len > 0)
                {
                    int len = sock->sending_len <= MAX_LEN - DEFAULT_HEADER_LEN ? sock->sending_len : MAX_LEN - DEFAULT_HEADER_LEN;

                    // 截断 len
                    char *pkt = malloc(len);
                    memcpy(pkt, sock->sending_buf, len);

                    // 组装 packet
                    char *msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, 1, 1 + 1,
                                            DEFAULT_HEADER_LEN, len + DEFAULT_HEADER_LEN, ACK_FLAG_MASK, 1, 0, pkt, len);
                    
                    // 发送
                    sendToLayer3(msg, DEFAULT_HEADER_LEN + len);

                    // 释放
                    free(pkt);
                    free(msg);

                    // 释放发送缓存区
                    char* new_buf = malloc(sock->sending_len - len);
                    memcpy(new_buf, sock->sending_buf + len, sock->sending_len - len);
                    free(sock->sending_buf);
                    sock->sending_buf = new_buf;
                    sock->sending_len -= len;

                    _debug_("send a packet: len = %d", len);
                }

                pthread_mutex_unlock(&(sock->send_lock)); // 解锁
            }
        }
    }
}

/*
 开启仿真, 运行起后台线程

 不论是server还是client
 都创建一个UDP socket 监听在20218端口
 然后创建新线程 不断调用该socket的recvfrom
*/
void startSimulation()
{
    // 对于内核 初始化监听socket哈希表和建立连接socket哈希表
    int index;
    for (index = 0; index < MAX_SOCK; index++)
    {
        listen_socks[index] = NULL;
        established_socks[index] = NULL;
    }

    // 获取hostname
    char hostname[8];
    gethostname(hostname, 8);
    _info_("startSimulation on hostname: %s", hostname);

    BACKEND_UDPSOCKET_ID = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (BACKEND_UDPSOCKET_ID < 0)
    {
        printf("ERROR opening socket");
        exit(-1);
    }

    // 设置socket选项 SO_REUSEADDR = 1
    // 意思是 允许绑定本地地址冲突 和
    // 改变了系统对处于TIME_WAIT状态的socket的看待方式
    int optval = 1;
    setsockopt(BACKEND_UDPSOCKET_ID, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));

    struct sockaddr_in conn;
    memset(&conn, 0, sizeof(conn));
    conn.sin_family = AF_INET;
    conn.sin_addr.s_addr = htonl(INADDR_ANY); // INADDR_ANY = 0.0.0.0
    conn.sin_port = htons((unsigned short)20218);

    if (bind(BACKEND_UDPSOCKET_ID, (struct sockaddr *)&conn, sizeof(conn)) < 0)
    {
        printf("ERROR on binding");
        exit(-1);
    }

    // 创建一个线程 不断调用receive_thread
    pthread_t thread_id = 1001;
    int rst = pthread_create(&thread_id, NULL, receive_thread, (void *)(&BACKEND_UDPSOCKET_ID));
    if (rst < 0)
    {
        printf("ERROR open thread");
        exit(-1);
    }

    // 创建一个线程 不断调用send_thread
    pthread_t thread_id2 = 1002;
    rst = pthread_create(&thread_id2, NULL, send_thread, (void *)(&BACKEND_UDPSOCKET_ID));
    if (rst < 0)
    {
        printf("ERROR open thread");
        exit(-1);
    }

    printf("successfully created bankend thread\n");
    return;
}

int cal_hash(uint32_t local_ip, uint16_t local_port, uint32_t remote_ip, uint16_t remote_port)
{
    uint64_t hash = 0;
    // 对每个字段进行简单的移位和XOR操作
    hash ^= ((uint64_t)local_ip << 32) | remote_ip;
    hash ^= ((uint64_t)local_port << 16) | remote_port;
    // 将64位的哈希值缩小到适合的范围
    return (int)(hash % MAX_SOCK);
}

const char *intToIp(uint32_t ip)
{
    static char ipStr[16]; // IPv4地址的字符串表示最多15个字符，加上终止符'\0'
    snprintf(ipStr, sizeof(ipStr), "%u.%u.%u.%u",
             (ip >> 24) & 0xFF, // 取最高的8位
             (ip >> 16) & 0xFF, // 取次高的8位
             (ip >> 8) & 0xFF,  // 取次低的8位
             ip & 0xFF);        // 取最低的8位
    return ipStr;
}

void initQueue(queue *q)
{
    q->front = 0;
    q->rear = -1;
    q->size = 0;
}

// 检查队列是否为空
int isEmpty(queue *q)
{
    return q->size == 0;
}

// 检查队列是否已满
int isFull(queue *q)
{
    return q->size == MAX_SOCK;
}

// 入队操作
void enqueue(queue *q, tju_tcp_t *value)
{
    if (isFull(q))
    {
        printf("Queue is full\n");
        return;
    }

    q->rear = (q->rear + 1) % MAX_SOCK;
    q->data[q->rear] = value;
    q->size++;
}

// 出队操作
tju_tcp_t *dequeue(queue *q)
{
    if (isEmpty(q))
    {
        printf("Queue is empty\n");
        return NULL;
    }

    tju_tcp_t *value = q->data[q->front];
    q->front = (q->front + 1) % MAX_SOCK;
    q->size--;
    return value;
}

// 获取队首元素但不出队
tju_tcp_t *peek(queue *q)
{
    if (isEmpty(q))
    {
        printf("Queue is empty\n");
        return NULL;
    }
    return q->data[q->front];
}
