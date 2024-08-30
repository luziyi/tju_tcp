#include "tju_tcp.h"

/*
创建 TCP socket
初始化对应的结构体
设置初始状态为 CLOSED
*/
tju_tcp_t *tju_socket()
{
    tju_tcp_t *sock = (tju_tcp_t *)malloc(sizeof(tju_tcp_t));
    sock->state = CLOSED;
    pthread_mutex_init(&(sock->state_lock), NULL);
    pthread_mutex_init(&(sock->send_lock), NULL);
    sock->sending_buf = NULL;
    sock->sending_len = 0;

    pthread_mutex_init(&(sock->recv_lock), NULL);
    sock->received_buf = NULL;
    sock->received_len = 0;

    if (pthread_cond_init(&sock->wait_cond, NULL) != 0)
    {
        perror("ERROR condition variable not set\n");
        exit(-1);
    }

    sock->window.wnd_recv = NULL;
    sock->window.wnd_recv = NULL;

    return sock;
}

/*
绑定监听的地址 包括ip和端口
*/
int tju_bind(tju_tcp_t *sock, tju_sock_addr bind_addr)
{
    sock->bind_addr = bind_addr;
    return 0;
}

/*
被动打开 监听bind的地址和端口
设置socket的状态为LISTEN
注册该socket到内核的监听socket哈希表
*/
int tju_listen(tju_tcp_t *sock)
{
    initQueue(&accept_queue);
    sock->state = LISTEN;
    int hashval = cal_hash(sock->bind_addr.ip, sock->bind_addr.port, 0, 0);
    listen_socks[hashval] = sock;
    return 0;
}

/*
接受连接
返回与客户端通信用的socket
这里返回的socket一定是已经完成3次握手建立了连接的socket
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
tju_tcp_t *tju_accept(tju_tcp_t *listen_sock)
{
    // while (listen_sock->state != SYN_RECV)
    //     ; // 阻塞 直到有SYN_RECV的socket

    // tju_tcp_t *new_conn = (tju_tcp_t *)malloc(sizeof(tju_tcp_t));
    // memcpy(new_conn, listen_sock, sizeof(tju_tcp_t));

    // tju_sock_addr local_addr, remote_addr;

    // // 创建SYN_ACK报文
    // /*
    //  这里涉及到TCP连接的建立
    //  正常来说应该是收到客户端发来的SYN报文
    //  从中拿到对端的IP和PORT
    //  换句话说 下面的处理流程其实不应该放在这里 应该在tju_handle_packet中
    // */
    // remote_addr.ip = inet_network("10.0.0.2"); // 具体的IP地址
    // remote_addr.port = 5678;                   // 端口

    // local_addr.ip = listen_sock->bind_addr.ip;     // 具体的IP地址
    // local_addr.port = listen_sock->bind_addr.port; // 端口

    // new_conn->established_local_addr = local_addr;
    // new_conn->established_remote_addr = remote_addr;

    // // 这里应该是经过三次握手后才能修改状态为ESTABLISHED
    // new_conn->state = ESTABLISHED;

    // // 将新的conn放到内核建立连接的socket哈希表中
    // int hashval = cal_hash(local_addr.ip, local_addr.port, remote_addr.ip, remote_addr.port);
    // established_socks[hashval] = new_conn;

    // // 如果new_conn的创建过程放到了tju_handle_packet中
    // // 那么accept怎么拿到这个new_conn呢 在linux中 每个listen
    // // socket都维护一个已经完成连接的socket队列 每次调用accept
    // // 实际上就是取出这个队列中的一个元素 队列为空,则阻塞
    while (isEmpty(&accept_queue))
        ;
    tju_tcp_t *accepted_conn;
    accepted_conn = dequeue(&accept_queue);
    return accepted_conn;
}

/*
连接到服务端
该函数以一个socket为参数
调用函数前, 该socket还未建立连接
函数正常返回后, 该socket一定是已经完成了3次握手, 建立了连接
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
int tju_connect(tju_tcp_t *sock, tju_sock_addr target_addr)
{
    tju_sock_addr local_addr;
    local_addr.ip = inet_network("172.17.0.2");
    local_addr.port = 5678; // 连接方进行connect连接的时候 内核中是随机分配一个可用的端口
    sock->established_local_addr = local_addr;
    sock->established_remote_addr = target_addr;
    int hashval = cal_hash(local_addr.ip, local_addr.port, target_addr.ip, target_addr.port);
    established_socks[hashval] = sock;
    // 这里也不能直接建立连接 需要经过三次握手
    // 实际在linux中 connect调用后 会进入一个while循环
    // 循环跳出的条件是socket的状态变为ESTABLISHED 表面看上去就是 正在连接中
    // 阻塞 而状态的改变在别的地方进行 在我们这就是tju_handle_packet

    // 调用isn生成初始化isn
    char *msg = create_packet_buf(sock->established_local_addr.port, target_addr.port, 1, 0, DEFAULT_HEADER_LEN,
                                  DEFAULT_HEADER_LEN, SYN_FLAG_MASK, 1, 0, NULL, 0);
    sendToLayer3(msg, DEFAULT_HEADER_LEN);
    _debug_("client SYN sent!");
    sock->state = SYN_SENT;

    while (sock->state != ESTABLISHED)
        ;
    // 超时处理 todo
    return 0;
}

int tju_send(tju_tcp_t *sock, const void *buffer, int len)
{
    // 这里当然不能直接简单地调用sendToLayer3
    char *data = malloc(len);
    memcpy(data, buffer, len);

    char *msg;
    uint32_t seq = 464;
    uint16_t plen = DEFAULT_HEADER_LEN + len;

    msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, 0,
                            DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, data, len);
    sendToLayer3(msg, plen);
    
    return 0;
}

int tju_recv(tju_tcp_t *sock, void *buffer, int len)
{
    while (sock->received_len <= 0)
    {
        // 阻塞
    }

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
        ; // 加锁

    int read_len = 0;
    if (sock->received_len >= len)
    { // 从中读取len长度的数据
        read_len = len;
    }
    else
    {
        read_len = sock->received_len; // 读取sock->received_len长度的数据(全读出来)
    }

    memcpy(buffer, sock->received_buf, read_len);

    if (read_len < sock->received_len)
    { // 还剩下一些
        char *new_buf = malloc(sock->received_len - read_len);
        memcpy(new_buf, sock->received_buf + read_len, sock->received_len - read_len);
        free(sock->received_buf);
        sock->received_len -= read_len;
        sock->received_buf = new_buf;
    }
    else
    {
        free(sock->received_buf);
        sock->received_buf = NULL;
        sock->received_len = 0;
    }
    pthread_mutex_unlock(&(sock->recv_lock)); // 解锁

    return 0;
}

int tju_handle_packet(tju_tcp_t *sock, char *pkt)
{
    _debug_("tju_handle_packet");
    uint32_t data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;
    uint8_t flag = get_flags(pkt);
    uint32_t seq = get_seq(pkt);
    uint32_t ack = get_ack(pkt);
    uint16_t rwnd_pkt = get_advertised_window(pkt);
    uint16_t src_port = get_src(pkt);
    uint16_t dst_port = get_dst(pkt);
    tju_tcp_t *new_conn = NULL;

    // 把收到的数据放到接受缓冲区
    while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
        ; // 加锁

    if (sock->received_buf == NULL)
    {
        sock->received_buf = malloc(data_len);
    }
    else
    {
        sock->received_buf = realloc(sock->received_buf, sock->received_len + data_len);
    }
    memcpy(sock->received_buf + sock->received_len, pkt + DEFAULT_HEADER_LEN, data_len);
    sock->received_len += data_len;

    pthread_mutex_unlock(&(sock->recv_lock)); // 解锁

    switch (sock->state)
    {
    case LISTEN:
        if (flag == SYN_FLAG_MASK)
        {
            _debug_("server: SYN received!");

            pthread_mutex_lock(&(sock->state_lock));
            sock->state = SYN_RECV;
            pthread_mutex_unlock(&(sock->state_lock));

            char *pkt = create_packet_buf(dst_port, src_port, ack, seq + 1, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                                          SYN_FLAG_MASK | ACK_FLAG_MASK, 1, 0, NULL, 0);
            sendToLayer3(pkt, DEFAULT_HEADER_LEN);
        }
        break;
    case SYN_SENT:
        if (flag == SYN_FLAG_MASK | ACK_FLAG_MASK)
        {
            _debug_("client: SYN_ACK received!");
            char *pkt = create_packet_buf(dst_port, src_port, ack, seq + 1, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                                          ACK_FLAG_MASK, 1, 0, NULL, 0);
            sendToLayer3(pkt, DEFAULT_HEADER_LEN);

            pthread_mutex_lock(&(sock->state_lock));
            sock->state = ESTABLISHED;
            pthread_mutex_unlock(&(sock->state_lock));
        }
        break;
    case SYN_RECV:
        if (flag == ACK_FLAG_MASK)
        {
            _debug_("server: ACK received!");
            tju_tcp_t *new_conn = (tju_tcp_t *)malloc(sizeof(tju_tcp_t));
            memcpy(new_conn, sock, sizeof(tju_tcp_t));

            tju_sock_addr local_addr, remote_addr;

            remote_addr.ip = inet_network("172.17.0.2");
            remote_addr.port = src_port;

            local_addr.ip = sock->bind_addr.ip;
            local_addr.port = sock->bind_addr.port;

            new_conn->established_local_addr = local_addr;
            new_conn->established_remote_addr = remote_addr;

            pthread_mutex_lock(&(new_conn->state_lock));
            new_conn->state = ESTABLISHED;
            pthread_mutex_unlock(&(new_conn->state_lock));

            int hashval = cal_hash(local_addr.ip, local_addr.port, remote_addr.ip, remote_addr.port);
            established_socks[hashval] = new_conn;

            enqueue(&accept_queue, new_conn);
            sock->state = LISTEN;
        }
        break;

    case ESTABLISHED:
        if (flag == FIN_FLAG_MASK | ACK_FLAG_MASK)
        {
            _debug_("FIN received! sock state -> CLOSE_WAIT");
            char *pkt =
                create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, ack, seq + 1,
                                  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, 1, 0, NULL, 0);
            sendToLayer3(pkt, DEFAULT_HEADER_LEN);
            _debug_("ACK sent!");

            pthread_mutex_lock(&(sock->state_lock));
            sock->state = CLOSE_WAIT;
            pthread_mutex_unlock(&(sock->state_lock));

            // 如果服务器没有消息要发送，则关闭连接,如果发送缓冲区还有东西，则阻塞
            sleep(1);
            // 应用进程关闭
            pkt =
                create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, ack, seq + 1,
                                  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FIN_FLAG_MASK | ACK_FLAG_MASK, 1, 0, NULL, 0);
            sendToLayer3(pkt, DEFAULT_HEADER_LEN);
            _debug_("FIN sent! sock state -> LAST_ACK");
            pthread_mutex_lock(&(sock->state_lock));
            sock->state = LAST_ACK;
            pthread_mutex_unlock(&(sock->state_lock));
        }
        break;

    case FIN_WAIT_1:
        if (flag == ACK_FLAG_MASK)
        {
            _debug_("ACK received! sock state -> FIN_WAIT_2");

            pthread_mutex_lock(&(sock->state_lock));
            sock->state = FIN_WAIT_2;
            pthread_mutex_unlock(&(sock->state_lock));
        }
        else if (flag == FIN_FLAG_MASK | ACK_FLAG_MASK)
        {
            // 发ack
            _debug_("FIN received! sock state -> CLOSING");
            char *pkt =
                create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, ack, seq + 1,
                                  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, 1, 0, NULL, 0);
            sendToLayer3(pkt, DEFAULT_HEADER_LEN);

            pthread_mutex_lock(&(sock->state_lock));
            sock->state = CLOSING;
            pthread_mutex_unlock(&(sock->state_lock));
        }
        else if (flag == FIN_FLAG_MASK | ACK_FLAG_MASK)
        {
			// 发ack
			_debug_("client FINACK received! sock state -> TIME_WAIT");
            char *pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, ack,
                                          seq + 1, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, 1, 0, NULL, 0);
            sendToLayer3(pkt, DEFAULT_HEADER_LEN);
            
            sock->state = TIME_WAIT;
            pthread_mutex_unlock(&(sock->state_lock));

            sleep(2);

            sock->state = CLOSED;
        }
        break;

    case FIN_WAIT_2:
        if (flag == FIN_FLAG_MASK | ACK_FLAG_MASK)
        {
            _debug_("FIN received! sock state -> TIME_WAIT");
            pthread_mutex_lock(&(sock->state_lock));
            sock->state = TIME_WAIT;
            pthread_mutex_unlock(&(sock->state_lock));

            char *pkt =
                create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, ack, seq + 1,
                                  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, 1, 0, NULL, 0);
            sendToLayer3(pkt, DEFAULT_HEADER_LEN);
            _debug_("ACK sent!");

            // 这里不清楚在等什么东西，状态转换图上有，但是还没看懂，就直接closed好了
            _debug_("sock state -> CLOSED");
            pthread_mutex_lock(&(sock->state_lock));
            sock->state = CLOSED;
            pthread_mutex_unlock(&(sock->state_lock));
        }
        break;

    case LAST_ACK:
        if (flag == ACK_FLAG_MASK)
        {
            _debug_("ACK received! sock state -> CLOSED");
            pthread_mutex_lock(&(sock->state_lock));
            sock->state = CLOSED;
            pthread_mutex_unlock(&(sock->state_lock));
        }
        break;
    case CLOSING:
        if (flag == ACK_FLAG_MASK)
        {
            _debug_("ACK received! sock state -> TIME_WAIT");
            pthread_mutex_lock(&(sock->state_lock));
            sock->state = TIME_WAIT;
            pthread_mutex_unlock(&(sock->state_lock));

            pthread_mutex_lock(&(sock->state_lock));
            sock->state = CLOSED;
            pthread_mutex_unlock(&(sock->state_lock));
        }
        break;
    }

    return 0;
}

int tju_close(tju_tcp_t *sock)
{
    // 检查收发缓冲区

    // 发送FIN报文

    char *pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, 1, 1 + 1,
                                  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FIN_FLAG_MASK | ACK_FLAG_MASK, 1, 0, NULL, 0);
    sendToLayer3(pkt, DEFAULT_HEADER_LEN);

    pthread_mutex_lock(&(sock->state_lock));
    sock->state = FIN_WAIT_1;
    pthread_mutex_unlock(&(sock->state_lock));

    _debug_("FIN sent! sock state -> FIN_WAIT_1");

    while (sock->state != CLOSED)
        ;
    _debug_("sock state -> CLOSED");
    return 0;
}