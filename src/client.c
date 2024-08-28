#include "tju_tcp.h"
#include <string.h>


int main(int argc, char **argv) {
    // 开启仿真环境 
    startSimulation();

    tju_tcp_t* my_socket = tju_socket();
    _info_("client state %s", STATE_TO_STRING(my_socket->state));
    
    tju_sock_addr target_addr;
    target_addr.ip = inet_network("10.0.0.1");
    target_addr.port = 1234;

    tju_connect(my_socket, target_addr);
    _info_("client state %s", STATE_TO_STRING(my_socket->state));
    uint32_t conn_ip;
    uint16_t conn_port;

    conn_ip = my_socket->established_local_addr.ip;
    conn_port = my_socket->established_local_addr.port;
    _info_("client established_local_addr ip:%s port:%d", intToIp(conn_ip), conn_port);

    conn_ip = my_socket->established_remote_addr.ip;
    conn_port = my_socket->established_remote_addr.port;
    _info_("client established_remote_addr ip:%s port:%d", intToIp(conn_ip), conn_port);

    sleep(3);

    tju_send(my_socket, "hello world", 12);
    tju_send(my_socket, "hello tju", 10);

    char buf[2021];
    tju_recv(my_socket, (void*)buf, 12);
    _msg_("recv: %s", buf);

    tju_recv(my_socket, (void*)buf, 10);
    _msg_("recv: %s", buf);

    tju_close(my_socket);

    while(my_socket->state != CLOSED);
    _debug_("test");
    return EXIT_SUCCESS;
}
