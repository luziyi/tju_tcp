#include "tju_tcp.h"
#include <string.h>

int main(int argc, char **argv) {
    // 开启仿真环境 
    startSimulation();

    tju_tcp_t* my_server = tju_socket();
    _info_("server state: %s", STATE_TO_STRING(my_server->state));
    
    tju_sock_addr bind_addr;
    bind_addr.ip = inet_network("10.0.0.1");
    bind_addr.port = 1234;

    tju_bind(my_server, bind_addr);

    tju_listen(my_server);
    _info_("server state: %s", STATE_TO_STRING(my_server->state));

    tju_tcp_t* new_conn = tju_accept(my_server);
    _info_("new connection state: %s", STATE_TO_STRING(new_conn->state));      

    uint32_t conn_ip;
    uint16_t conn_port;

    conn_ip = new_conn->established_local_addr.ip;
    conn_port = new_conn->established_local_addr.port;
    _info_("server new connection local_addr ip:%s port:%d", intToIp(conn_ip), conn_port);

    conn_ip = new_conn->established_remote_addr.ip;
    conn_port = new_conn->established_remote_addr.port;
    _info_("server new connection remote_addr ip:%s port:%d", intToIp(conn_ip), conn_port);

    sleep(3);
    
    tju_send(new_conn, "hello world", 12);
    tju_send(new_conn, "hello tju", 10);

    char buf[2021];
    tju_recv(new_conn, (void*)buf, 12);
    _msg_("recv: %s", buf);

    tju_recv(new_conn, (void*)buf, 10);
    _msg_("recv: %s", buf);

    while(new_conn->state != CLOSED);
    
    _debug_("test");
}
