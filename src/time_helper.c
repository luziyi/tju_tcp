#include "time_helper.h"

void timer_start(void *arg){
    tju_tcp_t *sock = (tju_tcp_t *)arg;
    while(TRUE){
        for(int i=0;i<MAX_PKG;i++){
            if(sock->resend_list->pkt[i]==NULL){
                continue;
            }
            if(getCurrentTime()-sock->resend_list->send_time[i]>1000000){
                pthread_mutex_lock(&(sock->resend_list->send_list));
                sock->resend_list->send_time[i]=getCurrentTime();
                pthread_mutex_unlock(&(sock->resend_list->send_list));
                sendToLayer3(sock->resend_list->pkt[i],get_plen(sock->resend_list->pkt[i]));
                log_event(sock->file,"RESEND","seq:%d",get_seq(sock->resend_list->pkt[i]));
            }
        }
    }
}