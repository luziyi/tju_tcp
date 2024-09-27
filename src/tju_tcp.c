#include "tju_tcp.h"
#include <sys/time.h>

#define MAX_SOCK 32

char *servertrace_file = "server.event.trace";
char *clienttrace_file = "client.event.trace";

int timeout_flag = 0;
int sending_base = 0;
int sending_nextseq = 0;

long getCurrentTime()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000000 + tv.tv_usec;
}

void trace_write(int EVENT, char *pkt, tju_tcp_t *sock)
{
	char trace[1024];
	long time = getCurrentTime();
	uint32_t seq, ack;
	uint8_t flag;
	double sample_rtt = sock->window.wnd_send->sample_rtt * 1.0 / 1000;
	double estmated_rtt = sock->window.wnd_send->estmated_rtt * 1.0 / 1000;
	double deviation_rtt = sock->window.wnd_send->deviation_rtt * 1.0 / 1000;
	double timeout_interval = sock->window.wnd_send->timeout_interval * 1.0 / 1000;
	char flags[32];
	if (pkt != NULL)
	{
		seq = get_seq(pkt), ack = get_ack(pkt);

		uint8_t flag = get_flags(pkt);
		if (flag == NO_FLAG)
			sprintf(flags, "NO_FLAG");
		else if (flag == SYN_FLAG_MASK)
			sprintf(flags, "SYN");
		else if (flag == ACK_FLAG_MASK)
			sprintf(flags, "ACK");
		else if (flag == FIN_FLAG_MASK)
			sprintf(flags, "FIN");
		else if (flag == (FIN_FLAG_MASK | ACK_FLAG_MASK))
			sprintf(flags, "FIN|ACK");
		else if (flag == (SYN_FLAG_MASK | ACK_FLAG_MASK))
			sprintf(flags, "SYN|ACK");
	}

	switch (EVENT)
	{
	case SENT:
		sprintf(trace, "[%ld] [SENT] [seq:%u ack:%u flag:%d length:%d]\n", time, seq, ack, get_flags(pkt), get_plen(pkt) - get_hlen(pkt));
		break;
	case RECV:
		sprintf(trace, "[%ld] [RECV] [seq:%u ack:%u flag:%d length:%d]\n", time, seq, ack, get_flags(pkt), get_plen(pkt) - get_hlen(pkt));
		break;
	case CWND:
		sprintf(trace, "[%ld] [CWND] [type:%d size:%d]\n", time, sock->window.wnd_send->status_type, sock->window.wnd_send->cwnd);
		break;
	case RWND:
		sprintf(trace, "[%ld] [RWND] [size:%d]\n", time, (sock->received_capacity - sock->received_len));
		break;
	case SWND:
		sprintf(trace, "[%ld] [SWND] [size:%d]\n", time, (sock->window.wnd_send->base + sock->window.wnd_send->window_size - sock->window.wnd_send->nextseq));
		break;
	case RTTS:
		// sprintf(trace, "[%ld] [RTTS] [SampleRTT:%ld EtimatedRTT:%ld DeviationRTT:%ld TimeoutInterval:%ld]\n",
		// 	time, sock->window.wnd_send->sample_rtt,
		// 	sock->window.wnd_send->estmated_rtt,
		// 	sock->window.wnd_send->deviation_rtt,
		// 	sock->window.wnd_send->timeout_interval);
		sprintf(trace, "[%ld] [RTTS] [SampleRTT:%f EtimatedRTT:%f DeviationRTT:%f TimeoutInterval:%f]\n",
				time, sample_rtt,
				estmated_rtt,
				deviation_rtt,
				timeout_interval);
		break;
	case DELV:
		sprintf(trace, "[%ld] [DELV] [seq:%d size:%d]\n", time, seq, get_plen(pkt) - get_hlen(pkt));
	default:
		break;
	}

	printf("%s\n", trace);
	FILE *fp = NULL;
	if (sock->established_local_addr.port == 1234 || (sock->bind_addr.port == 1234))
		fp = fopen(servertrace_file, "a+");
	else if (sock->established_local_addr.port == 5678)
		fp = fopen(clienttrace_file, "a+");
	if (fp != NULL)
	{
		fputs(trace, fp);
		fclose(fp);
	}
}

int resent_handing(tju_tcp_t *sock)
{
	if (sock->state == SYN_SENT)
	{
		uint32_t seq = 0;
		uint32_t ack = 0;
		uint16_t advertised_wnd = sock->received_capacity - sock->received_len;
		char *syn_pkt;
		syn_pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, ack, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, SYN_FLAG_MASK, advertised_wnd, 0, NULL, 0);
		sendToLayer3(syn_pkt, DEFAULT_HEADER_LEN);
		trace_write(SENT, syn_pkt, sock);
	}
	else if (sock->state == SYN_RECV)
	{
		uint32_t seq = 0, ack = 1;
		uint16_t advertised_wnd = sock->received_capacity - sock->received_len;
		char *syn_ack_pkt;
		syn_ack_pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, ack, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, SYN_FLAG_MASK | ACK_FLAG_MASK, advertised_wnd, 0, NULL, 0);
		sendToLayer3(syn_ack_pkt, DEFAULT_HEADER_LEN);
		trace_write(SENT, syn_ack_pkt, sock);
	}
	else if (sock->state == ESTABLISHED && sock->established_local_addr.port == 5678)
	{
		uint32_t seq = sock->window.wnd_send->nextseq;
		uint32_t ack = 0;
		// uint16_t advertised_wnd = sock->received_capacity - sock->received_len;
		char *zero_pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, ack, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, NO_FLAG, 0, 0, NULL, 0);
		sendToLayer3(zero_pkt, DEFAULT_HEADER_LEN);
		trace_write(SENT, zero_pkt, sock);
	}
	else if (sock->state == FIN_WAIT_1)
	{
		// 重传第一次挥手
		uint32_t seq = sock->window.wnd_send->nextseq, ack = sock->window.wnd_recv->expect_seq;
		// uint16_t advertised_wnd = sock->received_capacity - sock->received_len;
		char *fin_pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, ack, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FIN_FLAG_MASK, 0, 0, NULL, 0);
		sendToLayer3(fin_pkt, DEFAULT_HEADER_LEN);
		trace_write(SENT, fin_pkt, sock);
	}
	else if (sock->state == FIN_WAIT_2)
	{
		// 重传第四次挥手
		uint32_t seq = sock->window.wnd_send->nextseq, ack = sock->window.wnd_recv->expect_seq;
		// uint16_t advertised_wnd = sock->received_capacity - sock->received_len;
		char *ack_pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, ack, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, 0, 0, NULL, 0);
		sendToLayer3(ack_pkt, DEFAULT_HEADER_LEN);
		trace_write(SENT, ack_pkt, sock);
	}
	else if (sock->state == CLOSING)
	{
		// 重传第四次挥手
		uint32_t seq = sock->window.wnd_send->nextseq, ack = sock->window.wnd_recv->expect_seq;
		// uint16_t advertised_wnd = sock->received_capacity - sock->received_len;
		char *ack_pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, ack, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, 0, 0, NULL, 0);
		sendToLayer3(ack_pkt, DEFAULT_HEADER_LEN);
		trace_write(SENT, ack_pkt, sock);
	}
	else if (sock->state == TIME_WAIT)
	{
		// 重传第四次挥手
		uint32_t seq = sock->window.wnd_send->nextseq, ack = sock->window.wnd_recv->expect_seq;
		// uint16_t advertised_wnd = sock->received_capacity - sock->received_len;
		char *ack_pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, ack, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, 0, 0, NULL, 0);
		sendToLayer3(ack_pkt, DEFAULT_HEADER_LEN);
		trace_write(SENT, ack_pkt, sock);
	}
	else if (sock->state == CLOSE_WAIT)
	{
		// 重传第二次挥手
		uint32_t seq = sock->window.wnd_send->nextseq, ack = sock->window.wnd_recv->expect_seq;
		// uint16_t advertised_wnd = sock->received_capacity - sock->received_len;
		char *ack_pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, ack, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, 0, 0, NULL, 0);
		sendToLayer3(ack_pkt, DEFAULT_HEADER_LEN);
		trace_write(SENT, ack_pkt, sock);
	}
	else if (sock->state == LAST_ACK)
	{
		// 重传第三次挥手
		uint32_t seq = sock->window.wnd_send->nextseq, ack = sock->window.wnd_recv->expect_seq;
		// uint16_t advertised_wnd = sock->received_capacity - sock->received_len;
		char *fin_ack_pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, ack, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FIN_FLAG_MASK | ACK_FLAG_MASK, 0, 0, NULL, 0);
		sendToLayer3(fin_ack_pkt, DEFAULT_HEADER_LEN);
		trace_write(SENT, fin_ack_pkt, sock);
	}

	return 0;
}

void *timeout_thread(void *arg)
{
	tju_tcp_t *sock = (tju_tcp_t *)arg;
	while (TRUE)
	{
		if (sock->htimer.timer_state == TRUE)
		{
			sock->htimer.cur_time = getCurrentTime();
			long cost_time = sock->htimer.cur_time - sock->htimer.start_time;

			if (cost_time > sock->window.wnd_send->timeout_interval)
			{
				sock->window.wnd_send->timeout_interval = 2 * sock->window.wnd_send->timeout_interval;
				sock->htimer.start_time = getCurrentTime();
				printf("[timeout] cost time: %ld\n", cost_time);
				printf("[timeout] current base: %d\tnextseq: %d\n", sock->window.wnd_send->base, sock->window.wnd_send->nextseq);

				printf("[timeout] 超时重传.\n");
				printf("[timeout] sock状态: %d\n", sock->state);
				resent_handing(sock);
			}
		}
		sleep(0.1);
	}
}

void start_timer(tju_tcp_t *sock)
{
	sock->timer.timer_state = TRUE;
	timeout_flag = 0;
	sock->timer.start_time = getCurrentTime();
	gettimeofday(&sock->window.wnd_send->send_time, NULL);
}

void stop_timer(tju_tcp_t *sock)
{
	sock->timer.timer_state = FALSE;
}

void handle_rto(tju_tcp_t *sock)
{
	struct timeval now_time;
	gettimeofday(&now_time, NULL);
	uint32_t sample_rtt = (now_time.tv_sec - sock->window.wnd_send->send_time.tv_sec) * 1000000 + now_time.tv_usec - sock->window.wnd_send->send_time.tv_usec;
	// if (sample_rtt < 6000)
	// 	return;
	// if (sock->window.wnd_send->timeout_interval % 15000 == 0) {
	// 	sock->window.wnd_send->estmated_rtt = sample_rtt;
	// 	sock->window.wnd_send->deviation_rtt = sample_rtt / 2;
	// 	uint32_t temp = (4 * sock->window.wnd_send->deviation_rtt > 1000) ? 4 * sock->window.wnd_send->deviation_rtt : 1000;
	// 	sock->window.wnd_send->timeout_interval = sock->window.wnd_send->estmated_rtt + temp;
	// }
	// else {
	// 	sock->window.wnd_send->deviation_rtt = (int)((double)(sock->window.wnd_send->deviation_rtt) * 3.0 / 4.0 + (double)(abs(sock->window.wnd_send->estmated_rtt - sample_rtt)) / 4.0);
	// 	sock->window.wnd_send->estmated_rtt = (int)((double)(sock->window.wnd_send->estmated_rtt) * 7.0 / 8.0 + (double)(sample_rtt) / 8.0);
	// 	uint32_t temp = (4 * sock->window.wnd_send->deviation_rtt > 1000) ? 4 * sock->window.wnd_send->deviation_rtt : 1000;
	// 	sock->window.wnd_send->timeout_interval = sock->window.wnd_send->estmated_rtt + temp;
	// }
	sock->window.wnd_send->sample_rtt = sample_rtt;
	long dvalue = sock->window.wnd_send->sample_rtt - sock->window.wnd_send->estmated_rtt;
	sock->window.wnd_send->deviation_rtt = (1 - BETA) * sock->window.wnd_send->deviation_rtt + BETA * ((dvalue > 0) ? dvalue : (-dvalue));
	sock->window.wnd_send->estmated_rtt = (1 - ALPHA) * sock->window.wnd_send->estmated_rtt + ALPHA * sock->window.wnd_send->sample_rtt;
	// Set the maximum and minimum values for RTO
	long RTO = sock->window.wnd_send->estmated_rtt + 4 * sock->window.wnd_send->deviation_rtt;
	// RTO = (RTO < 1000000) ? 1000000 : RTO;
	RTO = (RTO > 15000000) ? 15000000 : RTO;
	sock->window.wnd_send->timeout_interval = RTO;
	trace_write(RTTS, NULL, sock);
}

void *time_thread(void *arg)
{
	tju_tcp_t *sock = (tju_tcp_t *)arg;

	while (TRUE)
	{
		if (sock->timer.timer_state == TRUE)
		{
			struct timeval send_time = sock->window.wnd_send->send_time;
			struct timeval now_time;
			gettimeofday(&now_time, NULL);
			long cur_time = getCurrentTime();

			// if ((now_time.tv_sec - send_time.tv_sec) * 1000000 + now_time.tv_usec - send_time.tv_usec >= sock->window.wnd_send->timeout_interval) {
			if (cur_time - sock->timer.start_time >= sock->window.wnd_send->timeout_interval)
			{
				timeout_flag = 1;
				printf("[timeout] cost time:%ld\ttimeout:%ld\n", (now_time.tv_sec - send_time.tv_sec) * 1000000 + now_time.tv_usec - send_time.tv_usec, sock->window.wnd_send->timeout_interval);
				sock->window.wnd_send->timeout_interval *= 2;
				stop_timer(sock);
			}
		}
	}
}

void send_packet(tju_tcp_t *sock)
{
	// Already sent but not acknowledged
	int sent_len = sock->window.wnd_send->nextseq - sock->window.wnd_send->base;
	// Remaining space in the sending window
	int window_left = sock->window.wnd_send->base + sock->window.wnd_send->window_size - sock->window.wnd_send->nextseq;
	// Remaining space in the sending buffer (including sent but not acknowledged and unsent)
	// dlen is the unsent data in the sending buffer
	int dlen = sock->sending_len - sock->window.wnd_send->nextseq;

	if (dlen > 0 && window_left > 0)
	{
		int packet_size;

		dlen = (dlen < window_left) ? dlen : window_left;
		dlen = (dlen < sock->window.wnd_send->rwnd) ? dlen : sock->window.wnd_send->rwnd;
		dlen = (dlen < sock->window.wnd_send->cwnd) ? dlen : sock->window.wnd_send->cwnd;
		dlen = (dlen < MAX_DLEN) ? dlen : MAX_DLEN;

		char *data = malloc(dlen);
		while (pthread_mutex_lock(&(sock->send_lock)) != 0)
			;
		int offset = sock->window.wnd_send->nextseq - sock->window.wnd_send->base;
		memcpy(data, sock->sending_buf + sock->window.wnd_send->nextseq, dlen);
		// memcpy(data, sock->sending_buf+offset, dlen);
		pthread_mutex_unlock(&(sock->send_lock));
		char *msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, sock->window.wnd_send->nextseq, 0,
									  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN + dlen, NO_FLAG, TCP_RECVWN_SIZE - sock->received_len, 0, data, dlen);
		sendToLayer3(msg, DEFAULT_HEADER_LEN + dlen);
		trace_write(SENT, msg, sock);
		// printf("[send packet] current timer state: %d\n", sock->timer.timer_state);
		if (sock->timer.timer_state == FALSE)
			start_timer(sock);
		// printf("[send packet] current timer state: %d\n", sock->timer.timer_state);
		// printf("[send packet] current send time:%ld\n", sock->window.wnd_send->send_time);
		packet_size = dlen;
		printf("[%ld] thread send data packet len %d and seq %d\n", getCurrentTime(), packet_size, sock->window.wnd_send->nextseq);
		sending_nextseq += dlen;
		sock->window.wnd_send->nextseq += dlen;
		trace_write(SWND, NULL, sock);
	}
	else if (window_left == 0 && sock->window.wnd_send->rwnd == 0)
	{
		if (sock->htimer.timer_state == TRUE)
		{
			return;
		}
		char *msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, sock->window.wnd_send->nextseq, 0,
									  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, NO_FLAG, TCP_RECVWN_SIZE - sock->received_len, 0, 0, 0);
		sendToLayer3(msg, DEFAULT_HEADER_LEN);
		sock->htimer.start_time = getCurrentTime();
		sock->htimer.timer_state = TRUE;
	}
}

void retransmit_packet(tju_tcp_t *sock)
{
	int dlen = sock->window.wnd_send->nextseq - sock->window.wnd_send->base;

	int packet_size;
	dlen = (dlen < MAX_DLEN) ? dlen : MAX_DLEN;

	if (dlen > 0)
	{
		if (sock->window.wnd_send->ack_cnt != 3)
		{
			handle_loss_ack(sock);
			trace_write(CWND, NULL, sock);
		}
		packet_size = dlen;

		char *data = malloc(dlen);
		while (pthread_mutex_lock(&(sock->send_lock)) != 0)
			;
		memcpy(data, sock->sending_buf + sock->window.wnd_send->base, dlen);
		// memcpy(data, sock->sending_buf, dlen);
		pthread_mutex_unlock(&(sock->send_lock));
		char *msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, sock->window.wnd_send->base, 0,
									  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN + dlen, NO_FLAG, TCP_RECVWN_SIZE - sock->received_len, 0, data, MAX_DLEN);
		sendToLayer3(msg, DEFAULT_HEADER_LEN + dlen);
		trace_write(SENT, msg, sock);
		if (sock->window.wnd_send->ack_cnt != 3)
		{
			start_timer(sock);
		}
		if (sock->window.wnd_send->ack_cnt == 3)
			printf("[%ld] 3-ACK retansmit data packet len %d and seq %d\n", getCurrentTime(), packet_size, sock->window.wnd_send->base);
		else
			printf("[%ld] timeout retansmit data packet len %d and seq %d\n", getCurrentTime(), packet_size, sock->window.wnd_send->base);

		while (pthread_mutex_lock(&(sock->window.wnd_send->ack_cnt_lock)) != 0)
			;
		sock->window.wnd_send->ack_cnt = 0;
		pthread_mutex_unlock(&(sock->window.wnd_send->ack_cnt_lock));
	}
}

void *sender_thread(void *arg)
{
	tju_tcp_t *sock = (tju_tcp_t *)arg;

	while (1)
	{
		while (sock->sending_len <= 0)
			;
		if (timeout_flag == TRUE)
		{
			// handle_loss_ack(sock);
			// trace_write(CWND, NULL, sock);
			retransmit_packet(sock);
		}
		else
		{
			send_packet(sock);
		}
	}
}

void send_ack(tju_tcp_t *sock)
{
	char *msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, 0, sock->window.wnd_recv->expect_seq,
								  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, TCP_RECVWN_SIZE - sock->window.wnd_recv->buffered_size, 0, NULL, 0);
	sendToLayer3(msg, DEFAULT_HEADER_LEN);
	trace_write(SENT, msg, sock);
	printf("[%ld] send ack packet acked %d\n", getCurrentTime(), sock->window.wnd_recv->expect_seq);
}

// 拥塞控制相关

void handle_loss_ack(tju_tcp_t *sock)
{
	// 处理超时重传的情况
	sock->window.wnd_send->ssthresh = (sock->window.wnd_send->cwnd + 1) / 2;
	sock->window.wnd_send->cwnd = MSS;

	if (sock->window.wnd_send->congestion_status == SLOW_START)
	{
		if (sock->window.wnd_send->cwnd >= sock->window.wnd_send->ssthresh)
		{
			sock->window.wnd_send->congestion_status = CONGESTION_AVOIDANCE;
		}
	}
	else
	{
		sock->window.wnd_send->congestion_status = SLOW_START;
	}
	sock->window.wnd_send->status_type = timeout;
	sock->window.wnd_send->cwnd = (sock->window.wnd_send->cwnd < MSS) ? MSS : sock->window.wnd_send->cwnd;
	printf("[CONGESTION STATE]cwnd:%d STATUS:%d ssthresh:%d\n", sock->window.wnd_send->cwnd, sock->window.wnd_send->congestion_status, sock->window.wnd_send->ssthresh);
}

void handle_valid_ack(tju_tcp_t *sock)
{
	if (sock->window.wnd_send->congestion_status == SLOW_START)
	{
		sock->window.wnd_send->cwnd *= 2;
		if (sock->window.wnd_send->cwnd > sock->window.wnd_send->ssthresh)
		{
			sock->window.wnd_send->congestion_status = CONGESTION_AVOIDANCE;
		}
		sock->window.wnd_send->status_type = SLOW_START;
	}
	else if (sock->window.wnd_send->congestion_status == CONGESTION_AVOIDANCE)
	{
		sock->window.wnd_send->cwnd = sock->window.wnd_send->cwnd + (int)(MSS * 1);
		sock->window.wnd_send->status_type = CONGESTION_AVOIDANCE;
	}
	else if (sock->window.wnd_send->congestion_status == FAST_RECOVERY)
	{
		sock->window.wnd_send->cwnd = sock->window.wnd_send->ssthresh;
		sock->window.wnd_send->congestion_status = CONGESTION_AVOIDANCE;
		sock->window.wnd_send->status_type = CONGESTION_AVOIDANCE;
	}
	else
	{
		printf("handle_success_ack 出现未定义行为\n");
	}
	sock->window.wnd_send->cwnd = (sock->window.wnd_send->cwnd < MSS) ? MSS : sock->window.wnd_send->cwnd;
	printf("[CONGESTION STATE]cwnd:%d STATUS:%d ssthresh:%d\n", sock->window.wnd_send->cwnd, sock->window.wnd_send->congestion_status, sock->window.wnd_send->ssthresh);
}

void handle_dup_ack(tju_tcp_t *sock)
{
	printf("[fast recovery] current dup cnt: %d\n", sock->window.wnd_send->ack_cnt);
	printf("[fast recovery] current status: %d\n", sock->window.wnd_send->congestion_status);
	if (sock->window.wnd_send->congestion_status == FAST_RECOVERY)
	{
		sock->window.wnd_send->cwnd += MSS;
		// sock->window.wnd_send->status_type = CONGESTION_AVOIDANCE;
	}
	else if ((sock->window.wnd_send->congestion_status == CONGESTION_AVOIDANCE || sock->window.wnd_send->congestion_status == SLOW_START) && sock->window.wnd_send->ack_cnt == 1)
	{
		sock->window.wnd_send->ssthresh = sock->window.wnd_send->cwnd / 2;
		sock->window.wnd_send->cwnd = sock->window.wnd_send->ssthresh + 3 * MSS;
		sock->window.wnd_send->congestion_status = FAST_RECOVERY;
		sock->window.wnd_send->status_type = FAST_RECOVERY;
	}
	else if ((sock->window.wnd_send->congestion_status == CONGESTION_AVOIDANCE || sock->window.wnd_send->congestion_status == SLOW_START) && sock->window.wnd_send->ack_cnt < 1)
	{
		return;
	}
	else
	{
		printf("不存在相应状态\n");
	}
	sock->window.wnd_send->status_type = FAST_RECOVERY;
	sock->window.wnd_send->cwnd = (sock->window.wnd_send->cwnd < MSS) ? MSS : sock->window.wnd_send->cwnd;
	printf("[CONGESTION STATE]cwnd:%d STATUS:%d ssthresh:%d\n", sock->window.wnd_send->cwnd, sock->window.wnd_send->congestion_status, sock->window.wnd_send->ssthresh);
	trace_write(CWND, NULL, sock);
}

/*
创建 TCP socket
初始化对应的结构体
设置初始状态为 CLOSED
*/
tju_tcp_t *tju_socket()
{
	tju_tcp_t *sock = (tju_tcp_t *)malloc(sizeof(tju_tcp_t));
	sock->state = CLOSED;

	pthread_mutex_init(&(sock->send_lock), NULL);
	sock->sending_buf = NULL;
	sock->sending_len = 0;
	sock->sending_capacity = TCP_SEND_BUFFER_SIZE;

	pthread_mutex_init(&(sock->recv_lock), NULL);
	sock->received_buf = NULL;
	sock->received_len = 0;
	sock->received_capacity = TCP_RECV_BUFFER_SIZE;

	if (pthread_cond_init(&sock->wait_cond, NULL) != 0)
	{
		perror("ERROR condition variable not set\n");
		exit(-1);
	}

	sock->window.wnd_send = (sender_window_t *)malloc(sizeof(sender_window_t));
	pthread_mutex_init(&(sock->window.wnd_send->ack_cnt_lock), NULL);
	sock->window.wnd_send->window_size = TCP_SEND_BUFFER_SIZE;
	sock->window.wnd_send->rwnd = MAX_DLEN;
	sock->window.wnd_send->base = 0;
	sock->window.wnd_send->nextseq = 0;
	sock->window.wnd_send->ack_cnt = 0;
	sock->window.wnd_send->estmated_rtt = 0;
	sock->window.wnd_send->sample_rtt = 0;
	sock->window.wnd_send->deviation_rtt = 0;
	sock->window.wnd_send->timeout_interval = 1000000;

	sock->window.wnd_recv = (receiver_window_t *)malloc(sizeof(receiver_window_t));
	sock->window.wnd_recv->expect_seq = 0;
	sock->window.wnd_recv->head = NULL;
	sock->window.wnd_recv->buffered_size = 0;
	sock->window.wnd_recv->buf_packet_cnt = 0;
	pthread_mutex_init(&(sock->window.wnd_recv->buf_queue_lock), NULL);

	sock->htimer.timer_state = FALSE;
	sock->timer.timer_state = FALSE;

	// 初始化拥塞控制相关
	sock->window.wnd_send->ssthresh = IW;
	sock->window.wnd_send->cwnd = MSS;
	sock->window.wnd_send->congestion_status = SLOW_START;

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
	tju_tcp_t *new_conn = NULL;

	printf("server waiting for connection\n");

	// 如果new_conn的创建过程放到了tju_handle_packet中 那么accept怎么拿到这个new_conn呢
	// 在linux中 每个listen socket都维护一个已经完成连接的socket队列
	// 每次调用accept 实际上就是取出这个队列中的一个元素
	// 队列为空,则阻塞

	while (esock_pointer == 0)
	{
		sleep(0.001);
	}
	printf("esock_pointer is not zero\n");
	new_conn = esock_queue[esock_pointer - 1];
	esock_pointer--;
	printf("connected\n");
	return new_conn;
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
	sock->established_remote_addr = target_addr;

	tju_sock_addr local_addr;
	local_addr.ip = inet_network(CLIENT_IP);
	local_addr.port = 5678; // 连接方进行connect连接的时候 内核中是随机分配一个可用的端口
	sock->established_local_addr = local_addr;

	// 这里也不能直接建立连接 需要经过三次握手
	// 实际在linux中 connect调用后 会进入一个while循环
	// 循环跳出的条件是socket的状态变为ESTABLISHED 表面看上去就是 正在连接中 阻塞
	// 而状态的改变在别的地方进行 在我们这就是tju_handle_packet
	// sock->state = ESTABLISHED;

	uint32_t seq = sock->window.wnd_send->nextseq, ack = sock->window.wnd_recv->expect_seq;
	char *syn_pkt;
	syn_pkt = create_packet_buf(local_addr.port, target_addr.port, seq, ack, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, SYN_FLAG_MASK, TCP_RECVWN_SIZE, 0, NULL, 0);
	// sock->window.wnd_send->nextseq += 1;
	sock->state = SYN_SENT;

	// 将建立了连接的socket放入内核 已建立连接哈希表中
	int hashval = cal_hash(local_addr.ip, local_addr.port, target_addr.ip, target_addr.port);
	established_socks[hashval] = sock;

	sendToLayer3(syn_pkt, DEFAULT_HEADER_LEN);
	trace_write(SENT, syn_pkt, sock);

	// 建立计时器以应对丢包等现象
	sock->htimer.timer_state = TRUE;
	// gettimeofday(&(sock->htimer.start_time), NULL);
	sock->htimer.start_time = getCurrentTime();
	pthread_t ththread_id = 1010;
	int timer_handing = pthread_create(&ththread_id, NULL, timeout_thread, (void *)(sock));
	if (timer_handing < 0)
	{
		printf("ERROR open thread");
		exit(-1);
	};

	struct timeval send_time;
	gettimeofday(&send_time, NULL);

	while (sock->state != ESTABLISHED)
	{
		// struct timeval now_time;
		// gettimeofday(&now_time, NULL);
		// long long timeinterval = (now_time.tv_sec - send_time.tv_sec) * 1000000 + (now_time.tv_usec - send_time.tv_usec);
		// if (timeinterval >= 15000) {
		// 	uint32_t seq = 0;
		// 	char* msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, 0,
		// 		DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, SYN_FLAG_MASK, 1, 0, NULL, 0);
		// 	sendToLayer3(msg, DEFAULT_HEADER_LEN);
		// 	trace_write(SENT, msg, sock);
		// 	printf("[%ld] [Timeout] (SYN_SENT) client send syn packet seq=%d ack=%d\n", getCurrentTime(), seq, 0);
		// 	gettimeofday(&send_time, NULL);
		// }
	}

	// 建立发送线程进行数据包的发送
	pthread_t sthread_id = 2001;
	int sender_client = pthread_create(&sthread_id, NULL, sender_thread, (void *)(sock));
	if (sender_client < 0)
	{
		printf("ERROR open thread");
		exit(-1);
	}
	printf("[client] sender pthread established!\n");

	// 建立计时器以应对丢包等现象
	// sock->timer.timer_state = TRUE;
	// gettimeofday(&(sock->timer.start_time), NULL);
	sock->timer.start_time = getCurrentTime();
	pthread_t tthread_id = 1020;
	int timer_client = pthread_create(&tthread_id, NULL, time_thread, (void *)(sock));
	if (timer_client < 0)
	{
		printf("ERROR open thread");
		exit(-1);
	};

	return 0;
}

int tju_send(tju_tcp_t *sock, const void *buffer, int len)
{
	// printf("start to send\n");
	while (pthread_mutex_lock(&(sock->send_lock)) != 0)
		; // 加锁
	if (sock->sending_len == 0)
	{
		sock->sending_buf = malloc(len);
		memcpy(sock->sending_buf, buffer, len);
		sock->sending_len = len;
	}
	else
	{
		sock->sending_buf = realloc(sock->sending_buf, len + sock->sending_len);
		memcpy(sock->sending_buf + sock->sending_len, buffer, len);
		sock->sending_len = len + sock->sending_len;
	}
	// trace_write(SWND, NULL, sock);
	pthread_mutex_unlock(&(sock->send_lock));
	return 0;
}

int tju_recv(tju_tcp_t *sock, void *buffer, int len)
{
	int len_read = 0;
	while (len > 0)
	{
		while (sock->received_len <= 0)
			;

		int read_len = 0;
		if (sock->received_len >= len)
		{
			// 从中读取len长度的数据
			read_len = len;
		}
		else
		{
			read_len = sock->received_len; // 读取sock->received_len长度的数据(全读出来)
		}
		while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
			; // 加锁
		memcpy(buffer + len_read, sock->received_buf, read_len);

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
		trace_write(RWND, NULL, sock);
		pthread_mutex_unlock(&(sock->recv_lock)); // 解锁
		len_read += read_len;
		len -= read_len;
	}

	return len_read;
}

int tju_handle_packet(tju_tcp_t *sock, char *pkt)
{
	printf("[handle packet] current timer state: %d\n", sock->timer.timer_state);
	printf("[handle packet] current state:%d\n", sock->state);
	uint8_t flag = get_flags(pkt);
	uint32_t ack = get_ack(pkt);
	uint32_t seq = get_seq(pkt);
	uint16_t plen = get_plen(pkt);
	uint16_t hlen = get_hlen(pkt);
	uint16_t data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;

	trace_write(RECV, pkt, sock);
	// printf("[handle packet] current state:%d\n", sock->state);

	switch (sock->state)
	{
	case LISTEN:
		if (flag == SYN_FLAG_MASK)
		{
			printf("[%ld] (LISTEN) server receive syn packet seq=%d ack=%d\n", getCurrentTime(), get_seq(pkt), get_ack(pkt));
			sock->state = SYN_RECV;
			// sock->window.wnd_recv->expect_seq = seq + 1;

			tju_tcp_t *new_conn = (tju_tcp_t *)malloc(sizeof(tju_tcp_t));
			memcpy(new_conn, sock, sizeof(tju_tcp_t));

			tju_sock_addr local_addr, remote_addr;

			remote_addr.ip = inet_network(CLIENT_IP); // 具体的IP地址
			remote_addr.port = get_src(pkt);		  // 端口

			local_addr.ip = sock->bind_addr.ip;		// 具体的IP地址
			local_addr.port = sock->bind_addr.port; // 端口

			new_conn->established_local_addr = local_addr;
			new_conn->established_remote_addr = remote_addr;

			int hashval = cal_hash(local_addr.ip, local_addr.port, remote_addr.ip, remote_addr.port);
			hesock_queue[hesock_pointer] = new_conn;
			hesock_pointer++;

			uint32_t seq = 0;
			char *msg = create_packet_buf(sock->bind_addr.port, remote_addr.port, seq, get_seq(pkt) + 1,
										  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, SYN_FLAG_MASK | ACK_FLAG_MASK, TCP_RECVWN_SIZE - sock->received_len, 0, NULL, 0);
			sendToLayer3(msg, DEFAULT_HEADER_LEN);
			trace_write(SENT, msg, sock);
			printf("[%ld] (SYN_RECV) server send synack packet seq=%d ack=%d\n", getCurrentTime(), seq, get_seq(pkt) + 1);

			// sock->window.wnd_send->nextseq += 1;
			// new_conn->window.wnd_send->nextseq += 1;

			// 建立server端的计时器
			new_conn->htimer.timer_state = TRUE;
			new_conn->htimer.start_time = getCurrentTime();
			pthread_t thread_id = 1011;
			int timer_server = pthread_create(&thread_id, NULL, timeout_thread, (void *)(new_conn));
			if (timer_server < 0)
			{
				printf("ERROR open thread");
				exit(-1);
			}
		}
		break;
	case SYN_SENT:
		if (flag == (SYN_FLAG_MASK | ACK_FLAG_MASK))
		{
			sock->htimer.timer_state = FALSE;

			sock->state = ESTABLISHED;
			// sock->window.wnd_recv->expect_seq = seq + 1;
			// sock->window.wnd_send->base = ack;

			sock->window.wnd_send->rwnd = get_advertised_window(pkt);

			printf("[%ld] (SYN_SENT) client receive synack packet seq=%d ack=%d\n", getCurrentTime(), get_seq(pkt), get_ack(pkt));
			uint32_t seq = get_ack(pkt);
			char *ack_pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, get_seq(pkt) + 1,
											  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, TCP_RECVWN_SIZE - sock->received_len, 0, NULL, 0);
			sendToLayer3(ack_pkt, DEFAULT_HEADER_LEN);
			trace_write(SENT, ack_pkt, sock);
			sock->htimer.start_time = getCurrentTime();
			// sock->window.wnd_send->nextseq += 1;

			printf("[%ld] (ESTABLISHED) client send ack packet seq=%d ack=%d\n", getCurrentTime(), seq, get_seq(pkt) + 1);
		}
		break;
	case SYN_RECV:
		if (flag == ACK_FLAG_MASK)
		{
			printf("[%ld] (SYN_RECV) server receive ack packet seq=%d ack=%d\n", getCurrentTime(), get_seq(pkt), get_ack(pkt));
			sock->htimer.timer_state = FALSE;
			sock->state = LISTEN;
			tju_sock_addr local_addr = sock->established_local_addr;
			tju_sock_addr remote_addr = sock->established_remote_addr;

			tju_tcp_t *est_conn = hesock_queue[hesock_pointer - 1];
			est_conn->htimer.timer_state = FALSE;
			// est_conn->window.wnd_recv->expect_seq += 1;
			// est_conn->window.wnd_send->base = ack;

			hesock_pointer--;
			hesock_queue[hesock_pointer] = NULL;
			est_conn->state = ESTABLISHED;
			esock_queue[esock_pointer] = est_conn;
			esock_pointer++;

			int hashval = cal_hash(est_conn->established_local_addr.ip, est_conn->established_local_addr.port, est_conn->established_remote_addr.ip, est_conn->established_remote_addr.port);
			established_socks[hashval] = est_conn;
			int hashval1 = cal_hash(local_addr.ip, local_addr.port, 0, 0);
			listen_socks[hashval1] = NULL;
			// sock->state = ESTABLISHED;
			// printf("esock_queue[esock_pointer - 1]:%d\n", esock_queue[esock_pointer - 1]);

			// est_conn->htimer.timer_state = FALSE;
			// est_conn->window.wnd_send->estmated_rtt = getCurrentTime() - sock->htimer.start_time;
			// est_conn->window.wnd_send->sample_rtt = getCurrentTime() - sock->htimer.start_time;
			// trace_write(RTTS, pkt, est_conn);
			// est_conn->htimer.start_time = getCurrentTime();
			// est_conn->window.wnd_send->rwnd = get_advertised_window(pkt);
		}
		break;
	case ESTABLISHED:
		if (flag == (SYN_FLAG_MASK | ACK_FLAG_MASK))
		{
			uint32_t seq = get_ack(pkt);
			char *msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, get_seq(pkt) + 1,
										  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, TCP_RECVWN_SIZE - sock->received_len, 0, NULL, 0);
			sendToLayer3(msg, DEFAULT_HEADER_LEN);
			trace_write(SENT, msg, sock);
			printf("[%ld] [Timeout] (ESTABLISHED) client send ack packet seq=%d ack=%d\n", getCurrentTime(), seq, get_seq(pkt) + 1);
		}
		else if (flag == ACK_FLAG_MASK)
		{
			// handle_success_ack(sock);
			// 客户端接收到ack包
			sock->window.wnd_send->rwnd = get_advertised_window(pkt);
			if (sock->window.wnd_send->rwnd > 0)
			{
				sock->htimer.timer_state = FALSE;
			}
			if (ack > sock->window.wnd_send->base && ack <= sock->window.wnd_send->nextseq)
			{
				printf("[%ld] receive data ack packet acked %d\n", getCurrentTime(), ack);
				handle_rto(sock);
				if (ack == sock->window.wnd_send->nextseq)
				{
					stop_timer(sock);
				}
				else
				{
					start_timer(sock);
				}

				// int dlen = ack - sock->window.wnd_send->base;
				// while (pthread_mutex_lock(&(sock->send_lock)) != 0)
				// 	;
				// if (dlen < sock->sending_len) { // 还剩下一些
				//     char* new_buf = malloc(sock->sending_len - dlen);
				//     memcpy(new_buf, sock->sending_buf + dlen, sock->sending_len - dlen);
				//     free(sock->sending_buf);
				//     sock->sending_len -= dlen;
				//     sock->sending_buf = new_buf;
				// }
				// else {
				//     free(sock->sending_buf);
				//     sock->sending_buf = NULL;
				//     sock->sending_len = 0;
				// }
				// pthread_mutex_unlock(&(sock->send_lock));

				while (pthread_mutex_lock(&(sock->window.wnd_send->ack_cnt_lock)) != 0)
					;
				sock->window.wnd_send->ack_cnt = 0;
				pthread_mutex_unlock(&(sock->window.wnd_send->ack_cnt_lock));
				sending_base = ack;
				sock->window.wnd_send->base = ack;
				trace_write(SWND, pkt, sock);
				handle_valid_ack(sock);
				trace_write(CWND, NULL, sock);
			}
			else if (ack == sock->window.wnd_send->base)
			{
				printf("[%ld] receive data ack packet acked %d\n", getCurrentTime(), ack);
				// ack号
				while (pthread_mutex_lock(&(sock->window.wnd_send->ack_cnt_lock)) != 0)
					;
				sock->window.wnd_send->ack_cnt++;
				pthread_mutex_unlock(&(sock->window.wnd_send->ack_cnt_lock));
				handle_dup_ack(sock);
				if (sock->window.wnd_send->ack_cnt == 3)
				{
					retransmit_packet(sock);
				}
				// handle_dup_ack(sock);
				// trace_write(CWND, NULL, sock);
			}
			else
			{
				// 丢弃
			}
		}
		else if (flag == NO_FLAG)
		{
			if (get_advertised_window(pkt) == 0)
			{
				send_ack(sock);
				break;
			}
			// 服务端接收数据包
			printf("[%ld] receive data packet len %d and seq %d\n", getCurrentTime(), (plen - hlen), seq);
			uint16_t datalen = plen - hlen;
			// 数据包的序号等于接收端期望接收到的序号
			if (seq == sock->window.wnd_recv->expect_seq)
			{
				char *data = NULL;
				if (sock->window.wnd_recv->head != NULL)
				{
					pthread_mutex_lock(&sock->window.wnd_recv->buf_queue_lock);
					uint32_t nextseq = seq + datalen;
					if (nextseq < sock->window.wnd_recv->head->seq)
					{
						data = malloc(datalen);
						memcpy(data, pkt + hlen, datalen);
					}
					else
					{
						if (nextseq > sock->window.wnd_recv->head->seq)
						{
							data = malloc(sock->window.wnd_recv->head->seq - seq);
							memcpy(data, pkt + hlen, sock->window.wnd_recv->head->seq - seq);
							nextseq = sock->window.wnd_recv->head->seq;
							datalen = sock->window.wnd_recv->head->seq - seq;
						}
						else
						{
							data = malloc(datalen);
							memcpy(data, pkt + hlen, datalen);
						}
						received_packet_t *p = sock->window.wnd_recv->head;
						while (p != NULL)
						{
							if (p->seq == nextseq)
							{
								data = realloc(data, datalen + p->len);
								memcpy(data + datalen, p->data, p->len);
								datalen += p->len;
								nextseq += p->len;
								received_packet_t *q = p;
								sock->window.wnd_recv->buffered_size -= p->len;
								sock->window.wnd_recv->buf_packet_cnt -= 1;
								p = p->next;
								sock->window.wnd_recv->head = p;
								free(q);
							}
							else
								break;
						}
						p = NULL;
					}
					pthread_mutex_unlock(&sock->window.wnd_recv->buf_queue_lock);
				}
				else
				{
					// 接收队列为空
					data = malloc(datalen);
					memcpy(data, pkt + hlen, datalen);
				}

				while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
					;

				if (sock->received_len == 0)
				{
					sock->received_buf = malloc(datalen);
					memcpy(sock->received_buf, data, datalen);
					sock->received_len = datalen;
				}
				else
				{
					sock->received_buf = realloc(sock->received_buf, datalen + sock->received_len);
					memcpy(sock->received_buf + sock->received_len, data, datalen);
					sock->received_len += datalen;
				}
				trace_write(RWND, NULL, sock);
				trace_write(DELV, pkt, sock);
				pthread_mutex_unlock(&(sock->recv_lock));
				free(data);

				sock->window.wnd_recv->expect_seq += datalen;
				send_ack(sock);
			}
			else
			{
				// 数据包的序号大于接收端期望接收到的序号
				if (seq > sock->window.wnd_recv->expect_seq)
				{
					// 链表操作
					pthread_mutex_lock(&sock->window.wnd_recv->buf_queue_lock);
					if (sock->window.wnd_recv->head == NULL)
					{
						sock->window.wnd_recv->head = (received_packet_t *)malloc(sizeof(received_packet_t));
						sock->window.wnd_recv->head->seq = seq;
						sock->window.wnd_recv->head->nextseq = seq + datalen;
						sock->window.wnd_recv->head->len = datalen;
						sock->window.wnd_recv->head->data = malloc(datalen);
						memcpy(sock->window.wnd_recv->head->data, pkt + hlen, datalen);
						sock->window.wnd_recv->head->next = NULL;
						sock->window.wnd_recv->buffered_size += datalen;
						sock->window.wnd_recv->buf_packet_cnt = 1;
						// trace_write(SWND, pkt, sock);
						printf("[%ld] recv queue add the first packet\n", getCurrentTime());
					}
					else
					{
						received_packet_t *new_packet = (received_packet_t *)malloc(sizeof(received_packet_t));
						new_packet->seq = seq;
						new_packet->nextseq = seq + datalen;
						new_packet->len = datalen;
						new_packet->data = malloc(datalen);
						memcpy(new_packet->data, pkt + hlen, datalen);
						// trace_write(SWND, pkt, sock);

						received_packet_t *p = sock->window.wnd_recv->head;
						received_packet_t *q = p->next;

						if (seq <= p->seq)
						{
							sock->window.wnd_recv->head = new_packet;
							new_packet->next = p;
						}
						else if (q == NULL)
						{
							p->next = new_packet;
							new_packet->next = NULL;
						}
						else
						{
							while (q != NULL)
							{
								if (seq > p->seq && seq < q->seq)
								{
									p->next = new_packet;
									new_packet->next = q;
									break;
								}
								else
								{
									p = p->next;
									q = q->next;
								}
							}
							if (q == NULL)
							{
								p->next = new_packet;
								new_packet->next = NULL;
							}
						}
						p = NULL;
						q = NULL;

						sock->window.wnd_recv->buffered_size += datalen;
						sock->window.wnd_recv->buf_packet_cnt += 1;

						printf("[%ld] recv queue add a packet\n", getCurrentTime());
					}
					pthread_mutex_unlock(&sock->window.wnd_recv->buf_queue_lock);
				}
				send_ack(sock);
			}
		}
		else if (flag == FIN_FLAG_MASK)
		{
			// server端接收到client端发送的FIN
			sock->state = CLOSE_WAIT;
			sock->window.wnd_recv->expect_seq += 1;
			sock->window.wnd_send->base = ack;

			// 发送第二次挥手
			uint32_t seq2 = sock->window.wnd_send->nextseq, ack2 = seq + 1;
			int adv_window = sock->received_capacity - sock->received_len;
			char *ack_pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq2, ack2,
											  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, adv_window, 0, NULL, 0);
			sendToLayer3(ack_pkt, DEFAULT_HEADER_LEN);
			trace_write(SENT, ack_pkt, sock);
			sock->window.wnd_send->nextseq += 1;

			while (sock->received_len != 0)
			{
			}
			sock->state = LAST_ACK;
			// 发送第三次挥手
			uint32_t seq3 = sock->window.wnd_send->nextseq, ack3 = seq + 1;
			adv_window = sock->received_capacity - sock->received_len;
			char *fin_ack_pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq3, ack3,
												  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FIN_FLAG_MASK | ACK_FLAG_MASK, adv_window, 0, NULL, 0);
			sendToLayer3(fin_ack_pkt, DEFAULT_HEADER_LEN);
			trace_write(SENT, fin_ack_pkt, sock);
		}
		break;
	case FIN_WAIT_1:
		// client端已发送FIN
		if (flag == ACK_FLAG_MASK)
		{
			// 收到第二次挥手, 等待第三次挥手
			sock->state = FIN_WAIT_2;
			printf("[handle packet] current state:%d\n", sock->state);
			break;
		}
		else if (flag == FIN_FLAG_MASK)
		{
			sock->state = CLOSING;
			sock->window.wnd_recv->expect_seq += 1;
			sock->window.wnd_send->base = ack;
			// 发送第四次挥手
			uint32_t seq4 = ack, ack4 = seq + 1;
			int adv_window = sock->received_capacity - sock->received_len;
			char *ack_pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq4, ack4,
											  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, adv_window, 0, NULL, 0);
			sendToLayer3(ack_pkt, DEFAULT_HEADER_LEN);
			trace_write(SENT, ack_pkt, sock);
			sock->window.wnd_send->nextseq += 1;
			printf("[handle packet] current state:%d\n", sock->state);
			break;
		}
		else if (flag == FIN_FLAG_MASK | ACK_FLAG_MASK)
		{
			// 收到第三次挥手
			sock->state = TIME_WAIT;
			sock->window.wnd_recv->expect_seq += 1;
			sock->window.wnd_send->base = ack;
			// 发送第四次挥手
			uint32_t seq4 = sock->window.wnd_send->nextseq, ack4 = seq + 1;
			int adv_window = sock->received_capacity - sock->received_len;
			char *ack_pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq4, ack4,
											  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, adv_window, 0, NULL, 0);
			sendToLayer3(ack_pkt, DEFAULT_HEADER_LEN);
			trace_write(SENT, ack_pkt, sock);
			sock->window.wnd_send->nextseq += 1;
			printf("[handle packet] current state:%d\n", sock->state);
			break;
		}
		break;
	case FIN_WAIT_2:
		// client端接收到第三次挥手, 发送第四次挥手
		if (flag == FIN_FLAG_MASK | ACK_FLAG_MASK)
		{
			sock->state = TIME_WAIT;
			sock->window.wnd_recv->expect_seq += 1;
			sock->window.wnd_send->base = ack;
			uint32_t seq4 = ack, ack4 = seq + 1;
			int adv_window = sock->received_capacity - sock->received_len;
			char *ack_pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq4, ack4,
											  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, adv_window, 0, NULL, 0);
			sendToLayer3(ack_pkt, DEFAULT_HEADER_LEN);
			trace_write(SENT, ack_pkt, sock);
			sock->window.wnd_send->nextseq += 1;
		}
		break;
	case CLOSING:
		if (flag == ACK_FLAG_MASK)
		{
			sock->state = TIME_WAIT;
		}
		break;
	case LAST_ACK:
		if (flag == ACK_FLAG_MASK)
		{
			sock->state = CLOSED;
		}
		break;
	default:
		break;
	}
	// printf("[handle packet] current state:%d\n", sock->state);
	return 0;
}

int tju_close(tju_tcp_t *sock)
{
	while (sock->sending_len != 0)
	{
		// 当前已收到的数据需要处理完毕
	}
	sock->state = FIN_WAIT_1;
	uint32_t seq = sock->window.wnd_send->nextseq, ack = sock->window.wnd_recv->expect_seq;
	int adv_window = sock->received_capacity - sock->received_len;
	char *fin_pkt = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, ack,
									  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, FIN_FLAG_MASK, adv_window, 0, NULL, 0);
	sendToLayer3(fin_pkt, DEFAULT_HEADER_LEN);
	trace_write(SENT, fin_pkt, sock);
	sock->window.wnd_send->nextseq += 1;
	while (sock->state != TIME_WAIT)
	{
	}
	sock->state = CLOSED;
	return 0;
}