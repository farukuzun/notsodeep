#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define UNUSED(x) (void)(x)

static inline bool tcp_synack_segment(struct tcphdr *tcphdr ) {
	if (tcphdr->urg == 0 &&
		tcphdr->ack == 1 &&
		tcphdr->psh == 0 &&
		tcphdr->rst == 0 &&
		tcphdr->syn == 1 &&
		tcphdr->fin == 0) {
		return 1;
	}
	return 0;
}

void tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {

    register unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcpLen);
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }

    if(tcpLen > 0) {
        sum += ((*ipPayload)&htons(0xFF00));
    }
    while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    tcphdrp->check = (unsigned short)sum;
}

int rewrite_win_size( unsigned char *packet ) {

	static uint16_t new_window = 40;

	struct iphdr *iphdr = (struct iphdr *) packet;
	struct tcphdr *tcphdr = (struct tcphdr *) (packet + (iphdr->ihl<<2));

	tcphdr->window = htons(new_window);

	tcp_checksum(iphdr, (unsigned short*)tcphdr);

	return 0;
}

int rewrite_host_header( unsigned char *packet, int len) {

	unsigned char *nhost = NULL;
	char host[4] = "HoSt";
	struct iphdr *iphdr = (struct iphdr *) packet;
	struct tcphdr *tcphdr = (struct tcphdr *) (packet + (iphdr->ihl<<2));

	while (len>=8)
	{
		if (!memcmp(packet,"\r\nHost: ",8)) {
			nhost= packet;
			break;
		}
		packet++;
		len--;
	}

	if (nhost) {
		memcpy(nhost+2,host,4);
		tcp_checksum(iphdr, (unsigned short*)tcphdr);
		return 1;
	}

	return 0;

}

int callback( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa,
	void *data ) {

	UNUSED(nfmsg);
	UNUSED(data);

	struct iphdr *iphdr = NULL;
	struct tcphdr *tcphdr = NULL;
	struct nfqnl_msg_packet_hdr *ph = NULL;
	unsigned char *packet= NULL;
	int id = 0;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
	} else {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	if (nfq_get_payload(nfa, &packet) == -1) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	iphdr = (struct iphdr *) packet;
	if ((iphdr->ihl < 5) || (iphdr->ihl > 15)) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	tcphdr = (struct tcphdr *) (packet + (iphdr->ihl<<2));

	if (tcp_synack_segment(tcphdr)) {

		if (rewrite_win_size(packet) != 0) {
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		}

		return nfq_set_verdict(qh, id, NF_ACCEPT, ntohs(iphdr->tot_len), packet);

	} else {
		if (rewrite_host_header(packet, ntohs(iphdr->tot_len))) {
			return nfq_set_verdict(qh, id, NF_ACCEPT, ntohs(iphdr->tot_len), packet);
		}
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		
	}
}

int init_libnfq( struct nfq_handle **h, struct nfq_q_handle **qh ) {

	*h = nfq_open();
	if (!(*h)) {
		return 1;
	}

	if (nfq_unbind_pf(*h, AF_INET) < 0) {
		return 1;
	}

	if (nfq_bind_pf(*h, AF_INET) < 0) {
		return 1;
	}

	*qh = nfq_create_queue(*h,  200, &callback, NULL);
	if (!(*qh)) {
		return 1;
	}

	if (nfq_set_mode(*qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		return 1;
	}

	return 0;
}

int main() {

	int fd = 0;
	int rv = 0;
	char buf[4096] __attribute__ ((aligned));
	struct nfq_handle *h;
	struct nfq_q_handle *qh;

	if (init_libnfq(&h, &qh) != 0) {
		return 1;
	}

	fd = nfq_fd(h);

	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		nfq_handle_packet(h, buf, rv);
	}

	nfq_destroy_queue(qh);
	nfq_close(h);

	return 0;
}
