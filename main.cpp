#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <libnet.h>
#include <netinet/in.h>
#include <iostream>
#include "getadds.h"

char iface[80];
u_char a_mac[80];
char pattern[80];

void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

bool check_IP(const u_char* pkt){
    const struct libnet_ethernet_hdr* header = \
                (const struct libnet_ethernet_hdr*)pkt;
    if(htons(header->ether_type)==0x800)
        return true;
    return false;
}

bool check_TCPIP(const u_char* pkt){
    if(check_IP(pkt)){
        const struct libnet_ipv4_hdr* header = \
            (const struct libnet_ipv4_hdr*)(pkt+sizeof(struct libnet_ethernet_hdr));
        if(header->ip_p==0x06)
            return true;
    }
    return false;
}

bool block_check(const u_char* pkt, int caplen){
	if(!check_TCPIP(pkt))
		return false;

    const struct libnet_ethernet_hdr* eth_header = \
        (const struct libnet_ethernet_hdr*)pkt;
    const struct libnet_ipv4_hdr* ipv4_header = \
        (const struct libnet_ipv4_hdr*)(pkt+14);
	int ip_hdr_len = (ipv4_header->ip_hl)*4;
	int tot_len = ntohs(ipv4_header->ip_len)*1;
    const struct libnet_tcp_hdr* tcp_header = \
        (const struct libnet_tcp_hdr*)(pkt+14+ip_hdr_len);
	int tcp_hdr_len = (tcp_header->th_off)*4;

	u_char* payload = (u_char*)(pkt+14+ip_hdr_len+tcp_hdr_len);
	int payload_len = tot_len-ip_hdr_len-tcp_hdr_len;
	char* temp = (char*)payload;
	if(strstr(temp, pattern)!=NULL)
		return true;

	return false;
}

uint16_t checksum(uint16_t* target, int len){
	uint32_t temp = 0x00;
	
	for(int i=0;i<len/2;i++){
		temp+=target[i];
	}
	temp = (temp >> 16) + (temp & 0xFFFF);
	return (uint16_t)~temp;
}

int forward(pcap_t* handle, const u_char* pkt, int len){
	u_char pkt_s[65536];
	memcpy(pkt_s, pkt, len);

	const struct libnet_ethernet_hdr* eth_header_org = \
        (const struct libnet_ethernet_hdr*)pkt_s;
    const struct libnet_ipv4_hdr* ipv4_header_org = \
        (const struct libnet_ipv4_hdr*)(pkt_s+14);
	int ip_hdr_len_org = (ipv4_header_org->ip_hl)*4;
	int tot_len_org = ntohs(ipv4_header_org->ip_len)*1;
    const struct libnet_tcp_hdr* tcp_header_org = \
        (const struct libnet_tcp_hdr*)(pkt_s+14+ip_hdr_len_org);
	int tcp_hdr_len_org = (tcp_header_org->th_off)*4;

	struct libnet_ethernet_hdr* eth_header = \
        (struct libnet_ethernet_hdr*)pkt_s;
	struct libnet_ipv4_hdr* ipv4_header = \
        (struct libnet_ipv4_hdr*)(pkt_s+14);
    struct libnet_tcp_hdr* tcp_header = \
        (struct libnet_tcp_hdr*)(pkt_s+14+ip_hdr_len_org);

	memcpy((void*)eth_header->ether_shost, a_mac, 6);
	memcpy((void*)eth_header->ether_dhost, eth_header_org->ether_dhost, 6);

	ipv4_header->ip_len = htons(ip_hdr_len_org+tcp_hdr_len_org); 
	ipv4_header->ip_sum = 0x00;
	ipv4_header->ip_sum = checksum((uint16_t *)ipv4_header, ip_hdr_len_org);

	tcp_header->th_seq = htonl(ntohl(tcp_header_org->th_seq)+tot_len_org-ip_hdr_len_org-tcp_hdr_len_org);
	tcp_header->th_flags = 0x16;
	tcp_header->th_sum = 0x00;
	tcp_header->th_sum = checksum((uint16_t *)tcp_header, tot_len_org-ip_hdr_len_org);

	int pkt_len = 14+ip_hdr_len_org+tcp_hdr_len_org;

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pkt_s), pkt_len);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return -1;
	}

	return pkt_len;
}

int backward(pcap_t* handle, const u_char* pkt, int len){
	u_char pkt_s[65536];
	char message[] = "blocked!!!";
	int message_len = strlen(message)+1;
	memcpy(pkt_s, pkt, len);

	const struct libnet_ethernet_hdr* eth_header_org = \
        (const struct libnet_ethernet_hdr*)pkt_s;
    const struct libnet_ipv4_hdr* ipv4_header_org = \
        (const struct libnet_ipv4_hdr*)(pkt_s+14);
	int ip_hdr_len_org = (ipv4_header_org->ip_hl)*4;
	int tot_len_org = ntohs(ipv4_header_org->ip_len)*1;
    const struct libnet_tcp_hdr* tcp_header_org = \
        (const struct libnet_tcp_hdr*)(pkt_s+14+ip_hdr_len_org);
	int tcp_hdr_len_org = (tcp_header_org->th_off)*4;

	struct libnet_ethernet_hdr* eth_header = \
        (struct libnet_ethernet_hdr*)pkt_s;
	struct libnet_ipv4_hdr* ipv4_header = \
        (struct libnet_ipv4_hdr*)(pkt_s+14);
    struct libnet_tcp_hdr* tcp_header = \
        (struct libnet_tcp_hdr*)(pkt_s+14+ip_hdr_len_org);
	char* payload = (char*)(pkt_s+14+ip_hdr_len_org+tcp_hdr_len_org);

	memcpy((void*)eth_header->ether_shost, a_mac, 6);
	memcpy((void*)eth_header->ether_dhost, eth_header_org->ether_shost, 6);

	ipv4_header->ip_len = htons(ip_hdr_len_org+tcp_hdr_len_org+message_len);
	ipv4_header->ip_ttl = 0x80;
	ipv4_header->ip_src = ipv4_header_org->ip_dst;
	ipv4_header->ip_dst = ipv4_header_org->ip_src;
	ipv4_header->ip_sum = 0x00;
	ipv4_header->ip_sum = checksum((uint16_t *)ipv4_header, ip_hdr_len_org);

	tcp_header->th_sport = tcp_header_org->th_dport;
	tcp_header->th_dport = tcp_header_org->th_sport;
	tcp_header->th_seq = tcp_header_org->th_ack;
	tcp_header->th_ack = htonl(ntohl(tcp_header_org->th_seq)+tot_len_org-ip_hdr_len_org-tcp_hdr_len_org);
	tcp_header->th_flags = 0x13;
	tcp_header->th_sum = 0x00;
	tcp_header->th_sum = checksum((uint16_t *)tcp_header, tot_len_org-ip_hdr_len_org);

	strcpy(payload, message);

	int pkt_len = 14+ip_hdr_len_org+tcp_hdr_len_org+message_len;

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pkt_s), pkt_len);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return -1;
	}

	return pkt_len;
}

int main(int argc, char* argv[]) {
	
	if (argc != 3) {
		usage();
		return -1;
	}

	strcpy(iface, argv[1]);
	strcpy(pattern, argv[2]);

	if(!get_mac(a_mac, argv[1])){
		printf("error getting mac!\n");
		return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", iface, errbuf);
		return false;
	}

    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    while(true){
        int res = pcap_next_ex(handle, &pkt_header, &pkt_data);

        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        if(block_check(pkt_data, pkt_header->caplen)){
            printf("blocked packet with pattern [%s]\n", pattern);
            if(forward(handle, pkt_data, pkt_header->caplen)<1)
				break;
			if(backward(handle, pkt_data, pkt_header->caplen)<1)
				break;
        }
    }
}