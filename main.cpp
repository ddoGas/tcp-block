#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include "ethhdr.h"
#include "getadds.h"

char iface[80];
char a_macstr[80];
Mac a_mac;
char pattern[80];

void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

bool block_check(){
	printf("goodd\n");
}

void forward(){

}

void backward(){
    
}

int main(int argc, char* argv[]) {
	
	if (argc != 4) {
		usage();
		return -1;
	}

	strcpy(iface, argv[1]);

	if(!get_mac(a_macstr, argv[1])){
		printf("error getting mac!\n");
		return -1;
	}
	a_mac = Mac(a_macstr);

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
            forward(handle, pkt_data, pkt_header->caplen);
            backward(handle, pkt_data, pkt_header->caplen);
        }
    }
}