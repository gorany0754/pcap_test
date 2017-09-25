#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libnet.h>
#include <libnet/libnet-types.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>

#define SIZE_ETHERNET 14//size for ethernet

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}
	const unsigned char *data;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev = pcap_lookupdev(errbuf);//get first dev
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while (1) {
		struct pcap_pkthdr* header;
		struct libnet_ipv4_hdr* iph;
		struct libnet_tcp_hdr* tcp;
		struct libnet_ethernet_hdr* eth;

		uint16_t eth_type;//uint16_t for ether_type
		char test[16];//buf for inet_ntop

		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		printf("------------------------------------------------\n");
		printf("%u bytes captured\n", header->caplen);

		//ETHERNET information
		eth = (struct libnet_ethernet_hdr*)(packet);
		printf("[ETHERNET]\n");
		//Print EHTHERNET address 
		printf("source ethernet address : ");
		for(int i=0;i<6;i++)
		{
			if(i!=5)
				printf("%.2x:", eth->ether_shost[i]);
			else
				printf("%.2x\n", eth->ether_shost[i]);
		}
		printf("destination ethernet address : ");
		for(int i=0;i<6;i++)
		{
			if(i!=5)
				printf("%.2x:", eth->ether_dhost[i]);
			else
				printf("%.2x\n", eth->ether_dhost[i]);
		}


		//IP information
		iph=(struct libnet_ipv4_hdr*)(packet+SIZE_ETHERNET);
		eth_type=ntohs(eth->ether_type);
		//If ether_type is IP
		if(eth_type==0x0800){
			printf("[IP]\n");
			printf("IP Src Address : %s\n", inet_ntop(AF_INET,&(iph->ip_src),test,sizeof(test)));
			memset(test,0,16);
			printf("IP Dst Address : %s\n", inet_ntop(AF_INET,&(iph->ip_dst),test,sizeof(test)));
			memset(test,0,16);
		}
		//TCP information
		tcp=(struct libnet_tcp_hdr*)(packet + SIZE_ETHERNET + (iph->ip_hl)*4);
		//If ether_type is TCP
		if(iph->ip_p==0x06){
			printf("[TCP] \n");
			printf("TCP Src Port : %d\n",ntohs(tcp->th_sport));
			printf("TCP Dst Port : %d\n",ntohs(tcp->th_dport));
			data = (char*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_tcp_hdr) + sizeof(struct libnet_ipv4_hdr));

			if(data == NULL){
				printf("Nothing...\n");
			}else{
				printf("Payload : ");
				for(int i = 0 ; i < 16 ; i++){
					printf("%02x ", *data);
					data += 1;
				}
				printf("\n");
			}
		}
	}
pcap_close(handle);
return 0;
}
