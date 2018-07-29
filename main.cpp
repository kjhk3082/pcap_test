#include <pcap.h>
#include <stdio.h>

void usage() {
  	printf("syntax: pcap_test <interface>\n");
  	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  	if (argc != 2) {
    		usage();
    		return -1;
	}

	char track[] = "Consulting";
	char name[] = "Kimjaehyung";
	printf("[bob7][%s]pcap_test[%s]\n", track, name);

	char* dev = argv[1];
  	char errbuf[PCAP_ERRBUF_SIZE];
  	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    		return -1;
  	}
	while (true) {
    		struct pcap_pkthdr* header;
    		const u_char* packet;
    		int res = pcap_next_ex(handle, &header, &packet);
    		if (res == 0) continue;
    		if (res == -1 || res == -2) break;
  		printf("\n#########################################");
		printf("\n%u bytes captured\n", header->caplen);
    		printf("Destination MAC : [%02x:%02x:%02x:%02x:%02x:%02x]\nSource MAC : [%02x:%02x:%02x:%02x:%02x:%02x] TYPE : 0x%02x%02x\n"
			,packet[0]
			,packet[1]
			,packet[2]
			,packet[3]
			,packet[4]
			,packet[5]
			,packet[6]
			,packet[7]
			,packet[8]
			,packet[9]
			,packet[10]
			,packet[11]
			,packet[12]
			,packet[13]);
		printf("###########################################\n");
		printf("\nSource IP : %d.%d.%d.%d\nDestination IP : %d.%d.%d.%d\n"
			,packet[26]
			,packet[27]
			,packet[28]
			,packet[29]
			,packet[30]
			,packet[31]
			,packet[32]
			,packet[33]);
		printf("\n##########################################\n");
		printf("\nSrc Port : %d%d\nDst Port :  %d%d\n"
        		,packet[34]
			,packet[35]
        		,packet[36]
        		,packet[37]);


			int i;
			printf("\n###########################################\n");
			printf("\nDATA : ");
			for(i=0; i<16; i++) {
				printf("%c",packet[i]);
				if (i == 70) {
					printf("\n");
				}
			}
			printf("\n");

			printf("#########################################\n");
  		}

  		pcap_close(handle);
  		return 0;
	}
