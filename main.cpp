#include <pcap.h>
#include <netinet/in.h>
#include <stdio.h>

void packetAnalyze(pcap_t* des)
{
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(des, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s).\n", res, pcap_geterr(des));
            break;
        }
        else {
            if((ntohs((uint16_t)packet[12]) == 0x800) && (packet[23] == 6)){
                printf("\n[1]Src mac : ");
	            for(int i=0; i<6; i++) printf("%d ", packet[i+6]);
                printf("\n   Dst mac : ");
	            for(int i=0; i<6; i++) printf("%d ", packet[i]);
	            printf("\n[2]Src ip : ");
		        for(int i=0; i<4; i++) printf("%d ", packet[i+26]); // ethernet(14)+ip(12)
                printf("\n   Dst ip : ");
		        for(int i=0; i<4; i++) printf("%d ", packet[i+30]); // ethernet(14)+ip(12)+srcip(4)
                
                int total_len = ntohs((uint16_t)packet[16]);
                int IPh_len = (packet[14]&0x0f)*4;
                int TCPh_len = ((packet[14+IPh_len+12]&0xf0)>>4)*4;
                printf("\n[3]Src port : %d", ntohs((uint16_t)packet[IPh_len+14]));
                printf("\n   Dst port : %d", ntohs((uint16_t)packet[IPh_len+16]));

                int data_len = total_len - IPh_len - TCPh_len;
                if(data_len > 0){
                    printf("\n[4]Data : ");
                    if(data_len > 16){
                        for(int i=0; i<16; i++) printf("%x ", packet[i+14+IPh_len+TCPh_len]);
                    }
                    else {
                        for(int i=0; i<data_len; i++) printf("%x ", packet[i+14+IPh_len+TCPh_len]);
                    }
                    printf("\n");
                }             
                printf("\n");
            }
        }
    }
}

int main(int argc, char* argv[]) {
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (argc != 2) {
        printf("syntax: pcap-test <interface>\nsample: pcap-test wlan0\n");
        return -1;
    }

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Device open error! %s return nullptr : %s\n", dev, errbuf);
        return -1;
    }

    packetAnalyze(handle);
    pcap_close(handle);
}
