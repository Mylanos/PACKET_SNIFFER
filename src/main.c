#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <getopt.h>
#include <sys/socket.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>


#define BUF_SIZE 100
#define PORT_MAX_BUFFER 20

pcap_t * od;
static int udp_flag;
static int tcp_flag;


#define LINE_LEN 16

int isNotNumber(char* s){
    for (int i = 0; i < strlen(s); i++)
        if (isdigit(s[i]) == 0)
            return 1;
    return 0;
}

int main(int argc, char **argv) {

    char errbuf[PCAP_ERRBUF_SIZE];          /* Buffer for possible pcap errors */
    int c;                                  /* Argument parsing variable */
    char port[PORT_MAX_BUFFER] = "port ";   /* Port to be listened // on skus to aj bez port v stringu */
    int num_of_packets = 1;                 /* Ammount of packets to be shown */
    int digit_optind = 0;                   /* PREBYTOCNA SOMARINA */
    char interface[BUF_SIZE] = "";          /* Sniffing interface buffer */
    struct bpf_program fp;		            /* Compiled filter expression */
    bpf_u_int32 mask;		                /* The netmask of our sniffing device */
    bpf_u_int32 net;		                /* The IP of our sniffing device */
    struct pcap_pkthdr *header;	            /* The header that pcap gives us */
    const u_char *packet;		            /* The actual packet */

    //parsing args
    while (1) {
        int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        static struct option long_options[] = {
                {"i",       required_argument,          0,  'i' },
                {"p",       required_argument,          0,  'p' },
                {"t",       no_argument,              &tcp_flag,  't' },
                {"tcp",     no_argument,              &tcp_flag,  't' },
                {"u",       no_argument,              &udp_flag,  'u'},
                {"udp",     no_argument,              &udp_flag,  'u' },
                {"n",       required_argument,           0,  'n'},
                {0,0,                           0,  0 }
        };

        c = getopt_long_only(argc, argv, "n", long_options, &option_index);

        //end of options detected
        if (c == -1){
            break;
        }

        switch (c) {
            case 0:
                break;

            case '0':
                if (digit_optind != 0 && digit_optind != this_option_optind)
                    printf("digits occur in two different argv-elements.\n");
                digit_optind = this_option_optind;
                printf("option %c\n", c);
                break;

            case 'i':
                snprintf(interface, BUF_SIZE, "%s", optarg );
                break;

            case 'p':
                if(isNotNumber(optarg)){
                    fprintf(stderr, "ERROR -> got %s: Expected integer!", optarg);
                    exit(EXIT_FAILURE);
                }
                strcat(port, optarg);
                break;

            case 'u':
            case 't':
                break;

            case 'n':
                //num_of_packets = (int)strtol(optarg, &tmpptr, 10);
                if(isNotNumber(optarg)){
                    fprintf(stderr, "ERROR -> got %s: Expected integer!", optarg);
                    exit(EXIT_FAILURE);
                }
                strcat(port, optarg);
                break;

            case '?':
                exit(EXIT_FAILURE);
            default:
                printf("?? getopt returned character code 0%o ??\n", c);
        }
    }

    if (optind < argc) {
        fprintf(stderr, "ERROR -> Non-option ARGV-element/s entered: ");
        while (optind < argc)
            fprintf(stderr, " \"%s\" ", argv[optind++]);
        fprintf(stderr, "!\n");
        exit(EXIT_FAILURE);
    }

    if(strcmp(interface, "") != 0){
        if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "ERROR -> Can't determine IPv4 network number and mask for device %s\n", interface);
            net = 0;
            mask = 0;
        }

        if(!(od = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf))){
            printf("ERROR -> got %s ", errbuf);
            exit(EXIT_FAILURE);
        }

        //https://www.tcpdump.org/linktypes.html on my device not supported by utun0
        if(pcap_datalink(od) != DLT_EN10MB) {
            fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", interface);
            exit(EXIT_FAILURE);
        }

        if (pcap_compile(od, &fp, port, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", port, pcap_geterr(od));
            exit(EXIT_FAILURE);
        }
/*
        if (pcap_setfilter(od, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", port, pcap_geterr(od));
            exit(EXIT_FAILURE);
        }
        */
        int i = 0;
        int n = 0;
        int size;
        int retCode = 0;
        char buff[100], buffer[BUF_SIZE];
        struct tm* tm_info;

        while((retCode = pcap_next_ex(od, &header, &packet)) >= 0){
            size = header->len;
            tm_info = localtime(&header->ts.tv_sec);

            if(retCode == 0){
                continue;
            }

            struct ip *iph = (struct ip*)(packet + sizeof(struct ethhdr*));

            switch ((int)iph->ip_p){

                case 6:
                case 17:
                    strftime(buff, 100, "%H:%M:%S", tm_info);
                    printf("%s.%06d \n", buff, header->ts.tv_usec);

                    for (i=1; (i < header->caplen + 1 ) ; i++)
                    {
                        printf("%.2x ", packet[i-1]);
                        if ( (i % LINE_LEN) == 0) printf("\n");
                    }
                    printf("\n\n");
                    break;
                default:
                    break;

            }
            printf("PROTOCOL: %hhu | TYPE OF SERVICE %hhu\n\n", iph->ip_p, iph->ip_tos);
            n++;
        }

       /* packet = pcap_next(od, &header);
        printf("Jacked a packet with length of %d [%d]\n", header.ts.tv_usec, header.len);
        printf("packet content %s", packet);*/
        pcap_close(od);
    }
    else{
        pcap_if_t *alldevs, *dev;
        int i = 1;
        if(pcap_findalldevs(&alldevs, errbuf) == -1){
            fprintf(stderr,"ERROR -> : %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
        printf("Argument specificating interface supposed to be sniffed, was not entered!\nList of active interfaces:\n");
        for(dev=alldevs; dev != NULL; dev=dev->next){
                printf("\t\t\t\t\t\t\t%d. = %s \n", i, dev->name);
                i++;
        }

        pcap_freealldevs(alldevs);
    }
    return 0;

}