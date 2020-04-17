#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <arpa/inet.h>

#define BUF_SIZE 100
#define PORT_MAX_BUFFER 20
#define SIZE_ETHERNET 14
#define LINE_LEN 16

pcap_t * od;
static int udp_flag;
static int tcp_flag;


void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);


int isNotNumber(char* s){
    for (int i = 0; i < strlen(s); i++)
        if (isdigit(s[i]) == 0)
            return 1;
    return 0;
}

void print_help(){
    printf("./ipk-sniffer -i rozhraní [-p port] [--tcp|-t] [--udp|-u] [-n num]");
}

int main(int argc, char **argv) {

    char errbuf[PCAP_ERRBUF_SIZE];          /* Buffer for possible pcap errors */
    int c;                                  /* Argument parsing variable */
    char port[PORT_MAX_BUFFER] = "";        /* Port to be listened // on skus to aj bez port v stringu */
    int num_of_packets = -1;                /* Ammount of packets to be shown */
    int digit_optind = 0;                   /* PREBYTOCNA SOMARINA */
    char interface[BUF_SIZE] = "";          /* Sniffing interface buffer */
    char filter[BUF_SIZE] = "";             /* Sniffing interface buffer */
    char *tmpptr = NULL;
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
                {"h",       no_argument,                 0,  'h'},
                {"help",    no_argument,                 0,  'h'},
                {0,0,                           0,  0 }
        };

        c = getopt_long_only(argc, argv, "p:tun", long_options, &option_index);

        //end of options detected
        if (c == -1){
            break;
        }

        switch (c) {
            case 0:
                break;
            case 'h':
                print_help();
                exit(EXIT_SUCCESS);
            case 'i':
                snprintf(interface, BUF_SIZE, "%s", optarg );
                break;
            case 'p':
                if(isNotNumber(optarg)){
                    fprintf(stderr, "ERROR -> got %s: Expected integer!", optarg);
                    exit(EXIT_FAILURE);
                }
                snprintf(port, PORT_MAX_BUFFER, "port %s", optarg);
                break;
            case 'u':
            case 't':
                break;
            case 'n':
                num_of_packets = (int)strtol(optarg, &tmpptr, 10);
                if(strcmp(tmpptr, "") != 0){
                    fprintf(stderr, "ERROR -> got %s: Expected integer!", optarg);
                    exit(EXIT_FAILURE);
                }
                printf("jouuu %s\n", tmpptr);
                break;
            case '?':
                //optopt argument pristup
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

        //1000 timeout
        if(!(od = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf))){
            printf("ERROR -> got %s ", errbuf);
            exit(EXIT_FAILURE);
        }

        //https://www.tcpdump.org/linktypes.html on my device not supported by utun0
        if(pcap_datalink(od) != DLT_EN10MB) {
            fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", interface);
            exit(EXIT_FAILURE);
        }

        if((tcp_flag && udp_flag) || (!tcp_flag && !udp_flag)){
            sprintf(filter, "udp or tcp ");
        }
        else if(tcp_flag){
            sprintf(filter, "tcp ");
        }
        else{
            printf("itsheer\n\n\n");

            sprintf(filter, "udp ");
        }
        if(strcmp(port, "") != 0){
            strcat(filter, port);
        }

        if (pcap_compile(od, &fp, filter, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", port, pcap_geterr(od));
            exit(EXIT_FAILURE);
        }

        if (pcap_setfilter(od, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", port, pcap_geterr(od));
            exit(EXIT_FAILURE);
        }


        pcap_loop(od, num_of_packets, process_packet, NULL);

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

/**
 *
 * @param user
 * @param pkthdr
 * @param packet
 */
void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    struct ip *ip;
    struct tcphdr *tcp;
    int k = 0;
    struct hostent *hp;
    char *source_addr;
    char *destination_addr;
    char buff[BUF_SIZE];
    u_int size_ip;

    struct tm* tm_info = localtime(&pkthdr->ts.tv_sec);
    strftime(buff, 100, "%H:%M:%S", tm_info);

    //typecast packet to ip header
    ip = (struct ip*)(packet + SIZE_ETHERNET);
    size_ip = ip->ip_hl*4;

    //typecast packet to tcp header
    tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);

    //try to resolve source IP address
    if((hp = gethostbyaddr((char *) &ip->ip_src, sizeof(ip->ip_src), AF_INET)) == NULL){
        source_addr = inet_ntoa(ip->ip_src);
    }
    else{
        source_addr = hp->h_name;
    }
    if((hp = gethostbyaddr((char *) &ip->ip_dst, sizeof(ip->ip_dst), AF_INET)) == NULL){
        destination_addr = inet_ntoa(ip->ip_dst);
    }
    else{
        destination_addr = hp->h_name;
    }

    /*packets time stamp*/
    printf("%s.%06d ", buff, pkthdr->ts.tv_usec);
    /*source address/host name and source port*/
    printf("%s : %d > ", source_addr, ntohs(tcp->th_sport));
    /*destination address/host name and destination port*/
    printf("%s : %d\n", destination_addr, ntohs(tcp->th_dport));
    /*print data*/
    for (int i = 0; i < pkthdr->len; i++) {
        if ((i % LINE_LEN) == 0) {
            if(i != 0){
                printf("\t");
                /*print data as ascii characters or '.'*/
                for(int n = LINE_LEN; n >= 0; n--) {
                    if(isprint(packet[i-n]))
                        printf("%c", packet[i-n]);
                    else
                        printf(".");
                }
            }
            printf("\n0x%03x0\t", k);
            k++;
        }
        if((i % (LINE_LEN/2)) == 0){
            printf(" ");
        }
        printf("%02x ", packet[i]);
    }
    printf("\n\n");

}