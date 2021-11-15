#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pcap/pcap.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#define BUF_SIZE 1000
#define PORT_MAX_BUFFER 20
#define LINE_LEN 16

pcap_t * od;
static int udp_flag;
static int tcp_flag;


void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);

/** Checks if string is number
 */
int isNotNumber(char* s){
    for (int i = 0; i < strlen(s); i++)
        if (isdigit(s[i]) == 0)
            return 1;
    return 0;
}

/** Prints help
 */
void print_help(){
    printf("./ipk-sniffer -i rozhraní [-p port] [--tcp|-t] [--udp|-u] [-n num]");
}

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];          /* Buffer for possible pcap errors */
    int c;                                  /* Argument parsing variable */
    char port[PORT_MAX_BUFFER] = "";        /* Port to be listened // on skus to aj bez port v stringu */
    int num_of_packets = 1;                /* Ammount of packets to be shown */
    char interface[BUF_SIZE] = "";          /* Sniffing interface buffer */
    char filter[BUF_SIZE] = "";             /* Sniffing interface buffer */
    char *tmpptr = NULL;
    struct bpf_program fp;		            /* Compiled filter expression */
    bpf_u_int32 mask;		                /* The netmask of our sniffing device */
    bpf_u_int32 net;		                /* The IP of our sniffing device */
    struct pcap_pkthdr *header;	            /* The header that pcap gives us */
    const u_char *packet;		            /* The actual packet */
    int link_type;                          /* interface's link-level header */

    /** Parsing arguments
     * inspirations from source: https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html (manpage)
     */
    while (1) {
        int option_index = 0;
        /*options file*/
        static struct option long_options[] = {
                {"i",       required_argument,          0,  'i' },
                {"p",       required_argument,          0,  'p' },
                {"port",       required_argument,       0,  'p' },
                {"t",       no_argument,              &tcp_flag,  't' },
                {"tcp",     no_argument,              &tcp_flag,  't' },
                {"u",       no_argument,              &udp_flag,  'u'},
                {"udp",     no_argument,              &udp_flag,  'u' },
                {"n",       required_argument,           0,  'n'},
                {"h",       no_argument,                 0,  'h'},
                {"help",    no_argument,                 0,  'h'},
                {0,0,                           0,  0 }
        };

        /*parses arguments*/
        c = getopt_long(argc, argv, "i:p:tunh", long_options, &option_index);

        //end of options detected
        if (c == -1){
            break;
        }
        /*switch on arguments*/
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
                /*if port didnt receive number -> error*/
                if(isNotNumber(optarg)){
                    fprintf(stderr, "ERROR -> got %s: Expected integer!", optarg);
                    exit(EXIT_FAILURE);
                }
                /*concatenating string for filtering*/
                snprintf(port, PORT_MAX_BUFFER, "port %s", optarg);
                break;
            case 'u':
            case 't':
                break;
            case 'n':
                /*how much packets should be processed*/
                num_of_packets = (int)strtol(optarg, &tmpptr, 10);
                /*checks if argument of -n wasnt a character*/
                if(strcmp(tmpptr, "") != 0){
                    fprintf(stderr, "ERROR -> got %s: Expected integer!", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case '?':
                //optopt argument pristup
                exit(EXIT_FAILURE);
            default:
                printf("Getopt returned character code 0%o ??\n", c);
        }
    }

    /*unsupported arguments were passed*/
    if (optind < argc) {
        fprintf(stderr, "ERROR -> Non-option ARGV-element/s entered: ");
        while (optind < argc)
            fprintf(stderr, " \"%s\" ", argv[optind++]);
        fprintf(stderr, "!\n");
        exit(EXIT_FAILURE);
    }

    /*if interface wasnt passed*/
    if(strcmp(interface, "") != 0){

        //Open handle for capturing
        if(!(od = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf))){
            printf("ERROR -> got %s ", errbuf);
            exit(EXIT_FAILURE);
        }


        //Supporting only devices with ETHERNET_PROTOCOL
        link_type = pcap_datalink(od);
        if(link_type != DLT_EN10MB){
            fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", interface);
            exit(EXIT_FAILURE);
        }

        /*apply filters*/
        if((tcp_flag && udp_flag) || (!tcp_flag && !udp_flag)){
            sprintf(filter, "(udp or tcp) ");
        }
        else if(tcp_flag){
            sprintf(filter, "tcp ");
        }
        else{
            sprintf(filter, "udp ");
        }
        if(strcmp(port, "") != 0){
            strcat(filter, " and ");
            strcat(filter, port);
        }

        /*compile handle with used filter*/
        if (pcap_compile(od, &fp, filter, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", port, pcap_geterr(od));
            exit(EXIT_FAILURE);
        }

        /*set used filter*/
        if (pcap_setfilter(od, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", port, pcap_geterr(od));
            exit(EXIT_FAILURE);
        }

        /*loop over processing packets*/
        pcap_loop(od, num_of_packets, process_packet, NULL);
        pcap_close(od);
    }
    else{
        pcap_if_t *alldevs, *dev;
        int i = 2;
        /*finds all active interfaces*/
        if(pcap_findalldevs(&alldevs, errbuf) == -1){
            fprintf(stderr,"ERROR -> : %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
        printf("Argument specifying interface supposed to be sniffed, was not entered!\n"
               "For further help with sniffer's launch options, use -h or --help argument.\n"
               "List of active interfaces: 1. = %s\n", alldevs->name);

        for(dev=alldevs->next; dev != NULL; dev=dev->next){
                printf("\t\t\t   %d. = %s \n", i, dev->name);
                i++;
        }
        pcap_freealldevs(alldevs);
    }
    return 0;

}

/** Prints packet's ascii representation
 *
 * @param packet_len length of packet
 * @param pkthdr packet header struct
 * @param packet packet
 */
void print_packet_ascii(int n, int i,const u_char *packet, int print_counter){
    if (print_counter == 8) {
        printf(" ");
    }
    if (isprint(packet[i - n])){
        printf("%c", packet[i - n]);
    }
    else{
        printf(".");
    }
}

/** Prints packet
 *
 * @param packet_len length of packet
 * @param pkthdr packet header struct
 * @param packet packet
 */
void print_packet(int packet_len,const u_char *packet){
    /*counter of  printed bytes in hexa*/
    int print_bytes_counter = 0;
    /*iterators*/
    int k = 0, i;

    /*print whole packet*/
    for (i = 0; i <= packet_len; i++) {
        /*in case of ending bytes that are not equal to LINE_LEN
         * flag is needed to output format differently than when its equal to LINE_LEN*/
        bool approaching_end = (packet_len - i == 0) && (print_bytes_counter % LINE_LEN != 0);
        /*counter of  printed bytes in ascii*/
        int print_ascii_counter = 0;
        if ((i % LINE_LEN) == 0 || approaching_end) {
            if(i != 0){
                if(!approaching_end){
                    printf("\t");
                }
                bool printed_space = false;
                /*print data as ascii characters or '.'*/
                for(int n = LINE_LEN; n > 0; n--) {
                    if(approaching_end){
                        int bytes_left = packet_len % LINE_LEN;
                        if(n > bytes_left){
                            printf("   ");
                        }
                        else{
                            if(n == bytes_left){
                                printf("\t");
                            }
                            print_packet_ascii(n, i, packet, print_ascii_counter);
                            print_ascii_counter++;
                        }
                    }
                    else{
                        print_packet_ascii(n, i, packet, print_ascii_counter);
                        print_ascii_counter++;
                    }
                }
            }
            if(approaching_end){
                break;
            }
            printf("\n0x%03x0\t", k);
            k++;
        }
        if(i % 8 == 0){
            printf(" ");
        }
        printf("%02x ", packet[i]);
        print_bytes_counter++;
    }
    if(i % LINE_LEN != 0){
        for(int j = 0; j < i; j++){

        }
    }
}

/** Processes packet, structure conversions
 *
 * @param user unnecessary argument
 * @param pkthdr header of the packet
 * @param packet processed packet
 */
void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    struct ip *ip;          /*ip header structure*/
    struct tcphdr *tcp;     /*tcp header structure*/
    struct udphdr *udp;     /*udp header structure*/
    struct hostent *hp;     /*hosts structure*/
    char *source_addr;      /*source address string*/
    char *destination_addr; /*destination address string*/
    int destination_port, source_port; /*ports*/
    char buff[BUF_SIZE];    /*string containing time stamp*/

    /*Conversion of packet headers timeval structure to needed format */
    struct tm* tm_info = localtime(&pkthdr->ts.tv_sec);
    strftime(buff, 100, "%H:%M:%S", tm_info);

    /*typecast packet to ip header*/
    ip = (struct ip*)(packet + sizeof(struct ether_header));

    /*typecast packet to tcp/udp header according to ip's protocol*/
    if(ip->ip_p == IPPROTO_TCP){
        tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        destination_port = ntohs(tcp->th_dport);
        source_port = ntohs(tcp->th_sport);
    }
    else{
        udp = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        destination_port = ntohs(udp->uh_dport);
        source_port = ntohs(udp->uh_sport);
    }

    /*try to resolve source IP addresses*/
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
    printf("%s.%06d ", buff, (int)pkthdr->ts.tv_usec);
    /*source address/host name and source port*/
    printf("%s : %d > ", source_addr, source_port);
    /*destination address/host name and destination port*/
    printf("%s : %d\n", destination_addr, destination_port);
    /*print packet*/
    print_packet(pkthdr->len, packet);
    printf("\n\n");

}