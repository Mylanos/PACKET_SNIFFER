#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <getopt.h>
#include <sys/socket.h>
#include <string.h>
#include <ctype.h>

#define BUF_SIZE 100
#define PORT_MAX_BUFFER 20

pcap_t * od;
static int udp_flag;
static int tcp_flag;


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
    struct pcap_pkthdr header;	            /* The header that pcap gives us */
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
        printf("%s", port);

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

        if (pcap_setfilter(od, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", port, pcap_geterr(od));
            exit(EXIT_FAILURE);
        }

        packet = pcap_next(od, &header);
        printf("Jacked a packet with length of [%d]\n", header.len);
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
    /*
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    if(pcap_open_live("eth1", 10, 10, 10, errbuf)) {
        printf("Device: %s\n", dev);

    }
    else{
        printf("Inactive interface! %s", "eth1");
    }*/
    return 0;


    /*
     *
     * socklen_t peer_addr_len;
    struct sockaddr peer_addr;
    int sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0)
    {
        printf("Socket Error\n");
        return 1;
    }
    char buffer[BUF_SIZE];

    while(1)
    {
        ssize_t data_size = recvfrom(sock_raw , buffer , 65536 , 0 , (struct sockaddr *) &peer_addr , &peer_addr_len);
        cout << data_size;
    }
    return 0;*/
}