void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int isNotNumber(char* s);

void print_packet_ascii(int n, int i,const u_char *packet, int print_counter);

void print_packet(int packet_len,const u_char *packet);

/**
 *
 * @param user
 * @param pkthdr
 * @param packet
 */
void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);