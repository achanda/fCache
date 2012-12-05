#include <algorithm>
#include <utility>
#include <iterator>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <set>
#include <map>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "redispp.h"

typedef std::vector<char> chars; // data
typedef std::pair<u_int,chars> record; // <seq no, data>
std::multimap<u_int,record> dict; // <ack no, record>

using namespace redispp;
Connection conn("127.0.0.1","6379","password",false);
//conn.set("hello","world");

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

std::set<u_int> get_keys(std::multimap<u_int,record> map) {
	std::set<u_int> temp;
	std::multimap<u_int,record>::iterator it;
	for(it = map.begin(); it != map.end(); ++it)
		temp.insert(it->first);
	return temp;
}

int get_max_key(std::multimap<u_int,record> map, std::set<u_int> keys) {
	std::set<u_int>::iterator it = keys.begin();
	u_int max = *it;
        for(;it != keys.end(); ++it){
		if (map.count(*it) > map.count(max))
			max = *it;
	}
	return max; 
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	//const char *payload;                    /* Packet payload */
	//const u_char *payload;

	int size_ip;
	int size_tcp;
	int size_payload;
	
	//printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	//printf("       From: %s\n", inet_ntoa(ip->ip_src));
	//printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			//printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}

	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	std::string flags;
	if (tcp->th_flags & TH_FIN) 
		flags = flags + "F";
	if (tcp->th_flags & TH_SYN) 
                flags = flags + "S";
	if (tcp->th_flags & TH_RST) 
                flags = flags + "R";
	if (tcp->th_flags & TH_ACK) 
                flags = flags + "A";
	if (tcp->th_flags & TH_URG) 
                flags = flags + "U";
	if (tcp->th_flags & TH_ECE) 
                flags = flags + "E";
	if (tcp->th_flags & TH_CWR) 
                flags = flags + "C";

	chars v;
	chars buffer;
	std::multimap<u_int,chars> temp_map; //to sort

	std::cout << "Packet# " << count << " S " << ntohl(tcp->th_seq) << " A " << ntohl(tcp->th_ack) << " Flags " << flags <<"\n";

	if ((tcp->th_flags & TH_ACK) != 0) {
		const u_char *payload = (const u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);
		size_payload = ntohs(ip->ip_len)- (size_ip + size_tcp);
		std::copy(payload, payload + size_payload, std::back_inserter(v));
		//std::reverse(v.begin(),v.end()); // byte order thing
		std::pair<u_int,chars> temp(ntohl(tcp->th_seq),v); // create record
		dict.insert(std::pair<u_int,record>(ntohl(tcp->th_ack),temp));
		//std::cout << "Packet# " << count << " " << ntohl(tcp->th_seq) << "\n";
		//std::cout << "Packet# " << count << " " << inet_ntoa(ip->ip_src) << "\n";
	}

	  if (((tcp->th_flags & TH_FIN) != 0) && ((tcp->th_flags & TH_ACK) != 0)) {
		std::set<u_int> temp = get_keys(dict);
		u_int last_key = ntohl(tcp->th_ack);
		std::cout << "*********************************************\n";
		std::set<u_int>::iterator it = temp.begin();
		for(;it != temp.end(); ++it)
			std::cout << "Key " << *it << " Count " << dict.count(*it) <<"\n";
		u_int image_key = get_max_key(dict,temp);
		std::cout << "Image key " << image_key << "\n";

		std::multimap<u_int,record>::iterator itt;
		std::cout << "*********************************************\n";
		for(itt=dict.begin(); itt!= dict.end(); ++itt) {
			if ((*itt).first == image_key) {
				std::pair<u_int,chars> temp_record = (*itt).second;
				temp_map.insert(std::pair<u_int,chars>(temp_record.first,temp_record.second));
			}
		}

		std::multimap<u_int,chars>::iterator ittt;
		for(ittt = temp_map.begin(); ittt!=temp_map.end(); ++ittt) {
			buffer.insert(buffer.end(), (*ittt).second.begin(), (*ittt).second.end());
		}

		std::ofstream myfile;
		myfile.open("image.jpg", std::ios::out | std::ios::binary);
		myfile.write(&buffer[0], buffer.size());
		std::cout << buffer.size() << "\n";
		std::cout << "For FIN packet " << "S: " << ntohl(tcp->th_seq) << " A: " << ntohl(tcp->th_ack) << "\n";
		dict.clear();
		conn.set("server_ip",inet_ntoa(ip->ip_src));
		//exit(0);
	}
return;
}

int main(int argc, char **argv)
{
	conn.set("hello","world");
	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "tcp and src port 80";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}

