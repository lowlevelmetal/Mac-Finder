#ifndef __NETWORK_H___
#define __NETWORK_H___

#include <features.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <rpc/types.h>

#define __USE_MISC 1

#include <sys/stat.h>
#include <netinet/in.h>
#include <linux/if_addr.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <getopt.h>
#include <pthread.h>
#include <time.h>

#define ICMP_ECHO 8

#define ETH_ADDRLEN 6  // octets in one address
#define ETH_HDRHLEN 14 // octets in entire header

#define NETWORK_CONTROL 0xFC // Set TOS to this value to \
                             // achieve max reliability

#define bool uint8_t

struct eth_hdr
{
    unsigned char h_dest[ETH_ADDRLEN];   // Destination address
    unsigned char h_source[ETH_ADDRLEN]; // Source address
    __be16 h_proto;                      // Packet type ID field
};

struct ip_hdr
{
    unsigned char ip_version_and_header_length; // Version and header length
    unsigned char ip_tos;                       // Type of service
    unsigned short ip_len;                      // Total length
    unsigned short ip_id;                       // Identification number
    unsigned short ip_frag_offset;              // Fragment offset and flags
    unsigned char ip_ttl;                       // Time to live
    unsigned char ip_type;                      // Protocol type
    unsigned short ip_checksum;                 // Checksum
    unsigned int ip_src_addr;                   // Source IP address
    unsigned int ip_dest_addr;                  // Destination IP address
};

struct icmp_hdr
{
  u_int8_t message_type;                /* message type */
  u_int8_t sub_code;                /* type sub-code */
  u_int16_t checksum;
  union
  {
    struct
    {
      u_int16_t process_id;
      u_int16_t sequence;
    } echo;                     /* echo datagram */
    u_int32_t   gateway;        /* gateway address */
    struct
    {
      u_int16_t __glibc_reserved;
      u_int16_t mtu;
    } frag;                     /* path mtu discovery */
  } un;
};

struct tcp_hdr
{
    unsigned short tcp_src_port;  // Source TCP port
    unsigned short tcp_dest_port; // Destination TCP port
    unsigned int tcp_seq;         // TCP sequence number
    unsigned int tcp_ack;         // TCP acknowledgment number
    unsigned char reserved : 4;   // 4 bits from the 6 bits of reserved space
    unsigned char tcp_offset:4;   // TCP data offset for little-endian host
    unsigned char tcp_flags;      // TCP flags (and 2 bits from reserved space)
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
    unsigned short tcp_window;   // TCP window size
    unsigned short tcp_checksum; // TCP checksum
    unsigned short tcp_urgent;   // TCP urgent pointer
};

//
//// This function sends a string of text to a socket descriptor
bool SendStringServer(int sockfd, char *buffer)
{
    int iSentBytes, iBytesToSend;
    iBytesToSend = strlen(buffer);

    // Continue to send information as long
    // as there are remaining bytes to send
    while (iBytesToSend > 0)
    {
        iSentBytes = send(sockfd, buffer, iBytesToSend, 0);
        if (iSentBytes == -1)
            return FALSE;

        // Calculate new ptr and sub iBytesT oSend
        iBytesToSend -= iSentBytes;
        buffer += iSentBytes;
    }

    return TRUE;
}

#define EOL "\r\n" // End of line sequence
#define EOL_SIZE 2

//
//// Recieves string of data from from server
int RecvStringServer(int sockfd, char *szDestinationBuffer)
{
    char *ptr;
    int iEolMatched = 0;

    ptr = szDestinationBuffer;

    // Loop as long as data is recieved
    while (recv(sockfd, ptr, 1, 0) == 1)
    {
        // Check if EOL is found
        if (*ptr == EOL[iEolMatched])
        {
            iEolMatched++;
            if (iEolMatched == EOL_SIZE)
            {
                *(ptr + 1 - EOL_SIZE) = '\0';
                return strlen(szDestinationBuffer);
            }
        }
        else
        {
            iEolMatched = 0;
        }

        ptr++;
    }
    return 0;
}

void dump(char *buffer, unsigned int size)
{
    for (int i = 0; i < size; i++)
    {
        printf("0x%02x ", (uint8_t)buffer[i]);
        if (!(i % 4) && i != 0)
            printf("\n");
        if (i == 2)
            printf("\n");
    }

    //memset(buffer, '\0', size);

    printf("\n");
}

void DecodeEthr(const char *szBuffer)
{
    struct eth_hdr *eth;
    eth = (struct eth_hdr *)szBuffer;

    printf("\nSource: %02x", eth->h_source[0]);
    for (int i = 1; i < ETH_ADDRLEN; i++)
        printf(":%02x", eth->h_source[i]);

    printf("\n");

    printf("Destination: %02x", eth->h_dest[0]);
    for (int i = 1; i < ETH_ADDRLEN; i++)
        printf(":%02x", eth->h_dest[i]);

    printf("\n\n");
}

void DecodeIp(const char *szBuffer)
{
    struct ip_hdr *ip;
    struct in_addr *addr;
    ip = (struct ip_hdr *)szBuffer;
    addr = (struct in_addr *)&ip->ip_src_addr;

    printf("Total Length of Datagram: %hu\n", ip->ip_len);

    printf("Source: 0x%02x | %s\n", ip->ip_src_addr, inet_ntoa(*addr));

    if (strcmp("157.240.3.35", inet_ntoa(*addr)) == 0)
    {
        addr = (struct ip_hdr *)&ip->ip_dest_addr;

        printf("Destination: 0x%02x | %s\n\n", ip->ip_dest_addr, inet_ntoa(*addr));
        exit(EXIT_SUCCESS);
    }

    addr = (struct ip_hdr *)&ip->ip_dest_addr;

    printf("Destination: 0x%02x | %s\n\n", ip->ip_dest_addr, inet_ntoa(*addr));

    if (strcmp("157.240.3.35", inet_ntoa(*addr)) == 0)
        exit(EXIT_SUCCESS);
}

void ParseSockAddr_IN(struct sockaddr_in *sin) {
    printf("%d\n", sin->sin_family);
    printf("%d\n", ntohs(sin->sin_port));
    printf("%s\n", inet_ntoa(sin->sin_addr));
}

__u_int DecodeTcp(const char *szBuffer)
{
    struct tcp_hdr *tcp;
    __u_int uHeaderSize;

    tcp = (struct tcp_hdr *)szBuffer;
    uHeaderSize = 4 * tcp->tcp_offset;

    // Not that total TCP header size is = to
    // 4 * TCP Data Offset
    //printf("Data Offset: 0x%010x\n", ntohs(tcp->doff));
    printf("Source PORT: %hu\n", ntohs(tcp->tcp_src_port));
    printf("Destination PORT: %hu\n", ntohs(tcp->tcp_dest_port));
    printf("Seq #: %u\n", ntohl(tcp->tcp_seq));
    printf("Ack #: %u\n", ntohl(tcp->tcp_ack));
    printf("Header Size: %u\nFlags: ", uHeaderSize);
    if (tcp->tcp_flags & TH_FIN)
        printf("FIN ");
    if (tcp->tcp_flags & TH_ACK)
        printf("ACK ");
    if (tcp->tcp_flags & TH_RST)
        printf("RST ");
    if (tcp->tcp_flags & TH_PUSH)
        printf("PUSH ");
    if (tcp->tcp_flags & TH_SYN)
        printf("SYN ");
    if (tcp->tcp_flags & TH_URG)
        printf("URG ");

    printf("\n\n");

    return 0;
}

struct pseudo_header //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcphdr tcp;
};

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
	register long sum;
	u_short oddbyte;
	register u_short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char *) & oddbyte) = *(u_char *) ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return (answer);
}

unsigned short csum(unsigned short *ptr, int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
}

void CreateSockaddr(struct sockaddr_in *sin, int port_num,
                    uint16_t family, const char *ip_address)
{
    memset(sin, '\0', sizeof(struct sockaddr_in));

    sin->sin_family = family;
    sin->sin_port = htons(port_num);
    inet_pton(family, ip_address, &sin->sin_addr);
}

void CreateRealArpHeader(struct iphdr *ip, unsigned int protocol,
                    char *destination)
{
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;//NETWORK_CONTROL;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip->id = htons(12345);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = protocol;
    ip->check = 0;
    ip->saddr = 0;
    ip->daddr = 0;

    inet_pton(AF_INET, destination, &ip->daddr);
}

void CreateEchoICMP(struct icmp_hdr *icmp) {
    icmp->message_type = ICMP_ECHO;
    icmp->sub_code = 0;
    icmp->un.echo.process_id = getpid();
    icmp->un.echo.sequence = htons(1);
}

int SendEchoPacket(int sockfd, struct sockaddr_in *sin,
        const char *pkt, unsigned int payloadsize) {
    struct icmp_hdr *icmp;
    icmp = pkt + sizeof(struct ip_hdr);

    icmp->checksum = 0;
    icmp->checksum = in_cksum((unsigned short *)icmp,
        sizeof(struct icmp_hdr) + payloadsize);

    if(sendto(sockfd, pkt, 64, 0, (const struct sockaddr *)sin,
            sizeof(struct sockaddr_in)) < 1) {
        fprintf(stderr, "Failed to send packet...\n");
        return -1;
    }

    printf("Packet Sent...\n");
    //fflush(stdout);

    return 0;
}

void CreateArpHeader(struct iphdr *ip, unsigned int protocol,
                     char *destination)
{
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = NETWORK_CONTROL;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip->id = htons(12345);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = protocol;
    ip->check = 0;
    ip->saddr = inet_addr("10.15.46.123");
    ip->daddr = 0;

    inet_pton(AF_INET, destination, &ip->daddr);
}

void CreateTcpHeader(struct tcphdr *tcph, int port)
{
    tcph->source = htons(1234);
    tcph->dest = htons(port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5; /* first and only tcp segment */
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 1;
    tcph->window = htons(5840); /* maximum allowed window size */
    tcph->check = 0;            /* if you set a checksum to zero, your kernel's IP stack
				should fill in the correct checksum during transmission */
    tcph->urg_ptr = 0;
}

void ProcessPacket(char *szBuffer, int len)
{
    DecodeEthr(szBuffer);
    DecodeIp(szBuffer + ETH_HDRHLEN);
    DecodeTcp(szBuffer + ETH_HDRHLEN + sizeof(struct iphdr));

    dump(szBuffer, len);
}

void pcap_fatal(const char *failed_in, const char *errbuf)
{
    printf("Fatal Error in %s: %s\n", failed_in, errbuf);
    exit(1);
}

#endif

/*
SPOOFING - Matthew T. Geiger
In a switched networking environment each computer is
given access to a specific port controlled by the switch.
This makes it more difficult to sniff information because
the switch will not allow you to receive another computers
packet by default.

A way to work around this is with spoofing.

Because most machines assume that the source address is correct,
couldn't you send a theoretical packet of information with the
source address modified to be yours so the switch sends you the
packets instead?

By designing a packet containing your mac address instead of the target's
mac address you would be able to trick the router to send you the
target's packets. From there you could craft a packet imitating the
router that could be sent back to the target without the target
even noticing this potentially dangerous situation

Basic Switched Network Diagram
-------------------------------
    HACKER  TARGET
       \      /
        Switch
          |
      ----------
      | Router |
      ----------

Some non complicated steps
1. The hacker responds to router with spoofed packet when requesting
for the target computers mac address. (Optionally send an imitated
reset request ARP Reply to router; discussed later)
2. The hacker then sends a packet to the target imitating the router
to complete the cycle of information

By this point the hackers computer is essentially a network proxy
allowing stealth sniffing and modification of packets

Remember to keep the connection active by transmitting and receiving
packets from both the target and router.

Side Note: A host will accept an ARP reply message.

If you are looking for information not covered in this document, feel
free to wait for the premier.

---------------------------->
ARP Poisoning?

If you already understand RFC 791(Ethernet Proto) then you probably
remember that RFC 791 has a TTL(Time To Live) value which controls
how long a packet of information remains on a network.
To make sure that the router does not attempt to re-acquire the
targets true mac address after the TTL runs out; ARP Poisoning is
required to maintain a spoofed connection between the hacker, router,
and target.

To achieve a reliable active spoof the hacker must send imitation
ARP replies periodically(About every 10 seconds) to the target.
After the fake ARP reply is transmitted remember to communicate this
with the router so the TTL is freed/re-cached from the router's memory.
----------------------------->
Future Projects?
If you understand basic routing you know that a gateway is an IP
address provided by the router that is used for communicating to
the world wide web. Maybe that would be fun to play around with?

The point is:
1. Read up on RFC 791, 793, and 826
2. Start experimenting
3. Get ready for part 2 of the socket series

PS: Everyone let Rake know that pee is stored in the balls
*/                                      
