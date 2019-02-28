#include "network.h"

char address[32] = "127.0.0.1"; 

int main(int argc, char *argv[])
{
    if(argc > 1)
        strcpy(address, (const char *)argv[1]);

    char packet[64];
    struct ip_hdr ip;
    struct icmp_hdr icmp;
    struct sockaddr_in sin;
    int sockfd, sockfdr;

    memset(&ip, '\0', sizeof(struct ip_hdr));
    memset(&icmp, '\0', sizeof(struct icmp_hdr));

    CreateSockaddr(&sin, 0, AF_INET, address);

    // 1. Establish a socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    sockfdr = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sockfd < 0)
    {
        fprintf(stderr, "Failed to create socket...\n");
        exit(EXIT_FAILURE);
    }

    printf("Socket Initalized...\n");

    // Create our own ip header
    int on = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL,
                   (const char *)&on, sizeof(on)) == -1)
    {
        fprintf(stderr, "Failed to set ip header options\n");
        exit(EXIT_FAILURE);
    }

    // Allow socket to send datagrams
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST,
                   (const char *)&on, sizeof(on)) == -1)
    {
        fprintf(stderr, "Failed to set up socket options\n");
        exit(EXIT_FAILURE);
    }

    printf("Socket options set completed\n");

    // 2. Create ICMP echo request
    CreateRealArpHeader((struct iphdr *)&ip, IPPROTO_ICMP, address);
    CreateEchoICMP(&icmp);

    // Find lengths
    int iplen = sizeof(struct iphdr);
    int icmplen = sizeof(struct icmp_hdr);
    int totlen = iplen + icmplen;

    printf("Total packet size(IP + ICMP): %d\n", totlen);

    // Compile packet
    memcpy(packet, &ip, iplen);
    memcpy(packet + iplen, &icmp, icmplen);

    memset(packet + totlen, '\x90', 64 - totlen);

    printf("Packet Created: \n");
    dump(packet, 64);
    printf("\n");

    // 3. Send packet to target

    if (SendEchoPacket(sockfd, &sin, (const char *)packet, 64 - totlen) != 0)
    {
        fprintf(stderr, "Failed to send packet\n");
        exit(EXIT_FAILURE);
    }

    // 4. Wait for response
    //sleep(1);

    char RecvBuffer[256];
    socklen_t socklen = sizeof(sin);
    int ret;

    // Recieve data
    ret = recvfrom(sockfdr, RecvBuffer, 256, 0,
        (struct sockaddr *)&sin, &socklen);
    if(ret < 0)
    {
        fprintf(stderr, "Server did not respond...\n");
        exit(EXIT_FAILURE);
    }

    printf("Packet Recieved!\n\n");

    dump(RecvBuffer, ret);
    DecodeEthr(RecvBuffer);

    printf("Mac Finder Complete!\n");

    // 6. Clean up/Exit
    close(sockfd);
    close(sockfdr);
    exit(EXIT_SUCCESS);
}