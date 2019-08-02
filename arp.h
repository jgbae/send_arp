#pragma once
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <pcap.h>

#define ARP_PACKET_SIZE 42
#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02

typedef struct ARP_Packet
{
    //ETHERNET
    uint8_t eth_dst[6];
    uint8_t eth_src[6];
    uint16_t eth_type;

    //ARP
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t hardAddLen;
    uint8_t protoAddLen;
    uint16_t operationCode;
    uint8_t srcMACAddr[6];
    uint8_t srcProtocolAddr[4];
    uint8_t dstMACAddr[6];
    uint8_t dstProtocolAddr[4];
} ARP_Packet;

typedef struct AddressInfo
{
    char* interface;
    uint32_t senderIp;
    uint32_t targetIp;
    uint8_t senderMac[6];
    uint8_t hostMac[6];
} AddressInfo;

void usage();
int GetSvrMacAddress(char *interface, uint8_t *macAddr);
void print_mac(const char *msg, uint8_t* mac);
int GetTargetMacAddress(AddressInfo *addressinfo);
void SetARPPacket(ARP_Packet *packet, uint16_t opcode, AddressInfo *addressinfo);
void attack(AddressInfo *addressinfo);
