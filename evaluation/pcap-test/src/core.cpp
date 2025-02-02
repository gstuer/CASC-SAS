#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <format>
#include <print>
#include <sstream>
#include <string>

using namespace std;

string parseEthernetAddress(uint8_t host[ETHER_ADDR_LEN]) {
    // Parse ethernet host address (from ETHER_ADDR_LEN long hex array) into typical x:x:x:x:x:x form
    stringstream stream;
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        if (i == 0) {
            stream << std::hex << static_cast<int>(host[i]);
        } else {
            stream << ":" << std::hex << static_cast<int>(host[i]);
        }
    }
    return stream.str();
}

void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Get ethernet header from packet
    struct ether_header *ethernetHeader;
    ethernetHeader = (struct ether_header *) packet;

    // Get layer-2 hosts and ethertype from header
    string ethernetSource = parseEthernetAddress(ethernetHeader->ether_shost);
    string ethernetDestination = parseEthernetAddress(ethernetHeader->ether_dhost);
    uint16_t etherType = ntohs(ethernetHeader->ether_type);

    printf("Captured packet: Length %d\n", header->len);
    if (etherType == ETHERTYPE_IP) {
        printf("Ethernet type hex:%x dec:%d is an IPv4 packet\n", etherType, etherType);
    } else if (etherType == ETHERTYPE_IPV6) {
        printf("Ethernet type hex:%x dec:%d is an IPv6 packet\n", etherType, etherType);
    } else if (etherType == ETHERTYPE_ARP) {
        printf("Ethernet type hex:%x dec:%d is an ARP packet\n", etherType, etherType);
    } else {
        printf("Ethernet type hex:%x dec:%d not known\n", etherType, etherType);
    }
    print("{} -> {}\n", ethernetSource, ethernetDestination);
}

int main(int argc, char **argv) {
    char errorBuffer[PCAP_ERRBUF_SIZE];

    // Get network interface name either from arguments or use default interface
    char *networkInterface;
    if (argc >= 2) {
        networkInterface = argv[1];
    } else {
        networkInterface = pcap_lookupdev(errorBuffer);
        if(networkInterface == NULL) {
            printf("%s\n", errorBuffer);
            return(1);
        }
    }

    // Create pcap handle and check if creation was successful
    pcap_t *handle;
    handle = pcap_create(networkInterface, errorBuffer);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't create device %s: %s\n", networkInterface, errorBuffer);
        return(1);
    }

    // Set pcap handle to promiscuous (see all packets) and immediate mode (packets delivered w/o buffering)
    pcap_set_snaplen(handle, BUFSIZ);
    pcap_set_timeout(handle, 0);
    pcap_set_promisc(handle, 1);
    int immediate = pcap_set_immediate_mode(handle, 1);
    if (immediate != 0) {
        fprintf(stderr, "Couldn't not set immediate mode for %s\n", networkInterface);
        return(1);
    }

    // Activate pcap handle (i.e., start sniffing session)
    if (pcap_activate(handle) != 0) {
        fprintf(stderr, "Couldn't activate device %s: %s\n", networkInterface, errorBuffer);
        return(1);
    }
    printf("Start sniffing interface %s\n", networkInterface);

    // Forward all received packets to handler function
    pcap_loop(handle, -1, processPacket, NULL);

    printf("Stop sniffing interface %s\n", networkInterface);
    return 0;
}
