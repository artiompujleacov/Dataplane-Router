#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len;

typedef struct {
    unsigned int len;
    char buff[MAX_PACKET_LEN];
    int interface;
    uint32_t route;
} packet_data;

int binarySearch(int left, int right, uint32_t dest, struct route_table_entry *rtable) {
    if (left <= right) {
        if (rtable[(left + right) / 2].prefix == (rtable[(left + right) / 2].mask & dest))
            return (left + right) / 2;
        else if (rtable[(left + right) / 2].prefix < (rtable[(left + right) / 2].mask & dest))
            binarySearch((left + right) / 2 + 1, right, dest, rtable);
        else
            binarySearch(left, (left + right) / 2 - 1, dest, rtable);
    }
    return -1;
}

struct route_table_entry *get_best_route(uint32_t dest, int rtable_len, struct route_table_entry *rtable) {
    struct route_table_entry *best_route = NULL;
    int idx = binarySearch(0, rtable_len, dest, rtable);
    for (int i = idx; i < rtable_len; i++) {
        int x = dest & rtable[i].mask;
        if (x == rtable[i].prefix) {
            if (best_route == NULL || (best_route->mask < rtable[i].mask))
                best_route = &rtable[i];
        }
    }
    return best_route;
}

int compare(const void *a, const void *b) {
    struct route_table_entry *a1 = (struct route_table_entry *)a;
    struct route_table_entry *a2 = (struct route_table_entry *)b;
    return a1->prefix != a2->prefix ? a2->prefix - a1->prefix : a2->mask - a1->mask;
}

struct arp_table_entry *get_arp_table_entry(uint32_t dest_ip, int arp_len) {
    for (int i = 0; i < arp_len; i++) {
        if (arp_table[i].ip == dest_ip)
            return &arp_table[i];
    }
    return NULL;
}

void create_and_send_icmp_packet(char *buf, struct ether_header *eth_hdr, struct iphdr *ip_hdr, int type, int interface) {
    char buff2[MAX_PACKET_LEN];
    memcpy(buff2, buf, MAX_PACKET_LEN);

    struct ether_header *new_eth_hdr = (struct ether_header *)buff2;
    struct iphdr *new_ip_hdr = (struct iphdr *)(buff2 + sizeof(struct ether_header));
    struct icmphdr *new_icmp_hdr = (struct icmphdr *)(buff2 + sizeof(struct ether_header) + sizeof(struct iphdr));

    memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, 8);
    memcpy(new_eth_hdr->ether_shost, eth_hdr->ether_dhost, 8);
    new_eth_hdr->ether_type = eth_hdr->ether_type;

    new_ip_hdr->daddr = ip_hdr->saddr;
    new_ip_hdr->saddr = ip_hdr->daddr;
    new_ip_hdr->protocol = IPPROTO_ICMP;
    new_ip_hdr->ttl = 64;
    new_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

    new_icmp_hdr->type = type;
    new_icmp_hdr->code = 0;
    new_icmp_hdr->checksum = 0;
    new_icmp_hdr->checksum = checksum((uint16_t *)new_icmp_hdr, sizeof(struct icmphdr));
    new_icmp_hdr->checksum = htons(new_icmp_hdr->checksum);
    size_t new_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

    send_to_link(interface, buff2, new_len);
}

int main(int argc, char *argv[]) {
    char buf[MAX_PACKET_LEN];

    init(argc - 2, argv + 2);

    rtable = (struct route_table_entry *)malloc(sizeof(struct route_table_entry) * 100000);
    rtable_len = read_rtable(argv[1], rtable);
    arp_table_len = 10;
    arp_table = (struct arp_table_entry *)malloc(sizeof(struct arp_table_entry) * arp_table_len);
    int arp_len = 0;
    qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare);
    queue q = queue_create();

    while (1) {
        int interface;
        size_t len;
        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        struct ether_header *eth_hdr = (struct ether_header *)buf;

        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
            struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
		    uint16_t old_checksum = ip_hdr->check;
            ip_hdr->check = 0;
            uint16_t new = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
            ip_hdr->check = htons(new);
            if (old_checksum != ip_hdr->check) {
                continue;
            }
            if (ip_hdr->ttl <= 1) {
                create_and_send_icmp_packet(buf, eth_hdr, ip_hdr, 11, interface);
                continue;
            }
            struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
            
            if (ip_hdr->daddr == inet_addr(get_interface_ip(interface)) && icmp_hdr->type == 8) {
                create_and_send_icmp_packet(buf, eth_hdr, ip_hdr, 0, interface);
                continue;
            }

            struct route_table_entry *route = get_best_route(ip_hdr->daddr, rtable_len, rtable);

            if (route == NULL) {
                create_and_send_icmp_packet(buf, eth_hdr, ip_hdr, 3, interface);
                continue;
            }

            ip_hdr->ttl--;
            ip_hdr->check = 0;
            ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
            ip_hdr->check = htons(ip_hdr->check);

            struct arp_table_entry *arp = get_arp_table_entry(route->next_hop,arp_len);
            if (arp == NULL) {
                packet_data *p = (packet_data *)malloc(sizeof(packet_data));
                p->interface = route->interface;
                p->len = len;
                p->route = route->next_hop;
                memcpy(p->buff, &buf, MAX_PACKET_LEN * sizeof(char));
                queue_enq(q, p);

                size_t new_len = sizeof(struct ether_header) + sizeof(struct arp_header);

                char buff2[MAX_PACKET_LEN];

                struct ether_header *eth_header = (struct ether_header *)malloc(sizeof(struct ether_header));

                uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

                memcpy(eth_header->ether_dhost, broadcast, 6);

                get_interface_mac(route->interface, eth_header->ether_shost);

                eth_header->ether_type = htons(ETHERTYPE_ARP);

                struct arp_header *arp_hdr = (struct arp_header *)malloc(sizeof(struct arp_header));
                arp_hdr->htype = htons(1);
                arp_hdr->ptype = htons(0x0800);
                arp_hdr->hlen = 6;
                arp_hdr->plen = 4;
                arp_hdr->op = htons(1);

                get_interface_mac(route->interface, arp_hdr->sha);
                arp_hdr->spa = inet_addr(get_interface_ip(route->interface));

                memcpy(arp_hdr->tha, broadcast, 8);
                arp_hdr->tpa = route->next_hop;

                memcpy(buff2, eth_header, sizeof(struct ether_header));
                memcpy(buff2 + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));

                send_to_link(route->interface, buff2, new_len);
                continue;
            }

            memcpy(eth_hdr->ether_dhost, arp->mac, 8);
            get_interface_mac(interface, eth_hdr->ether_shost);
            send_to_link(route->interface, buf, len);
        }
        else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
            struct arp_header *arp_hdr = ((void*)(struct ether_header *)buf + sizeof(struct ether_header));

            if (ntohs(arp_hdr->op) == 1) {

                if (arp_hdr->tpa != inet_addr(get_interface_ip(interface)))
                    continue;

                size_t new_len = sizeof(struct ether_header) + sizeof(struct arp_header);
                char buff2[MAX_PACKET_LEN];
                memcpy(buff2, buf, MAX_PACKET_LEN);

                struct ether_header *new_eth_hdr = (struct ether_header *)buff2;
                struct arp_header *arph_reply = (struct arp_header *)(buff2 + sizeof(struct ether_header));

                arph_reply->op = htons(2);
                arph_reply->spa = arp_hdr->tpa;
                arph_reply->tpa = arp_hdr->spa;

                memcpy(arph_reply->tha, arp_hdr->sha, 8);

                get_interface_mac(interface, arph_reply->sha);

                memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, 8);

                get_interface_mac(interface, new_eth_hdr->ether_shost);

                send_to_link(interface, buff2, new_len);
                continue;
            }
            else if (ntohs(arp_hdr->op) == 2) {

                if (arp_hdr->tpa != inet_addr(get_interface_ip(interface)))
                    continue;

                arp_table[arp_len].ip = arp_hdr->spa;
                memcpy(arp_table[arp_len].mac, arp_hdr->sha, 8);
                arp_len++;

                if (arp_len == arp_table_len) {
                    arp_table = realloc(arp_table, 2*arp_table_len);
                    arp_table_len = arp_table_len * 2;
                }

                while (!queue_empty(q)) {

                    packet_data *p = (packet_data *)malloc(sizeof(packet_data));
                    p = (packet_data *)queue_deq(q);

                    struct ether_header *packet_eth = (struct ether_header *)p->buff;

                    struct arp_table_entry *arp = get_arp_table_entry(p->route,arp_len);

                    if (arp == NULL) {
                        queue_enq(q, p);
                        break;
                    }

                    memcpy(packet_eth->ether_dhost, arp->mac, 8);

                    send_to_link(p->interface, p->buff, p->len);
                    free(p);
                }
                continue;
            }
        }
    }
}