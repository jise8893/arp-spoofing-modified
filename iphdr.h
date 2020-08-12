#include <cstdint>
#include <arpa/inet.h>
#ifndef IPHDR_H
#define IPHDR_H

#endif // IPHDR_H
struct IpHdr final {
    uint8_t ip_hl:4,ip_v:4;
    uint8_t tos;
    uint16_t ip_len;         /* total length */
    uint16_t ip_id;          /* identification */
    uint16_t ip_off;

    uint8_t ip_ttl;          /* time to live */
    uint8_t ip_p;            /* protocol */
    uint16_t ip_sum;
    uint32_t ip_src;
    uint32_t ip_dst;
};
