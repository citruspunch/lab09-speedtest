#include "ip_header.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

static uint16_t ip_id_counter = 12345;

void build_ip_header(ip_header_t *iph, const char *src_ip, const char *dst_ip,
                      uint16_t payload_len) {
    memset(iph, 0, sizeof(ip_header_t));

    iph->ihl_version = (4 << 4) | 5;  /* IPv4, header length 5 * 4 = 20 bytes */
    iph->tos         = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    /*
     * BSD / Darwin raw sockets with IP_HDRINCL expect ip_len (total_length)
     * and ip_off (flags_fo) in host byte order.
     */
    iph->total_length = (uint16_t)(sizeof(ip_header_t) + payload_len);
    iph->flags_fo     = 0x4000; /* Don't Fragment flag */
#else
    /* Linux expects network byte order */
    iph->total_length = htons((uint16_t)(sizeof(ip_header_t) + payload_len));
    iph->flags_fo     = htons(0x4000); /* Don't Fragment flag */
#endif

    iph->id        = htons(ip_id_counter++);
    iph->ttl       = 64;
    iph->protocol  = IPPROTO_TCP; /* 6 */
    iph->checksum  = 0;            /* Calculated later by caller */
    iph->src_addr  = inet_addr(src_ip);
    iph->dst_addr  = inet_addr(dst_ip);
}
