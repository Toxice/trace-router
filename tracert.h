#ifndef TRACERT_H
#define TRACERT_H

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

/**
 * @brief Traceroute packet structure containing IP and ICMP headers
 * @details This structure is packed to ensure proper memory layout for raw socket transmission
 */
typedef struct _tracert_packet {
    struct iphdr ip_header;      /**< IP header for the packet */
    struct icmphdr icmp_payload; /**< ICMP payload (echo request) */
} __attribute__((packed)) traceret_packet;

// max hop parameter
#define MAX_HOP 30

// value of ip protocol field of ICMP
#define IP_PROTOCOL_ICMP 1

// ICMP ECHo type & code
#define ECHOREPLY_TYPE 0
#define ECHOREPLY_CODE 0

#define ICMP_ECHO_TYPE 8
#define ICMP_ECHO_CODE 0

// ICMP time exceed message type & code
#define TIMEXCEED_TYPE 11
#define TIMEXCEED_CODE 0

#define BUFFER_SIZE 1024

#define TIMEOUT 1000

#define IP_STR_LENGTH 16 // total length of IP address (3 digits per point, plus 3 points plus the '/0' sign)

#define DEST_REACHED 1
#define TIMEXCEED_REACHED 0

#define PROBES_PER_HOP 3  // Number of probes sent per TTL value

/**
 * @brief Setting up the sockaddr_in structure with destination IP
 * @details Configures the socket address structure for the destination host
 * 
 * @param ip_addr String representation of the IP address
 * @param dest_address Pointer to sockaddr_in structure to be configured
 */
void set_sockaddr_in(char *ip_addr, struct sockaddr_in *dest_address);

/**
 * @brief Setting the traceroute packet with the desired TTL value
 * @details Constructs a complete ICMP echo request packet with IP header,
 *          calculating checksums and setting appropriate fields
 * 
 * @param packet Pointer to the packet structure to be configured
 * @param ttl Time-to-live value for this packet
 */
void set_packet(traceret_packet *packet, int ttl);

#endif