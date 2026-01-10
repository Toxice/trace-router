#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <sys/time.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/mman.h>
#include "tracert.h"

extern char *optarg;

char *ip_address = NULL;

struct sockaddr_in dest_address;

/**
 * @brief Shared memory structure for inter-process communication
 * @details Used to coordinate between sender and listener processes,
 *          tracking destination status, timing, and probe progress
 */
typedef struct {
    int is_dest;                        /**< Flag indicating if destination has been reached */
    struct timeval time_sent[3];        /**< Timestamps for each of the 3 probes per TTL */
    int current_ttl;                    /**< Current TTL value being tested */
    int current_probe;                  /**< Current probe number (0-2) for this TTL */
    int packets_received_for_probe[3];  /**< Track if each probe received a response */
    int sender_done;                    /**< Flag indicating sender has finished sending all packets */
} dest_flag;

dest_flag *dest_instance;

int sock_send;
int sock_recv;
int sock_opt_send;

int counter = 1;

/**
 * @brief Calculate checksum for ICMP header
 * @details Computes the Internet Checksum (RFC 1071) for the given buffer
 * 
 * @param b Pointer to the buffer to checksum
 * @param len Length of the buffer in bytes
 * @return Calculated checksum value
 */
unsigned short checksum(void *b, int len) {
    uint16_t *buffer = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len = len - 2) {
        sum = sum + (*buffer);
        buffer++;
    }

    if (len == 1) {
        sum += *(uint8_t*)buffer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

/**
 * @brief Validate and classify received ICMP packet
 * @details Determines if the packet is a time exceeded message or echo reply
 * 
 * @param ip_header Pointer to the IP header of the received packet
 * @return DEST_REACHED if echo reply, TIMEXCEED_REACHED if time exceeded, -1 for other types
 */
int handle_packet(struct iphdr *ip_header) {
    struct icmphdr *icmp_header = (struct icmphdr*)((char*)ip_header + ip_header->ihl * 4);

    if (icmp_header->type == TIMEXCEED_TYPE && icmp_header->code == TIMEXCEED_CODE) {
        return TIMEXCEED_REACHED; // 0 (FALSE)
    } else if (icmp_header->type == ECHOREPLY_TYPE && icmp_header->code == ECHOREPLY_CODE) {
        return DEST_REACHED; // 1 (TRUE)
    }
    
    // Return error code for unexpected packet types
    return -1;
}

/**
 * @brief Process and display received packet information
 * @details Extracts timing information, validates checksums, and prints RTT for the probe
 * 
 * @param buffer Buffer containing the received packet
 * @param bytes Number of bytes received
 * @param probe_num Probe number (0-2) for this TTL
 */
void display(char *buffer, int bytes, int probe_num) {
    char src_addr[IP_STR_LENGTH];

    struct timeval recv_time;
    struct timeval sent_time;

    memset(&recv_time, 0, sizeof(struct timeval));
    memset(&sent_time, 0, sizeof(struct timeval));

    // get the time where the packet was sent for this specific probe
    memcpy(&sent_time, &(dest_instance->time_sent[probe_num]), sizeof(struct timeval));

    struct iphdr *ip_header = (struct iphdr*)buffer;

    inet_ntop(AF_INET, &(ip_header->saddr), src_addr, IP_STR_LENGTH);

    // if we got an ECHO REPLY
    int packet_type = handle_packet(ip_header);
    if (packet_type == DEST_REACHED) {
        // validate we got the same IP address as the desired destination
        if (strcmp(src_addr, ip_address) == 0) {
            dest_instance->is_dest = DEST_REACHED;
        }  
    } else if (packet_type == -1) {
        // Unexpected packet type, ignore
        return;
    }

    if (bytes < ip_header->ihl * 4 + (int)sizeof(struct icmphdr))
        return;

    int ip_header_length = ip_header->ihl * 4;
            
    struct icmphdr *icmp_header = (struct icmphdr*)(buffer + ip_header->ihl * 4);

    if (bytes - ip_header_length < 8) 
        return;

    int icmp_header_length = bytes - ip_header_length;

    // validating icmp checksum 
    if (checksum(icmp_header, icmp_header_length) != 0) {
        fprintf(stderr, "Warning: Invalid ICMP checksum\n");
        return;
    }

    // get the current time, the time when we received the packet
    gettimeofday(&recv_time, NULL);

    // Calculate RTT in milliseconds
    double rtt = (recv_time.tv_sec - sent_time.tv_sec) * 1000.0 + 
                 (recv_time.tv_usec - sent_time.tv_usec) / 1000.0;

    // Mark this probe as received
    dest_instance->packets_received_for_probe[probe_num] = 1;

    // Print hop number and IP only for first probe
    if (probe_num == 0) {
        printf("%d  %s  %.3f ms", dest_instance->current_ttl, src_addr, rtt);
    } else {
        printf("  %.3f ms", rtt);
    }
    
    // Print newline after third probe
    if (probe_num == 2) {
        printf("\n");
    }
    
    fflush(stdout);
}

/**
 * @brief Listener process that receives and processes ICMP packets
 * @details Continuously monitors for incoming packets, handling timeouts and
 *          processing responses from intermediate routers and the destination
 */
void listener() {
    struct sockaddr_in addr;
    unsigned char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(dest_address);

    struct pollfd fds[1];
    fds[0].fd = sock_recv;
    fds[0].events = POLLIN;

    int last_ttl_processed = 0;
    int last_probe_processed = -1;

    // Continue listening until sender is done AND we've processed all packets
    while (1) {
        int current_ttl = dest_instance->current_ttl;
        int current_probe = dest_instance->current_probe;
        
        // Check if we should exit: sender done AND we've processed everything
        if (dest_instance->sender_done && 
            current_ttl == last_ttl_processed && 
            current_probe == last_probe_processed) {
            break;
        }

        // Skip if we haven't moved to a new probe yet
        if (current_ttl == 0 || 
            (current_ttl == last_ttl_processed && current_probe == last_probe_processed)) {
            usleep(10000); // Sleep 10ms to avoid busy waiting
            continue;
        }

        int poll_result = poll(fds, 1, TIMEOUT);

        if (poll_result == 0) {
            // Timeout occurred
            if (current_probe == 0) {
                printf("%d  *", current_ttl);
            } else {
                printf("  *");
            }
            
            if (current_probe == 2) {
                printf("\n");
            }
            
            fflush(stdout);
            last_ttl_processed = current_ttl;
            last_probe_processed = current_probe;
            continue;
        } else if (poll_result < 0) {
            perror("poll error");
            last_ttl_processed = current_ttl;
            last_probe_processed = current_probe;
            continue;
        }

        memset(buffer, 0, sizeof(buffer));

        int bytes = recvfrom(sock_recv, buffer, sizeof(buffer), 0, 
                            (struct sockaddr*)&addr, &addr_len);

        if (bytes < 0) {
            perror("recvfrom error");
            continue;
        }

        if (bytes < (ssize_t)sizeof(struct iphdr))
            continue;

        display(buffer, bytes, current_probe);
        last_ttl_processed = current_ttl;
        last_probe_processed = current_probe;
    }
}

/**
 * @brief Setting up the sockaddr_in structure with destination IP
 * @details Configures the socket address structure for the destination host
 * 
 * @param ip_addr String representation of the IP address
 * @param dest_address Pointer to sockaddr_in structure to be configured
 */
void set_sockaddr_in(char *ip_addr, struct sockaddr_in *dest_address) {
    memset(dest_address, 0, sizeof(*dest_address));
    dest_address->sin_family = AF_INET;
    dest_address->sin_port = 0;
    if (inet_pton(AF_INET, ip_addr, &dest_address->sin_addr) <= 0) {
        perror("invalid IP Address");
        exit(EXIT_FAILURE);    
    }
}

/**
 * @brief Setting the traceroute packet with the desired TTL value
 * @details Constructs a complete ICMP echo request packet with IP header,
 *          calculating checksums and setting appropriate fields
 * 
 * @param packet Pointer to the packet structure to be configured
 * @param ttl Time-to-live value for this packet
 */
void set_packet(traceret_packet *packet, int ttl) {
    memset(packet, 0, sizeof(traceret_packet));

    int ip_flag = inet_pton(AF_INET, ip_address, &(packet->ip_header.daddr));
    if (ip_flag <= 0) {
        perror("Invalid IP Address");
        exit(EXIT_FAILURE);
    }

    // setting the ip header
    packet->ip_header.version = 4;
    packet->ip_header.tos = 0;
    packet->ip_header.protocol = IP_PROTOCOL_ICMP;
    packet->ip_header.id = htons(getpid() + ttl);
    packet->ip_header.ttl = ttl;
    packet->ip_header.frag_off = htons(0);
    packet->ip_header.saddr = 0;
    packet->ip_header.ihl = 5;

    // setting the icmp payload
    memset(&(packet->icmp_payload), 0, sizeof(struct icmphdr));
    packet->icmp_payload.type = ICMP_ECHO_TYPE;
    packet->icmp_payload.code = ICMP_ECHO_CODE;
    packet->icmp_payload.un.echo.id = getpid();
    packet->icmp_payload.un.echo.sequence = htons(ttl);

    // setting the checksum
    packet->icmp_payload.checksum = 0;
    packet->icmp_payload.checksum = checksum(&(packet->icmp_payload), sizeof(struct icmphdr));

    // setting the total length of the header
    packet->ip_header.tot_len = sizeof(traceret_packet);
    packet->ip_header.check = 0;
}

/**
 * @brief Send 3 probe packets for a given TTL value
 * @details Sends three ICMP echo requests with the specified TTL,
 *          recording timestamp for each probe and updating shared state
 * 
 * @param address Destination socket address
 * @param ttl Time-to-live value for the packets
 */
void send_packet(struct sockaddr_in address, int ttl) {
    traceret_packet packet;

    set_packet(&packet, ttl);
    
    // Reset probe received flags
    for (int i = 0; i < 3; i++) {
        dest_instance->packets_received_for_probe[i] = 0;
    }
    
    // Send 3 probes for this TTL
    for (int probe = 0; probe < 3; probe++) {
        // Update shared state for this probe
        dest_instance->current_ttl = ttl;
        dest_instance->current_probe = probe;
        gettimeofday(&(dest_instance->time_sent[probe]), NULL);
        
        if (sendto(sock_send, &packet, sizeof(packet), 0, 
                  (struct sockaddr*)(&address), sizeof(address)) <= 0) {
            perror("sendto");
        }
        
        // Small delay between probes
        usleep(100000); // 100ms between probes
    }
}

/**
 * @brief Main traceroute loop that sends packets with increasing TTL
 * @details Iteratively sends probe packets with increasing TTL values until
 *          either the destination is reached or MAX_HOP is exceeded.
 *          Ensures all 3 probes are sent even when destination is reached.
 * 
 * @param dst_addr Destination socket address structure
 */
void trace_route_to(struct sockaddr_in dst_addr) {
    while (counter <= MAX_HOP) {
        send_packet(dst_addr, counter);
        
        // Check if we reached destination AFTER sending all 3 probes
        if (dest_instance->is_dest == DEST_REACHED) {
            // We've reached the destination and sent all 3 packets
            // Wait a bit for the listener to process the last responses
            sleep(1);
            break;
        }
        
        sleep(1); // Wait 1 second before moving to next TTL
        ++counter;
    }
    
    // Signal to listener that sender is done
    dest_instance->sender_done = 1;
}

/**
 * @brief Cleanup function to release resources
 * @details Closes sockets and unmaps shared memory before program exit
 */
void cleanup() {
    if (sock_send >= 0) close(sock_send);
    if (sock_recv >= 0) close(sock_recv);
    if (dest_instance != MAP_FAILED) {
        munmap(dest_instance, sizeof(dest_flag));
    }
}

/**
 * @brief Main function - entry point of the traceroute program
 * @details Parses command line arguments, sets up sockets and shared memory,
 *          forks sender and listener processes, and coordinates traceroute execution
 * 
 * @param argc Argument count
 * @param argv Argument vector
 * @return Exit status code
 */
int main(int argc, char *argv[]) {
    int opt;

    while ((opt = getopt(argc, argv, "a:")) != -1) {
        switch (opt) {
            case 'a':
                ip_address = optarg;
                break;
            case '?':
                fprintf(stderr, "Usage: %s -a <address>\n", argv[0]);            
                exit(EXIT_FAILURE);  
        }
    }

    if (ip_address == NULL) {
        fprintf(stderr, "Usage: %s -a <address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    set_sockaddr_in(ip_address, &dest_address);

    dest_instance = mmap(NULL, sizeof(dest_flag), 
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (dest_instance == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }

    dest_instance->is_dest = 0;
    dest_instance->current_ttl = 0;
    dest_instance->current_probe = 0;
    dest_instance->sender_done = 0;
    for (int i = 0; i < 3; i++) {
        dest_instance->packets_received_for_probe[i] = 0;
    }

    sock_send = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock_send < 0) {
        perror("socket send (requires root privileges)");
        cleanup();
        exit(EXIT_FAILURE);
    }

    sock_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock_recv < 0) {
        perror("socket recv (requires root privileges)");
        cleanup();
        exit(EXIT_FAILURE);
    }

    const int on = 1;
    sock_opt_send = setsockopt(sock_send, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    if (sock_opt_send < 0) {
        perror("setsockopt");
        cleanup();
        exit(EXIT_FAILURE);
    }

    printf("traceroute to %s, %d hops max\n", ip_address, MAX_HOP);

    pid_t process_id = fork();

    if (process_id < 0) {
        perror("fork failed");
        cleanup();
        exit(EXIT_FAILURE);
    }

    if (process_id == 0) {
        // Child process - listener
        listener();
        cleanup();
        exit(EXIT_SUCCESS);
    } else {
        // Parent process - sender
        trace_route_to(dest_address);
        wait(NULL);
        cleanup();
    }

    return 0;
}