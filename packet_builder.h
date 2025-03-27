/**
 * @file packet_builder.h
 * @brief Assembles the packets, including the checksum calculations.
 *
 *
 * @author Patrik Tomasko (xtomasp00)
 * @date 2025-03-27
 */

#include <stdbool.h>
#include <stdint.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define SOURCE_PORT 50000 //source port, it is in the ephemeral port range, and i just decided for it because it was nice

struct pseudo_header_ipv4{
    uint32_t source_ip;
    uint32_t destination_ip;
    uint8_t zero;
    uint8_t protocol;
    uint16_t udp_tcp_length;
};

struct pseudo_header_ipv6{
    uint8_t source_ip[16];
    uint8_t destination_ip[16];
    uint8_t zero;
    uint8_t protocol;
    uint16_t udp_tcp_length;
};

/**
 * @brief Calculates the checksum from the provided data buffer
 *
 * @param data Points to the pseudo header + TCP/UDP header
 * @param length Length of the data, since the function is universal across IPV6/IPV4 and UDP/TCP
 * 
 * @return Checksum calculation out of the provided data.
 */
uint16_t sum_calculator(void *data, int length);

/**
 * @brief Creates the UDP pseudo header and uses the sum_calculator to calculate the checksum
 *
 * @param source_ip
 * @param dest_ip
 * @param udp_header
 * @param udp_length
 * @param ipv6_mode Determines wether the IPs are IPv6 or IPv4.
 * 
 * @return Checksum calculation result.
 */
uint16_t udp_checksum(void* source_ip, void* dest_ip, struct udphdr* udp_header, int udp_length, bool ipv6_mode);

/**
 * @brief Creates the TCP pseudo header and uses the sum_calculator to calculate the checksum
 *
 * @param source_ip
 * @param dest_ip
 * @param tcp_header
 * @param tcp_length
 * @param ipv6_mode Determines wether the IPs are IPv6 or IPv4.
 * 
 * @return Checksum calculation result.
 */
uint16_t tcp_checksum(void* source_ip, void* dest_ip, struct tcphdr* tcp_header, int tcp_length, bool ipv6_mode);

/**
 * @brief Constructs the TCP header and fills it up with given data and other calculations like checksum.
 *
 * @param target_ip
 * @param destination_port
 * @param header Pointer through which the header is "given back" to the caller.
 * @param ipv6_mode
 * @param source_ip
 */
void construct_tcp_header(void* target_ip, uint16_t destination_port, struct tcphdr* header, bool ipv6_mode, void* source_ip);

/**
 * @brief Constructs the UDP header and fills it up with given data and other calculations like checksum.
 *
 * @param target_ip
 * @param destination_port
 * @param header Pointer through which the header is "given back" to the caller.
 * @param ipv6_mode
 * @param source_ip
 */
void construct_udp_header(void* target_ip, uint16_t destination_port, struct udphdr* header, bool ipv6_mode, void* source_ip);