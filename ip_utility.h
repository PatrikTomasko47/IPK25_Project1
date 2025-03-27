/**
 * @file ip_utility.h
 * @brief Contains functions used to work with interfaces and string to ip conversions.
 *
 *
 * @author Patrik Tomasko (xtomasp00)
 * @date 2025-03-27
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>

/**
 * @brief Prints all the interfaces of the system.
 * 
 * @return true in case of success, false in case of failure.
 */
bool print_available_interfaces();

/**
 * @brief Converts the string containing the source_ip to uint32_t or struct in6_addr.
 * 
 * @param interface The string containing the source IP.
 * @param return_pointer The pointer to which the IP will get copied.
 * @param ipv6_mode Determines wether the given IP is IPv6 or IPv4.
 * 
 * @return true in case of success, false in case of failure.
 */
bool convert_source_ip(char* interface, void* return_pointer, bool ipv6_mode);

/**
 * @brief Looks up the IPs of the given domain and scans them.
 * 
 * @param domain String containing the domain.
 * @param tcp_ports TCP ports to scan.
 * @param udp_ports UDP ports to scan.
 * @param timeout Determines the time after which another packet will get send (TCP)/the port will be declared as open (UDP).
 * @param source_ipv4 Source IPv4, could be set to zero if the interface doesn't have a suitable IPv4.
 * @param source_ipv4 Source IPv6, could be set to zero if the interface doesn't have a suitable IPv6.
 * 
 * @return true in case of success, false in case of failure.
 */
bool iterate_domain_ips(char* domain, int* tcp_ports, int* udp_ports, int timeout, uint32_t source_ipv4, struct in6_addr source_ipv6);