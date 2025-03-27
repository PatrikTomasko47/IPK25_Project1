/**
 * @file port_analyzer.h
 * @brief Sends the packets to the targets and analyzes the result.
 *
 *
 * @author Patrik Tomasko (xtomasp00)
 * @date 2025-03-27
 */

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

#define MAX_PORTS 65535 //maximum ammount of possible ports to scan through

/**
 * @brief Initializes a raw socket and returns it via the given pointer.
 *
 * @param protocol The protocol of the created socket.
 * @param socket_var The pointer via the socket's number will be returned.
 * @param ipv6_mode Determines wether to create an ipv4 or an ipv6 raw socket.
 * 
 * @return true if the socket was made, false if an error occured whilst initializing the socket.
 */
bool raw_socket_maker(int protocol, int* socket_var, bool ipv6_mode);

/**
 * @brief Checks wether the given IPv6 addresses match.
 * 
 * This function is used to check that the recieved packet came from the IP that was scanned.
 *
 * @param real_source_ip The source IPv6 of the recieved packet.
 * @param expected_source_ip The expected source IPv6 of the recieved packet.
 * 
 * @return 0 in case of matching IPs, 1 in case of non-matching IPs.
 */
int analyze_ips6(struct in6_addr real_source_ip, struct in6_addr expected_source_ip);

/**
 * @brief Checks wether the given IPv4 addresses match.
 * 
 * This function is used to check that the recieved packet came from the IP that was scanned.
 *
 * @param buffer Pointer to the recieved packet. The IP header is extracted from it and compared.
 * @param expected_source_ip The expected source IPv4 of the recieved packet.
 * 
 * @return 0 in case of matching IPs, 1 in case of non-matching IPs.
 */
int analyze_ips(char* buffer, uint32_t expected_source_ip);

/**
 * @brief Checks the status of incoming TCP packet.
 * 
 * Checks the flags of the incoming TCP packet response. Also checks wether the sequence number matches.
 *
 * @param buffer Pointer to the recieved packet.
 * @param ipv6_mode Used to determine the type of response (ipv4/ipv6).
 * @param seq_number Used to verify that the TCP packet is a response to the sent packet.
 * 
 * @return 1 in case of closed (RST), -1 in case of open (SYN + ACK), 2 in case the sequence number doesn't match up.
 */
int analyze_tcp_response(char* buffer, bool ipv6_mode, uint32_t seq_number);

/**
 * @brief Checks the status of incoming ICMP/ICMPv6 packets.
 * 
 * Checks the flags of the incoming ICMP/ICMPv6 packets that could indicate that the scanned port is closed.
 *
 * @param buffer Pointer to the recieved packet.
 * @param ipv6_mode Used to determine the type of response (ipv4/ipv6).
 * 
 * @ 1 in case of closed, -1 in case of open.
 */
int analyze_udp_response(char* buffer, bool ipv6_mode);

/**
 * @brief Sends IPv4 TCP packets and then analyzes the response and prints out the results.
 * 
 *
 * @param source_ip Source IP of the sent packets.
 * @param ports_array Array of zeros and ones, where one means that the port on that index shall be scanned
 * @param target The scanned IP address, the destination IP in the packets.
 * @param timeout Time in miliseconds, after which another packet will be sent (in TCP).
 * 
 * @return true in case of success, false in case of failure.
 */
bool scan_tcp_ipv4(uint32_t source_ip, int* ports_array, uint32_t target, int timeout);

/**
 * @brief Sends IPv6 TCP packets and then analyzes the response and prints out the results.
 * 
 *
 * @param target The scanned IP address, the destination IP in the packets.
 * @param ports_array Array of zeros and ones, where one means that the port on that index shall be scanned
 * @param source_ip Source IP of the sent packets.
 * @param timeout Time in miliseconds, after which the port will be declared as open (in UDP).
 * 
 * @return true in case of success, false in case of failure.
 */
bool scan_tcp_ipv6(struct in6_addr target, int* ports_array, struct in6_addr source_ip, int timeout);

/**
 * @brief Sends IPv4 UDP packets and then analyzes the response and prints out the results.
 * 
 *
 * @param source_ip Source IP of the sent packets.
 * @param ports_array Array of zeros and ones, where one means that the port on that index shall be scanned
 * @param target The scanned IP address, the destination IP in the packets.
 * @param timeout Time in miliseconds, after which another packet will be sent (in TCP).
 * 
 * @return true in case of success, false in case of failure.
 */
bool scan_udp_ipv4(uint32_t source_ip, int* ports_array, uint32_t target, int timeout);

/**
 * @brief Sends IPv6 UDP packets and then analyzes the response and prints out the results.
 * 
 *
 * @param target The scanned IP address, the destination IP in the packets.
 * @param ports_array Array of zeros and ones, where one means that the port on that index shall be scanned
 * @param source_ip Source IP of the sent packets.
 * @param timeout Time in miliseconds, after which the port will be declared as open (in UDP).
 * 
 * @return true in case of success, false in case of failure.
 */
bool scan_udp_ipv6(struct in6_addr target, int* ports_array, struct in6_addr source_ip, int timeout);