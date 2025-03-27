/**
 * @file ipk-l4-scan.c
 * @brief Connects all the other files together to analyze specified ports via the specified interface.
 *
 *
 * @author Patrik Tomasko (xtomasp00)
 * @date 2025-03-27
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "ll_ip_array.h"
#include "input_parser.h"
#include "ip_utility.h"
#include "port_analyzer.h"

#define DEFAULT_TIMEOUT 5000 //the default timeout if the user doesn't specify otherwise


/**
 * @brief Scans the specified ports
 *
 * Takes the user input, parses it and then uses the extracted information 
 * to scan certain ports of a specified target via the specified interface.
 *
 * @param argc The number of values input by the user.
 * @param argv Array of values given by the user.
 * 
 * @returns 0 in case of success, 1 in case of failure.
 */
int main(int argc, char *argv[]){

        bool udp = false;
        bool tcp = false;

        int timeout = DEFAULT_TIMEOUT;
		char* interface = NULL;
		char* target = NULL;
		char* tcp_ports_string = NULL;
		char* udp_ports_string = NULL;
		int tcp_ports[MAX_PORTS] = {0};
		int udp_ports[MAX_PORTS] = {0};
		
		int input_result = get_input_params(argc, argv, &interface, &timeout, &target, &udp_ports_string, &tcp_ports_string);
		
		if(input_result == 1){ //an error occured

				return 1;

		}else if (input_result == 2){ //printed out the interfaces

				return 0;

		}
		
		if(tcp_ports_string){

				if(!port_parser(tcp_ports_string, tcp_ports, &tcp))
						return 1;

		}

		if(udp_ports_string){

				if(!port_parser(udp_ports_string, udp_ports, &udp))
						return 1;

		}
		
		target_type ttype = determine_target_type(target);

		if(ttype == TYPE_UNKNOWN){

				fprintf(stderr, "Error: The specified target is not of any supported format.\n");
				return 1;

		}else if(ttype == TYPE_DOMAIN){
		
				uint32_t source_ipv4;

				if(!convert_source_ip(interface, (void *) &source_ipv4, false))
						source_ipv4 = 0;
				
				struct in6_addr source_ipv6;

				if(!convert_source_ip(interface, (void *) &source_ipv6, true))
						memset(&source_ipv6, 0, sizeof(struct in6_addr));
		
				if(!iterate_domain_ips(target, tcp_ports, udp_ports, timeout, source_ipv4, source_ipv6))
						return 1;

				return 0;

		}else if(ttype == TYPE_IPV4 || ttype == TYPE_LOCALHOST){
					
				char* target_local = target;

				if(ttype == TYPE_LOCALHOST)
						target_local = "127.0.0.1";

				uint32_t source_ipv4;

				if(!convert_source_ip(interface, (void*)&source_ipv4, false)){

						fprintf(stderr, "Error: The interface you want to use '%s' does not have an suitable ipv4 address.\n",interface);
						return 1;

				}

				struct in_addr target_ipv4_struct;

				if(inet_pton(AF_INET, target_local, &target_ipv4_struct) != 1){ //converting target to an IPv4

						fprintf(stderr, "Error: The conversion of the target IP from string to uint_32 failed.\n");
						return 1;

				}

				if(!scan_tcp_ipv4(source_ipv4, tcp_ports, target_ipv4_struct.s_addr, timeout))
						return 1;

				if(!scan_udp_ipv4(source_ipv4, udp_ports, target_ipv4_struct.s_addr, timeout))
						return 1;

				return 0;

		}else if(ttype == TYPE_IPV6){

				struct in6_addr target_ipv6;

				if(inet_pton(AF_INET6, target, &target_ipv6) != 1){ //converting the target to in6_addr
						fprintf(stderr, "Error: The conversion of the target IP from string to in6_addrfailed.\n");
						return 1;
				}
				
				struct in6_addr source_ipv6;

				if(!convert_source_ip(interface, (void *) &source_ipv6, true)){
						fprintf(stderr, "Error: The interface you want to use '%s' does not have an suitable ipv6 address.\n",interface);
						return 1;
				}
				
				if(!scan_tcp_ipv6(target_ipv6, tcp_ports, source_ipv6, timeout))
							return 1;

				if(!scan_udp_ipv6(target_ipv6, udp_ports, source_ipv6, timeout))
						return 1;

				return 0;

		}

		return 1;
		
}
