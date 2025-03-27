/**
 * @file ip_utility.c
 * @brief Contains functions used to work with interfaces and string to ip conversions.
 *
 *
 * @author Patrik Tomasko (xtomasp00)
 * @date 2025-03-27
 */

#include <ifaddrs.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <netdb.h>

#include "ip_utility.h"
#include "ll_ip_array.h"
#include "port_analyzer.h"

bool print_available_interfaces(){

    struct ifaddrs *ifaddresses, *ifaddress;

    if(getifaddrs(&ifaddresses) == -1){

            printf("Error: An error occured fetching the available interfaces.\n");
            return false;

    }
    
    printf("Active network interfaces:\n");

    for(ifaddress = ifaddresses; ifaddress != NULL; ifaddress = ifaddress->ifa_next){

            if(ifaddress->ifa_addr && ifaddress->ifa_addr->sa_family == AF_INET) //if there will be an interface with only ipv6 than it will not print it out
                    printf("%s\n", ifaddress->ifa_name);

    }

    freeifaddrs(ifaddresses);
    return true;

}

bool iterate_domain_ips(char* domain, int* tcp_ports, int* udp_ports, int timeout, uint32_t source_ipv4, struct in6_addr source_ipv6){

        //used to skip if the interface does not have such an IP
        bool ipv4_skip, ipv6_skip = false;

        //used not to not scan the same IP over and over
        struct ll_ip4* visited_ipv4;
        struct ll_ip6* visited_ipv6;

        ll_ip4_init(&visited_ipv4);
        ll_ip6_init(&visited_ipv6);

        struct addrinfo h, *result, *found;
        memset(&h, 0, sizeof(h));
        h.ai_family = AF_UNSPEC;
        h.ai_socktype = 0;

        if (getaddrinfo(domain, NULL, &h, &result) != 0) {

                fprintf(stderr, "Error: An error occured resolving domain: %s\n", domain);
                return false;

        }

        for (found = result; found != NULL; found = found->ai_next) {

                if (found->ai_family == AF_INET) { //ipv4
                        
                        if(source_ipv4 == 0){

                                if(!ipv4_skip){

                                        printf("Skipping IPV4 since the chosen interface has no suitable IPV4 address.\n");
                                        ipv4_skip = true;

                                }

                                continue;

                        }
                        
                        struct sockaddr_in* ipv4 = (struct sockaddr_in*)found->ai_addr;

                        if(!ll_ip4_search(visited_ipv4, &(ipv4->sin_addr))){ //checking for duplicate IP

                                if(!ll_ip4_append(visited_ipv4, &(ipv4->sin_addr))){

                                        printf("Error: An internal error occured logging all the scanned IPv4 addresses.\n");
                                        return false;

                                }

                        }else{

                                continue;

                        }

                        
                        if(!scan_tcp_ipv4(source_ipv4, tcp_ports, (uint32_t)ipv4->sin_addr.s_addr, timeout))
                                return false;

                        if(!scan_udp_ipv4(source_ipv4, udp_ports, (uint32_t)ipv4->sin_addr.s_addr, timeout))
                                return false;
                        
                } else if (found->ai_family == AF_INET6) { //ipv6
                
                        if(memcmp(&source_ipv6, &(struct in6_addr){0}, sizeof(struct in6_addr)) == 0){
                                
                                if(!ipv6_skip){

                                        printf("Skipping IPV6 since the chosen interface has no suitable IPV6 address.\n");
                                        ipv6_skip = true;

                                }

                                continue;
                        }
                        
                        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)found->ai_addr;

                        if(!ll_ip6_search(visited_ipv6, &(ipv6->sin6_addr))){ //checking for duplicate IP

                                if(!ll_ip6_append(visited_ipv6, &(ipv6->sin6_addr))){

                                        printf("Error: An internal error occured logging all the scanned IPv6 addresses.\n");
                                        return false;

                                }

                        }else{

                                continue;

                        }

                        if(!scan_tcp_ipv6(ipv6->sin6_addr, tcp_ports, source_ipv6, timeout))
                                return false;

                        if(!scan_udp_ipv6(ipv6->sin6_addr, udp_ports, source_ipv6, timeout))
                                return false;
                }
        }

        ll_ip4_free(visited_ipv4);
        ll_ip6_free(visited_ipv6);

        freeaddrinfo(result);

        return true;

}

bool convert_source_ip(char* interface, void* return_pointer, bool ipv6_mode){

    struct ifaddrs *ifaddresses, *ifaddress;

    if(getifaddrs(&ifaddresses) == -1){

            printf("An error occured fetching the interfaces while converting the interface to an IP.\n");
            return false;

    }
    
    for(ifaddress = ifaddresses; ifaddress != NULL; ifaddress = ifaddress->ifa_next){

            if(strcmp(ifaddress->ifa_name, interface) == 0 && ifaddress->ifa_addr != NULL){

                    if(ipv6_mode && ifaddress->ifa_addr->sa_family == AF_INET6){
                    
                            struct sockaddr_in6* ipv6_address = (struct sockaddr_in6*)ifaddress->ifa_addr;
                            
                            if(IN6_IS_ADDR_LINKLOCAL(&ipv6_address->sin6_addr)){ //checking for link local addresses
                                    continue;
                            }
                            
                            memcpy(return_pointer, &ipv6_address->sin6_addr, sizeof(struct in6_addr));
                            free(ifaddresses);
                            return true;
                            
                    }else if(!ipv6_mode && ifaddress->ifa_addr->sa_family == AF_INET){
                            
                            struct sockaddr_in* ipv4_address = (struct sockaddr_in*)ifaddress->ifa_addr;
                            
                            memcpy(return_pointer, &ipv4_address->sin_addr, sizeof(uint32_t));
                            free(ifaddresses);
                            return true;
                            
                    }

            }

    }

    freeifaddrs(ifaddresses);
    return false;
    
}