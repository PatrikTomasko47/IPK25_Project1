#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include <stdbool.h>
#include <ifaddrs.h>
#include <regex.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#define DEFAULT_TIMEOUT 5000 //the default timeout if the user doesn't specify otherwise
#define DOMAIN_REGEX "^([a-zA-Z0-9][-a-zA-Z0-9]*\\.)+[a-zA-Z]{2,}$" //regex used to verify wether user entered a valid domain name
#define MAX_PORTS 65535 //maximum ammount of possible ports to scan through
#define SOURCE_PORT 50000 //source port, it is in the ephemeral port range, and i just decided for it because it was nice

typedef enum {
    TYPE_UNKNOWN,
    TYPE_IPV4,
    TYPE_IPV6,
    TYPE_DOMAIN
} target_type;

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

uint16_t sum_calculator(void *data, int length){
        uint32_t sum = 0;
        uint16_t odd_byte = 0;
        uint16_t *pointer = (uint16_t *)data;
        
        while(length > 1){
                sum += *pointer++;
                length=-2;
        }
        
        if (length == 1){
                *(unsigned char *)(&odd_byte) = *(unsigned char *)pointer;
                sum += odd_byte;
        }
        
        sum =(sum >> 16) + (sum & 0xFFFF);
        sum +=(sum >> 16);
        return ~sum;
}

uint16_t udp_checksum(void* source_ip, void* dest_ip, struct udphdr* udp_header, int udp_length, bool ipv6_mode){
        uint16_t* buffer;
        int final_length;
        
        if(ipv6_mode){
                struct pseudo_header_ipv4 p_header;
                memcpy(p_header.source_ip, source_ip, 16);
                memcpy(p_header.dest_ip, dest_ip, 16);
                p_header.reserved = 0;
                p_header.protocol = IPPROTO_UDP;
                p_header.udp_length = htons(udp_len);
                
                total_len = sizeof(struct pseudo_header_ipv6) + udp_len;
                buffer = malloc(total_len);
                
                memcpy(buffer, &p_header, sizeof(struct pseudo_header_ipv6));
                memcpy(buffer + sizeof(struct pseudo_header_ipv6) / 2, udp_header, udp_len);
        }else{
                struct pseudo_header_ipv6 p_header;
                p_header.source_ip = *(uint32_t *)source_ip;
                p_header.dest_ip = *(uint32_t *)dest_ip;
                p_header.reserved = 0;
                p_header.protocol = IPPROTO_UDP;
                p_header.udp_length = htons(udp_len);
                
                total_len = sizeof(struct pseudo_header_ipv4) + udp_len;
                buffer = malloc(total_len);
                
                memcpy(buffer, &p_header, sizeof(struct pseudo_header_ipv4));
                memcpy(buffer + sizeof(struct pseudo_header_ipv4) / 2, udp_header, udp_len);
        }
        
        uint16_t checksum_value = checksum(buffer, total_len);
        free(buffer);
        
        return checksum_value;
}

uint16_t tcp_checksum(void* source_ip, void* dest_ip, struct tcphdr* tcp_header, int tcp_length, bool ipv6_mode){
        uint16_t* buffer;
        int final_length;
        
        if(ipv6_mode){
                struct pseudo_header_ipv4 p_header;
                memcpy(p_header.source_ip, source_ip, 16);
                memcpy(p_header.dest_ip, dest_ip, 16);
                p_header.reserved = 0;
                p_header.protocol = IPPROTO_TCP;
                p_header.tcp_length = htons(tcp_len);
                
                total_len = sizeof(struct pseudo_header_ipv6) + tcp_len;
                buffer = malloc(total_len);
                
                memcpy(buffer, &p_header, sizeof(struct pseudo_header_ipv6));
                memcpy(buffer + sizeof(struct pseudo_header_ipv6) / 2, tcp_header, tcp_len);
        }else{
                struct pseudo_header_ipv6 p_header;
                p_header.source_ip = *(uint32_t *)source_ip;
                p_header.dest_ip = *(uint32_t *)dest_ip;
                p_header.reserved = 0;
                p_header.protocol = IPPROTO_TCP;
                p_header.tcp_length = htons(udp_len);
                
                total_len = sizeof(struct pseudo_header_ipv4) + tcp_len;
                buffer = malloc(total_len);
                
                memcpy(buffer, &p_header, sizeof(struct pseudo_header_ipv4));
                memcpy(buffer + sizeof(struct pseudo_header_ipv4) / 2, tcp_header, tcp_len);
        }
        
        uint16_t checksum_value = checksum(buffer, total_len);
        free(buffer);
        
        return checksum_value;
}

void construct_tcp_header(void* target_ip, uint16_t destination_port, struct tcphdr* header, bool ipv6_mode, void* source_ip){
        memset(header, 0, sizeof(struct tcphder));
        
        header->th_sport = htons(SOURCE_PORT);
        header->th_dport = htons(destination_port);
        header->th_seq = htonl(rand());
        header->th_flags = TH_SYN;
        header->th_off = 5;
        header->th_win = htons(65535);
        tcp->th_sum = 0;
        
        uint16_t sum = tcp_checksum(source_ip, target_ip, header, sizeof(struct tcphdr), ipv6_mode);
        header->th_sum = sum;
        
        return ;
}

void construct_udp_header(void* target_ip, uint16_t destination_port, struct udphdr* header, bool ipv6_mode, void* source_ip){
        memset(header, 0, sizeof(struct udphder));
        
        header->uh_sport = htons(SOURCE_PORT);
        header->uh_dport = htons(destination_port);
        header->uh_ulen = htons(sizeof(struct udphdr));
        tcp->uh_sum = 0;
        
        uint16_t checksum = udp_checksum(source_ip, target_ip, header, sizeof(struct udphdr), ipv6_mode);
        header->uh_sum = checksum;
        
        return ;
}

int raw_socket_maker(int protocol){
        int socket_var = socket(AF_INET, SOCK_RAW, protocol);
        if(socket_var < 0){
                fprintf(stderr, "Error: The creation of a raw socket failed.");
                return -1;
        }
        
}

void scan_tcp_ipv4(uint32_t target, int* ports_array) {
        for(int index = 0; index < MAX_PORTS; index++){
                if(ports_array[index]){
                        
                }
        }
}

void scan_tcp_ipv6(struct in6_addr target, int* ports_array) {
        printf("Inside scan_tcp_ipv6 -> Target: %s\n", target);
}

void scan_udp_ipv4(uint32_t target, int* ports_array) {
        printf("Inside scan_udp_ipv4 -> Target: %s\n", target);
}

void scan_udp_ipv6(struct in6_addr, int* ports_array) {
        printf("Inside scan_udp_ipv6 -> Target: %s\n", target);
}

void iterate_domain_ips(char* domain, int* tcp_ports, int* udp_ports) {
        struct addrinfo h, *result, *found;
        memset(&h, 0, sizeof(h));
        h.ai_family = AF_UNSPEC;
        h.ai_socktype = 0;

        if (getaddrinfo(domain, NULL, &h, &result) != 0) {
                fprintf(stderr, "Error: An error occured resolving domain: %s\n", domain);
                return;
        }

        for (found = result; found != NULL; found = found->ai_next) {
                char ip[INET6_ADDRSTRLEN];
                void *addr;

                if (found->ai_family == AF_INET) {
                        struct sockaddr_in *ipv4 = (struct sockaddr_in *)found->ai_addr;
                        addr = &(ipv4->sin_addr);
                        inet_ntop(found->ai_family, addr, ip, sizeof(ip));
                        printf("IPv4: %s\n", ip);
                        scan_tcp_ipv4(ip, tcp_ports);
                        scan_udp_ipv4(ip, udp_ports);
                } else if (found->ai_family == AF_INET6) {
                        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)found->ai_addr;
                        addr = &(ipv6->sin6_addr);
                        inet_ntop(found->ai_family, addr, ip, sizeof(ip));
                        printf("IPv6: %s\n", ip);
                        scan_tcp_ipv6(ip, tcp_ports);
                        scan_udp_ipv6(ip, udp_ports);
                }
        }

        freeaddrinfo(result);
}

target_type determine_target_type(char *target){
        struct in_addr ipv4_addr;
        struct in6_addr ipv6_addr;
        
        if (inet_pton(AF_INET, target, &ipv4_addr)){
                return TYPE_IPV4;
        }
        
        if (inet_pton(AF_INET6, target, &ipv6_addr)){
                return TYPE_IPV6;
        }
        
        regex_t regex;
        if (regcomp(&regex, DOMAIN_REGEX, REG_EXTENDED | REG_NOSUB) == 0) {
                int match = regexec(&regex, target, 0, NULL, 0);
                regfree(&regex);
                if (match == 0){
                        return TYPE_DOMAIN;
                }
        }
        
        return TYPE_UNKNOWN;	
}

bool print_available_interfaces(){
        struct ifaddrs *ifaddresses, *ifaddress;
        if(getifaddrs(&ifaddresses) == -1){
                printf("An error occured fetching the available interfaces");
                return false;
        }
        
        printf("Active network interfaces:\n");
        for(ifaddress = ifaddresses; ifaddress != NULL; ifaddress = ifaddress->ifa_next){
                if(ifaddress->ifa_addr && ifaddress->ifa_addr->sa_family == AF_INET){
                        printf("%s\n", ifaddress->ifa_name);
                }
        }
        freeifaddrs(ifaddresses);
        return true;
}

bool get_input_params(int argc, char *argv[], char** interface, int* wait, char** target, char** udp_ports_string, char** tcp_ports_string){

        bool wait_input = false;
        bool interface_input = false;
        
	static struct option long_options[] = {
		{"interface", optional_argument, NULL, 'i'},
		{"wait", required_argument, NULL, 'w'},
		{"pt", required_argument, NULL, 't'},
		{"pu", required_argument, NULL, 'u'},
		{0, 0, 0, 0}
	};

	int flag;
	while((flag = getopt_long(argc, argv, "i::w:t:u:", long_options, NULL)) != -1){
		switch(flag){
			case 'i':
			        if(optarg){
			                if(!*interface){
				                *interface = argv[optind];
                                                interface_input = false;
                                        }else{
                                                fprintf(stderr, "Error: multiple -i/--interface inputs were detected.\n");
                                                return false;
                                        }
				}else{
				        if (optind < argc && argv[optind][0] != '-') {
                                                if (!*interface) {
                                                        interface_input = true;
                                                        *interface = argv[optind];
                                                        optind++;
                                                } else {
                                                        fprintf(stderr, "Error: multiple -i/--interface inputs detected.\n");
                                                        return false;
                                                }
                                        }else{
				                if(!interface_input){
				                        interface_input = true;
				                }else{
				                        fprintf(stderr, "Error: multiple -i/--interface inputs were detected.\n");
				                        return false;
				                }
				        }
				}
				break;
			case 'w':
			        if(isdigit(*optarg)){
			                if(!wait_input){
			                        *wait = atoi(optarg);
			                        wait_input = true;
			                }else{
			                        fprintf(stderr, "Error: multiple -w/--wait inputs were detected.\n");
				                return false;
			                }
			        }else{
			                fprintf(stderr, "Error: Timeout value has to be a nubmer.\n");
			                return false;
			        }
			        break;
			case 't':
			        if(!*tcp_ports_string){
			                *tcp_ports_string = optarg;
			        }else{
			                fprintf(stderr, "Error: multiple -t/--pt inputs were detected.\n");
				        return false;
			        }
			        break;
			case 'u':
			        if(!*udp_ports_string){
			                *udp_ports_string = optarg;
			        }else{
			                fprintf(stderr, "Error: multiple -u/--pu inputs were detected.\n");
				        return false;
			        }
			        break;
			case '?':
				fprintf(stderr, "Error: An unknown flag was '%c' detected\n", flag);
				return false;
			default:
				fprintf(stderr, "Error: An error occured whilst parsing through the flags.\n");
				return false;
		}
	}
	
	if(argc == 1){
	        if(!print_available_interfaces()){
	                fprintf(stderr, "An error occured listing all the available interfaces.\n");
	                return false;
	        }else{
	                return true;
	        }
	}
	
	if(interface_input && !*interface && !wait_input && !*udp_ports_string && !*tcp_ports_string && optind >= argc){
	        if(!print_available_interfaces()){
	                fprintf(stderr, "An error occured listing all the available interfaces.\n");
	                return false;
	        }else{
	                return true;
	        }
	}
	
	if (optind < argc){
	        *target = argv[optind];
	        optind++;
	}else{
	        fprintf(stderr, "Error: No target specified\n");
	        return false;
	}
	
	if(optind < argc){
	        fprintf(stderr, "Error: An unexpected argument was detected after the target.\n");
	        return false;
	}
	
	if(!*udp_ports_string && !*tcp_ports_string){
	        fprintf(stderr, "Error: No ports to scan have been specified.\n");
	        return false;
	}
	
	if(!*interface){
	        fprintf(stderr, "Error: No interface specified. To wiev available interfaces -> './ipk-l4-scan -i' or './ipk-l4-scan'\n");
	        return false;
	}
	
	return true;
}



bool port_parser(char* ports_string, int* ports_array){
        char* number = strtok(ports_string, ",");
        while(number){
                if(isdigit(number[0])){
                        if(strchr(number, '-')){
                                int start, end;
                                if(sscanf(number, "%d-%d", &start, &end) == 2 && start <= end && start > 0 && end <= MAX_PORTS){
                                        for(int index = start; index <= end; index++){
                                                ports_array[index] = 1;
                                        }
                                }else{
                                        fprintf(stderr, "Error: Unexpected value detected in the port range. Know that in ranges, the number to the left has to be smaller or equal to the number to the right.");
                                }
                        }else{
                                int value = atoi(number);
                                if(value > 0 && value <= MAX_PORTS){
                                        ports_array[value] = 1;
                                }else{
                                        fprintf(stderr, "Error: The port you entered (%d) is out of the allowed range.", value);
                                }
                        }
                }else{
                        fprintf(stderr, "Error: Unexpected value was detected in the ports.");
                }
        }
        return true;
}

int main(int argc, char *argv[]){
        int timeout = DEFAULT_TIMEOUT;
	char* interface = NULL;
	char* target = NULL;
	char* tcp_ports_string = NULL;
	char* udp_ports_string = NULL;
	int tcp_ports[MAX_PORTS] = {0};
	int udp_ports[MAX_PORTS] = {0};
	
	if(!get_input_params(argc, argv, &interface, &timeout, &target, &udp_ports_string, &tcp_ports_string) && interface){
		return 1;
	}
	target_type ttype = determine_target_type(target);
	
	if(ttype == TYPE_UNKNOWN){
	        fprintf(stderr, "Error: The specified target is not correct.");
	        return 1;
	}else if(ttype == TYPE_DOMAIN){
	        iterate_domain_ips(target, tcp_ports, udp_ports);
	}else if(ttype == TYPE_IPV4){
	        uint32_t converted_ipv4;
	        
	        if(inet_pton(AF_INET, target, &converted_ipv4) != 1)
	                fprintf(stderr, "Error: An error occured converting the target IP address to uint32_t.");
	        
	        scan_tcp_ipv4(converted_ipv4, tcp_ports);
                scan_udp_ipv4(converted_ipv4, udp_ports);
	}else{
	        struct ip6_addr converted_ipv6;
	        
	        if(inet_pton(AF_INET6, target, &converted_ipv4) != 1)
	                fprintf(stderr, "Error: An error occured converting the target IP address to uint32_t.");
	                
	        scan_tcp_ipv6(converted_ipv6, tcp_ports);
                scan_udp_ipv6(converted_ipv6, udp_ports);
	}
	return 0;
}
