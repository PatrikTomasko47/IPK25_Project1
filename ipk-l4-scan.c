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
#include <unistd.h>

#define DEFAULT_TIMEOUT 5000 //the default timeout if the user doesn't specify otherwise
#define DOMAIN_REGEX "^(([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\\.)+[a-zA-Z]{2,})$" //regex used to verify wether user entered a valid domain name
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

struct send_parameters{
        int* ports;
        uint32_t target_ipv4;
        uint32_t source_ipv4;
        struct in6_addr target_ipv6;
        struct in6_addr source_ipv6;
};

uint16_t sum_calculator(void *data, int length){
        uint32_t sum = 0;
        uint16_t odd_byte = 0;
        uint16_t *pointer = (uint16_t *)data;
        
        while(length > 1){
                sum += *pointer++;
                length-=2;
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
                struct pseudo_header_ipv6 p_header;
                memcpy(&p_header.source_ip, source_ip, 16);
                memcpy(&p_header.destination_ip, dest_ip, 16);
                p_header.zero = 0;
                p_header.protocol = IPPROTO_UDP;
                p_header.udp_tcp_length = htons(udp_length);
                
                final_length = sizeof(struct pseudo_header_ipv6) + udp_length;
                buffer = malloc(final_length);
                
                memcpy(buffer, &p_header, sizeof(struct pseudo_header_ipv6));
                memcpy(buffer + sizeof(struct pseudo_header_ipv6) / 2, udp_header, udp_length);
        }else{
                struct pseudo_header_ipv4 p_header;
                p_header.source_ip = *((uint32_t *)source_ip);
                p_header.destination_ip = *((uint32_t *)dest_ip);
                p_header.zero = 0;
                p_header.protocol = IPPROTO_UDP;
                p_header.udp_tcp_length = htons(udp_length);
                
                final_length = sizeof(struct pseudo_header_ipv4) + udp_length;
                buffer = malloc(final_length);
                
                memcpy(buffer, &p_header, sizeof(struct pseudo_header_ipv4));
                memcpy(buffer + sizeof(struct pseudo_header_ipv4) / 2, udp_header, udp_length);
        }
        
        uint16_t checksum_value = sum_calculator(buffer, final_length);
        free(buffer);
        
        return checksum_value;
}

uint16_t tcp_checksum(void* source_ip, void* dest_ip, struct tcphdr* tcp_header, int tcp_length, bool ipv6_mode){
        uint16_t* buffer;
        int final_length;
        
        if(ipv6_mode){
                struct pseudo_header_ipv6 p_header;
                memcpy(&p_header.source_ip, source_ip, 16);
                memcpy(&p_header.destination_ip, dest_ip, 16);
                p_header.zero = 0;
                p_header.protocol = IPPROTO_TCP;
                p_header.udp_tcp_length = htons(tcp_length);
                
                final_length = sizeof(struct pseudo_header_ipv6) + tcp_length;
                buffer = malloc(final_length);
                
                memcpy(buffer, &p_header, sizeof(struct pseudo_header_ipv6));
                memcpy(buffer + sizeof(struct pseudo_header_ipv6) / 2, tcp_header, tcp_length);
        }else{
                struct pseudo_header_ipv4 p_header;
                p_header.source_ip = *((uint32_t *)source_ip);
                p_header.destination_ip = *((uint32_t *)dest_ip);
                p_header.zero = 0;
                p_header.protocol = IPPROTO_TCP;
                p_header.udp_tcp_length = htons(tcp_length);
                
                final_length = sizeof(struct pseudo_header_ipv4) + tcp_length;
                buffer = malloc(final_length);
                
                memcpy(buffer, &p_header, sizeof(struct pseudo_header_ipv4));
                memcpy(buffer + sizeof(struct pseudo_header_ipv4) / 2, tcp_header, tcp_length);
        }
        
        uint16_t checksum_value = sum_calculator(buffer, final_length);
        free(buffer);
        
        printf("Calculated %d \n",checksum_value);
        return checksum_value;
}

void construct_tcp_header(void* target_ip, uint16_t destination_port, struct tcphdr* header, bool ipv6_mode, void* source_ip){
        memset(header, 0, sizeof(struct tcphdr));
        
        header->th_sport = htons(SOURCE_PORT);
        header->th_dport = htons(destination_port);
        header->th_seq = htonl(rand());
        header->th_flags = TH_SYN;
        header->th_off = 5;
        header->th_win = htons(65535);
        header->th_sum = 0;
        
        uint16_t sum = tcp_checksum(source_ip, target_ip, header, sizeof(struct tcphdr), ipv6_mode);
        header->th_sum = sum;
        
        return ;
}

void construct_udp_header(void* target_ip, uint16_t destination_port, struct udphdr* header, bool ipv6_mode, void* source_ip){
        memset(header, 0, sizeof(struct udphdr));
        
        header->uh_sport = htons(SOURCE_PORT);
        header->uh_dport = htons(destination_port);
        header->uh_ulen = htons(sizeof(struct udphdr));
        header->uh_sum = 0;
        
        uint16_t checksum = udp_checksum(source_ip, target_ip, header, sizeof(struct udphdr), ipv6_mode);
        header->uh_sum = checksum;
        
        return ;
}

bool raw_socket_maker(int protocol, int* socket_var){
        *socket_var = socket(AF_INET, SOCK_RAW, protocol);
        if(socket_var < 0){
                fprintf(stderr, "Error: The creation of a raw socket failed.");
                return false;
        }
        return true;
}

void scan_tcp_ipv4(uint32_t target, int* ports_array, uint32_t source_ip) {
        int raw_socket;
        if(!raw_socket_maker(IPPROTO_TCP, &raw_socket)){
                fprintf(stderr, "Error: An error occured opening the raw socket.");
        }
        
        struct sockaddr_in target_wrapper;
        memset(&target_wrapper, 0, sizeof(target_wrapper));
        target_wrapper.sin_family = AF_INET;
        target_wrapper.sin_addr.s_addr = target;
        
        struct sockaddr_in src_wrapper;
        src_wrapper.sin_family = AF_INET;
        src_wrapper.sin_addr.s_addr = source_ip;
        bind(raw_socket, (struct sockaddr *)&src_wrapper, sizeof(src_wrapper));
        
        if (bind(raw_socket, (struct sockaddr *)&src_wrapper, sizeof(src_wrapper)) == -1) {
                perror("Binding source IP failed");
                close(raw_socket);
                return;
        }
        
        for(int index = 0; index < MAX_PORTS; index++){
                if(ports_array[index]){
                        struct tcphdr tcp_header;
                        construct_tcp_header(&target, (uint16_t) index, &tcp_header, false, &source_ip);
                        
                        target_wrapper.sin_port = htons(index);
                        
                        ssize_t bytes_sent = sendto(raw_socket, &tcp_header, sizeof(tcp_header), 0, (struct sockaddr *)&target_wrapper, sizeof(target_wrapper));

                        if (bytes_sent == -1) {
                            fprintf(stderr, "Error: Failed to send the packet.");
                        } else {
                            printf("[+] Sent TCP SYN to %s:%d\n", inet_ntoa(target_wrapper.sin_addr), index);
                        }
                }
        }
        close(raw_socket);
        return;
}

void scan_tcp_ipv6(struct in6_addr target, int* ports_array, struct in6_addr source_ip) {
        return;
}

void scan_udp_ipv4(uint32_t target, int* ports_array, uint32_t source_ip) {
        return;
}

void scan_udp_ipv6(struct in6_addr, int* ports_array, struct in6_addr source_ip) {
        return;
}

bool convert_source_ip(char* interface, void* return_pointer, bool ipv6_mode){
        struct ifaddrs *ifaddresses, *ifaddress;
        if(getifaddrs(&ifaddresses) == -1){
                printf("An error occured fetching the interfaces while converting the interface to an IP.");
                return false;
        }
        
        for(ifaddress = ifaddresses; ifaddress != NULL; ifaddress = ifaddress->ifa_next){
                if(strcmp(ifaddress->ifa_name, interface) == 0 && ifaddress->ifa_addr != NULL){
                        if(ipv6_mode && ifaddress->ifa_addr->sa_family == AF_INET6){
                        
                                struct sockaddr_in6 *ipv6_address = (struct sockaddr_in6 *)ifaddress->ifa_addr;
                                
                                if(IN6_IS_ADDR_LINKLOCAL(&ipv6_address->sin6_addr)){
                                        continue;
                                }
                                
                                memcpy(return_pointer, &ipv6_address->sin6_addr, sizeof(struct in6_addr));
                                free(ifaddresses);
                                return true;
                                
                        }else if(!ipv6_mode && ifaddress->ifa_addr->sa_family == AF_INET){
                                
                                struct sockaddr_in *ipv4_address = (struct sockaddr_in *)ifaddress->ifa_addr;
                                
                                memcpy(return_pointer, &ipv4_address->sin_addr, sizeof(uint32_t));
                                free(ifaddresses);
                                return true;
                                
                        }
                }
        }
        fprintf(stderr, "Error: The interface you want to use '%s' does not have a ipv%d address.",interface, ipv6_mode ? 6 : 4);
        freeifaddrs(ifaddresses);
        return false;
}

void iterate_domain_ips(char* domain, int* tcp_ports, int* udp_ports, uint32_t source_ipv4, struct in6_addr source_ipv6) {
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
                        
                        if(source_ipv4 == 0){
                                fprintf(stderr, "Error: The selected interface does not support ipv4 communication.");
                                freeaddrinfo(result);
                                return;
                        }
                        
                        struct sockaddr_in *ipv4 = (struct sockaddr_in *)found->ai_addr;
                        addr = &(ipv4->sin_addr);
                        inet_ntop(found->ai_family, addr, ip, sizeof(ip));
                        printf("IPv4: %s\n", ip);
                        scan_tcp_ipv4((uint32_t)ipv4->sin_addr.s_addr, tcp_ports, source_ipv4);
                        scan_udp_ipv4((uint32_t)ipv4->sin_addr.s_addr, udp_ports, source_ipv4);
                        
                } else if (found->ai_family == AF_INET6) {
                
                        if(memcmp(&source_ipv6, &(struct in6_addr){0}, sizeof(struct in6_addr)) == 0){
                                fprintf(stderr, "Error: The selected interface does not support ipv6 communication.");
                                freeaddrinfo(result);
                                return;
                        }
                        
                        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)found->ai_addr;
                        addr = &(ipv6->sin6_addr);
                        inet_ntop(found->ai_family, addr, ip, sizeof(ip));
                        printf("IPv6: %s\n", ip);
                        scan_tcp_ipv6(ipv6->sin6_addr, tcp_ports, source_ipv6);
                        scan_udp_ipv6(ipv6->sin6_addr, udp_ports, source_ipv6);
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



bool port_parser(char* ports_string, int* ports_array, bool* filled){
        char* number = strtok(ports_string, ",");
        while(number){
                if(isdigit(number[0])){
                        
                        if(strchr(number, '-')){
                                int start, end;
                                if(sscanf(number, "%d-%d", &start, &end) == 2 && start <= end && start > 0 && end <= MAX_PORTS){
                                        for(int index = start; index <= end; index++){
                                                ports_array[index] = 1;
                                                *filled = true;
                                        }
                                }else{
                                        fprintf(stderr, "Error: Unexpected value detected in the port range. Know that in ranges, the number to the left has to be smaller or equal to the number to the right.");
                                }
                        }else{
                                int value = atoi(number);
                                if(value > 0 && value <= MAX_PORTS){
                                        ports_array[value] = 1;
                                        *filled = true;
                                }else{
                                        fprintf(stderr, "Error: The port you entered (%d) is out of the allowed range.", value);
                                }
                        }
                }else{
                        fprintf(stderr, "Error: Unexpected value was detected in the ports.");
                }
                number = strtok(NULL, ",");
        }
        return true;
}

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
	
	if(!get_input_params(argc, argv, &interface, &timeout, &target, &udp_ports_string, &tcp_ports_string) && interface){
		return 1;
	}
	
	if(!port_parser(tcp_ports_string, tcp_ports, &tcp))
	        return 1;

	if(!port_parser(udp_ports_string, udp_ports, &udp)){
	
	}
	
	target_type ttype = determine_target_type(target);
	
        printf("The target is %d", ttype);

	if(ttype == TYPE_UNKNOWN){
	        fprintf(stderr, "Error: The specified target is not correct.");
	        return 1;
	}else if(ttype == TYPE_DOMAIN){
	
                uint32_t source_ipv4;
	        if(!convert_source_ip(interface, (void *) &source_ipv4, false)){
	                source_ipv4 = 0;
	        }
	        
	        struct in6_addr source_ipv6;
	        if(!convert_source_ip(interface, (void *) &source_ipv6, true)){
	                memset(&source_ipv6, 0, sizeof(struct in6_addr));
	        }
	
	        iterate_domain_ips(target, tcp_ports, udp_ports, source_ipv4, source_ipv6);
	}else if(ttype == TYPE_IPV4){
	        uint32_t converted_ipv4;
	        convert_source_ip(interface, (void *) &converted_ipv4, false);
	        
	        if(inet_pton(AF_INET, target, &converted_ipv4) != 1)
	                fprintf(stderr, "Error: An error occured converting the target IP address to uint32_t.");
	        
	        uint32_t source_ipv4;
	        if(!convert_source_ip(interface, (void *) &source_ipv4, false)){
	                return 1;
	        }
	        
	        scan_tcp_ipv4(converted_ipv4, tcp_ports, source_ipv4);
                //scan_udp_ipv4(converted_ipv4, udp_ports, source_ipv4);
	}else{
	        struct in6_addr converted_ipv6;
	        
	        if(inet_pton(AF_INET6, target, &converted_ipv6) != 1)
	                fprintf(stderr, "Error: An error occured converting the target IP address to ip6_addr struct.");
	        
	        struct in6_addr source_ipv6;
	        if(!convert_source_ip(interface, (void *) &source_ipv6, true)){
	                fprintf(stderr, "Error: The selected interface does not support ipv6 communication.");
	                return 1;
	        }
	        
	        scan_tcp_ipv6(converted_ipv6, tcp_ports, source_ipv6);
                scan_udp_ipv6(converted_ipv6, udp_ports, source_ipv6);
	}
	return 0;
}
