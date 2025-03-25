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
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <unistd.h>
#include <sys/select.h>

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
        
        //printf("Calculated %d \n",checksum_value);
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

bool raw_socket_maker(int protocol, int* socket_var, bool ipv6_mode){
        int inet_type = AF_INET;

        if(ipv6_mode == true) 
                inet_type = AF_INET6;
        

        *socket_var = socket(inet_type, SOCK_RAW, protocol);
        if(socket_var < 0){
                fprintf(stderr, "Error: The creation of a raw socket failed.");
                return false;
        }
        return true;
}

int analyze_ips6(struct in6_addr real_source_ip, struct in6_addr expected_source_ip){

        char real_source_ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &real_source_ip, real_source_ip_str, INET6_ADDRSTRLEN);

        char expected_source_ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &expected_source_ip, expected_source_ip_str, INET6_ADDRSTRLEN);

        printf("Comparing IPs:\n");
        printf("Real Source IP: %s vs Expected Source IP: %s\n", real_source_ip_str, expected_source_ip_str);

        if (memcmp(&real_source_ip, &expected_source_ip, sizeof(struct in6_addr)) == 0) {
                return 0;
        }

        return 1;
}

int analyze_ips(char* buffer, uint32_t expected_source_ip){
        struct iphdr *ip_header = (struct iphdr*) buffer;

        uint32_t real_source_ip = ip_header->saddr;

        char real_source_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &real_source_ip, real_source_ip_str, INET_ADDRSTRLEN);

        char expected_source_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &expected_source_ip, expected_source_ip_str, INET_ADDRSTRLEN);

        printf("Comparing IPs:\n");
        printf("Real Source IP: %s vs Expected Source IP: %s\n", real_source_ip_str, expected_source_ip_str);

        if (real_source_ip == expected_source_ip) {
                return 0;
        }

        return 1;
}

int analyze_tcp_response(char* buffer, bool ipv6_mode, uint32_t seq_number){
        struct tcphdr *tcp_header;

        if(ipv6_mode == false){
                struct iphdr *ip_header = (struct iphdr*) buffer;
                tcp_header = (struct tcphdr*)(buffer + (ip_header->ihl * 4));  
        }else{
                tcp_header = (struct tcphdr*) buffer;
        }

        printf("TCP Header:\n");
        printf("\tSource Port: %u\n", ntohs(tcp_header->th_sport));
        printf("\tDestination Port: %u\n", ntohs(tcp_header->th_dport));
        printf("\tSequence Number: %u\n", ntohl(tcp_header->th_seq));
        printf("\tAcknowledgment Number: %u\n", ntohl(tcp_header->th_ack));
        printf("\tData Offset: %u\n", tcp_header->th_off);
        printf("\tFlags: ");
        if (tcp_header->th_flags & TH_SYN) printf("SYN ");
        if (tcp_header->th_flags & TH_ACK) printf("ACK ");
        if (tcp_header->th_flags & TH_RST) printf("RST ");
        if (tcp_header->th_flags & TH_FIN) printf("FIN ");
        printf("\n");
        printf("\tWindow Size: %u\n", ntohs(tcp_header->th_win));
        printf("\tChecksum: 0x%04x\n", ntohs(tcp_header->th_sum));
        printf("\tUrgent Pointer: %u\n", ntohs(tcp_header->th_urp));

        if(ntohl(tcp_header->th_ack) != ntohl(seq_number) + 1){
                return 2;
        }else if(tcp_header->rst){
                return 1;
        }else if(tcp_header->syn && tcp_header->ack){
                return -1;
        }

        return 0;
}

int analyze_udp_response(char* buffer, bool ipv6_mode){

        if(!ipv6_mode){

                struct iphdr *ip_header = (struct iphdr*) buffer;
                struct icmphdr *icmp_header = (struct icmphdr*)(buffer + (ip_header->ihl * 4));

                printf("ICMP Header:\n");
                printf("\tType: %u\n", icmp_header->type);
                printf("\tCode: %u\n", icmp_header->code);
                printf("\tChecksum: 0x%04x\n", ntohs(icmp_header->checksum));

                if(icmp_header->type == 3 && icmp_header->code == 3){
                        return 1;
                }
        
        }else{
        
                struct icmp6_hdr *icmp6_header = (struct icmp6_hdr*)buffer;
                
                printf("ICMPv6 Header:\n");
                printf("\tType: %u\n", icmp6_header->icmp6_type);
                printf("\tCode: %u\n", icmp6_header->icmp6_code);
                printf("\tChecksum: 0x%04x\n", ntohs(icmp6_header->icmp6_cksum));
                
                if(icmp6_header->icmp6_type == 1 && icmp6_header->icmp6_code == 4){
                        return 1;
                }
                
        }
        
        return -1;
}

void scan_tcp_ipv4(uint32_t source_ip, int* ports_array, uint32_t target, int timeout) {
        int raw_socket;
        if(!raw_socket_maker(IPPROTO_TCP, &raw_socket, false)){
                fprintf(stderr, "Error: An error occured opening the raw socket.");
                return;
        }

        struct sockaddr_in target_wrapper;
        memset(&target_wrapper, 0, sizeof(target_wrapper));
        target_wrapper.sin_family = AF_INET;
        target_wrapper.sin_addr.s_addr = target;
        
        struct sockaddr_in src_wrapper;
        src_wrapper.sin_family = AF_INET;
        src_wrapper.sin_addr.s_addr = source_ip;

        if (bind(raw_socket, (struct sockaddr *)&src_wrapper, sizeof(src_wrapper)) == -1) {
                perror("Binding source IP failed");
                close(raw_socket);
                return;
        }
        
        for(int index = 0; index < MAX_PORTS; index++){
                if(ports_array[index]){
                        struct tcphdr tcp_header;
                        int verify_filtered = 0;

                        while(verify_filtered < 2){
                                construct_tcp_header(&target, (uint16_t) index, &tcp_header, false, &source_ip);
                                
                                ssize_t bytes_sent = sendto(raw_socket, &tcp_header, sizeof(tcp_header), 0, (struct sockaddr *)&target_wrapper, sizeof(target_wrapper));

                                if (bytes_sent == -1) {
                                        fprintf(stderr, "Error: Failed to send the packet. Didn't you try to analyze ports outside localhost via lo?  ");
                                        close(raw_socket);
                                        return;
                                }



                                fd_set read_content;
                                FD_ZERO(&read_content);
                                FD_SET(raw_socket, &read_content);

                                struct timeval timeout_struct;
                                timeout_struct.tv_usec = 0;
                                timeout_struct.tv_sec = timeout/1000;

                                int matching_ips = 1;

                                while(matching_ips == 1){

                                        int waiter = select(raw_socket + 1, &read_content, NULL, NULL, &timeout_struct);

                                        if(waiter < 0){
                                                printf("Error: Select() failed.");
                                                close(raw_socket);
                                                return;
                                        }

                                        if(waiter == 0){

                                                matching_ips = 0;

                                                verify_filtered++;

                                                if(verify_filtered == 2){
                                                        printf("%s %d tcp filtered\n", inet_ntoa(target_wrapper.sin_addr), index);
                                                }

                                        }else{
                                                struct sockaddr_in sender;
                                                socklen_t sender_length = sizeof(sender);
                                                char buffer[1024];

                                                ssize_t recieved = recvfrom(raw_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_length);

                                                matching_ips = analyze_ips(buffer, target);

                                                if(matching_ips == 1){
                                                        continue;
                                                }

                                                verify_filtered = 2;

                                                if(recieved > 0){
                                                        int state = analyze_tcp_response(buffer,false, tcp_header.th_seq);
                                                        if(state == -1){
                                                                printf("%s %d tcp open\n", inet_ntoa(target_wrapper.sin_addr), index);
                                                        }else if (state == 1){
                                                                printf("%s %d tcp closed\n", inet_ntoa(target_wrapper.sin_addr), index);
                                                        }else if (state == 2){
                                                                matching_ips = 1;
                                                                continue;
                                                        }
                                                }
                                                break;
                                        }
                                }
                        }
                }
        }
        close(raw_socket);
        return;
}

void scan_tcp_ipv6(struct in6_addr target, int* ports_array, struct in6_addr source_ip, int timeout) {
        int raw_socket;
        if(!raw_socket_maker(IPPROTO_TCP, &raw_socket, true)){
                fprintf(stderr, "Error: An error occured opening the raw socket.");
                return;
        }

        struct sockaddr_in6 target_wrapper;
        memset(&target_wrapper, 0, sizeof(target_wrapper));
        target_wrapper.sin6_family = AF_INET6;
        target_wrapper.sin6_addr = target;
        
        struct sockaddr_in6 src_wrapper;
        src_wrapper.sin6_family = AF_INET6;
        src_wrapper.sin6_addr = source_ip;

        if (bind(raw_socket, (struct sockaddr *)&src_wrapper, sizeof(src_wrapper)) == -1) {
                perror("Binding source IP failed");
                close(raw_socket);
                return;
        }
        
        for(int index = 0; index < MAX_PORTS; index++){
                if(ports_array[index]){
                        struct tcphdr tcp_header;
                        int verify_filtered = 0;

                        char target_ip_str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &target, target_ip_str, sizeof(target_ip_str));

                        while(verify_filtered < 2){
                                construct_tcp_header(&target, (uint16_t) index, &tcp_header, true, &source_ip);
                                
                                ssize_t bytes_sent = sendto(raw_socket, &tcp_header, sizeof(tcp_header), 0, (struct sockaddr *)&target_wrapper, sizeof(target_wrapper));

                                if (bytes_sent == -1) {
                                fprintf(stderr, "Error: Failed to send the packet.");
                                }



                                fd_set read_content;
                                FD_ZERO(&read_content);
                                FD_SET(raw_socket, &read_content);

                                struct timeval timeout_struct;
                                timeout_struct.tv_usec = 0;
                                timeout_struct.tv_sec = timeout/1000;

                                int matching_ips = 1;

                                while(matching_ips == 1){

                                        int waiter = select(raw_socket + 1, &read_content, NULL, NULL, &timeout_struct);

                                        if(waiter < 0){
                                                printf("Error: Select() failed.");
                                                close(raw_socket);
                                                return;
                                        }

                                        if(waiter == 0){

                                                matching_ips = 0;

                                                verify_filtered++;

                                                if(verify_filtered == 2){
                                                        printf("%s %d tcp filtered\n", target_ip_str, index);
                                                }

                                        }else{
                                                struct sockaddr_in6 sender;
                                                socklen_t sender_length = sizeof(sender);
                                                char buffer[1024];

                                                ssize_t recieved = recvfrom(raw_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_length);

                                                matching_ips = analyze_ips6(sender.sin6_addr, target);

                                                if(matching_ips == 1){
                                                       continue;
                                                }

                                                verify_filtered = 2;

                                                if(recieved > 0){
                                                        int state = analyze_tcp_response(buffer, true, tcp_header.th_seq);
                                                        if(state == -1){
                                                                printf("%s %d tcp open\n", target_ip_str, index);
                                                        }else if (state == 1){
                                                                printf("%s %d tcp closed\n", target_ip_str, index);
                                                        }else if(state == 2){
                                                                matching_ips = 1;
                                                                continue;
                                                        }
                                                }
                                                break;
                                        }
                                }
                        }
                }
        }
        close(raw_socket);
        return;
}

void scan_udp_ipv4(uint32_t source_ip, int* ports_array, uint32_t target, int timeout) {
        int raw_socket_send;
        if(!raw_socket_maker(IPPROTO_UDP, &raw_socket_send, false)){
                fprintf(stderr, "Error: An error occured opening the raw socket.");
                return;
        }

        int raw_socket_recieve;
        if(!raw_socket_maker(IPPROTO_ICMP, &raw_socket_recieve, false)){
                fprintf(stderr, "Error: An error occured opening the raw socket.");
                return;
        }

        struct sockaddr_in target_wrapper;
        memset(&target_wrapper, 0, sizeof(target_wrapper));
        target_wrapper.sin_family = AF_INET;
        target_wrapper.sin_addr.s_addr = target;
        
        struct sockaddr_in src_wrapper;
        src_wrapper.sin_family = AF_INET;
        src_wrapper.sin_addr.s_addr = source_ip;

        if (bind(raw_socket_send, (struct sockaddr *)&src_wrapper, sizeof(src_wrapper)) == -1) {
                perror("Binding source IP failed");
                close(raw_socket_recieve);
                close(raw_socket_send);
                return;
        }
        
        for(int index = 0; index < MAX_PORTS; index++){
                if(ports_array[index]){
                        struct udphdr udp_header;

                                construct_udp_header(&target, (uint16_t) index, &udp_header, false, &source_ip);
                                
                                ssize_t bytes_sent = sendto(raw_socket_send, &udp_header, sizeof(udp_header), 0, (struct sockaddr *)&target_wrapper, sizeof(target_wrapper));

                                if (bytes_sent == -1) {
                                fprintf(stderr, "Error: Failed to send the packet.");
                                }



                                fd_set read_content;
                                FD_ZERO(&read_content);
                                FD_SET(raw_socket_recieve, &read_content);

                                struct timeval timeout_struct;
                                timeout_struct.tv_usec = 0;
                                timeout_struct.tv_sec = timeout/1000;

                                int matching_ips = 1;

                                while(matching_ips == 1){

                                        int waiter = select(raw_socket_recieve + 1, &read_content, NULL, NULL, &timeout_struct);

                                        if(waiter < 0){
                                                printf("Error: Select() failed.");
                                                close(raw_socket_recieve);
                                                close(raw_socket_send);
                                                return;
                                        }

                                        if(waiter == 0){

                                                matching_ips = 0;

                                                printf("%s %d udp open\n", inet_ntoa(target_wrapper.sin_addr), index);

                                        }else{
                                                struct sockaddr_in sender;
                                                socklen_t sender_length = sizeof(sender);
                                                char buffer[1024];

                                                ssize_t recieved = recvfrom(raw_socket_recieve, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_length);

                                                matching_ips = analyze_ips(buffer, target);

                                                if(matching_ips == 1){
                                                        continue;
                                                }

                                                if(recieved > 0){
                                                        int state = analyze_udp_response(buffer, false);
                                                        if(state == -1){
                                                                printf("%s %d udp open\n", inet_ntoa(target_wrapper.sin_addr), index);
                                                        }else if (state == 1){
                                                                printf("%s %d udp closed\n", inet_ntoa(target_wrapper.sin_addr), index);
                                                        }
                                                }
                                                break;
                                        }
                                }
                        sleep(1);
                }
        }
        close(raw_socket_recieve);
        close(raw_socket_send);
        return;
}

void scan_udp_ipv6(struct in6_addr source_ip, int* ports_array, struct in6_addr target, int timeout) {
        int raw_socket_send;
        if(!raw_socket_maker(IPPROTO_UDP, &raw_socket_send, true)){
                fprintf(stderr, "Error: An error occured opening the raw socket.");
                return;
        }

        int raw_socket_recieve;
        if(!raw_socket_maker(IPPROTO_ICMPV6, &raw_socket_recieve, true)){
                fprintf(stderr, "Error: An error occured opening the raw socket.");
                return;
        }

        struct sockaddr_in6 target_wrapper;
        memset(&target_wrapper, 0, sizeof(target_wrapper));
        target_wrapper.sin6_family = AF_INET6;
        target_wrapper.sin6_addr = target;
        
        struct sockaddr_in6 src_wrapper;
        src_wrapper.sin6_family = AF_INET6;
        src_wrapper.sin6_addr = source_ip;

        if (bind(raw_socket_send, (struct sockaddr *)&src_wrapper, sizeof(src_wrapper)) == -1) {
                perror("Binding source IP failed");
                close(raw_socket_send);
                close(raw_socket_recieve);
                return;
        }
        
        for(int index = 0; index < MAX_PORTS; index++){
                if(ports_array[index]){
                        struct udphdr udp_header;
                        
                        char target_ip_str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &target, target_ip_str, sizeof(target_ip_str));

                                construct_udp_header(&target, (uint16_t) index, &udp_header, true, &source_ip);
                                
                                ssize_t bytes_sent = sendto(raw_socket_send, &udp_header, sizeof(udp_header), 0, (struct sockaddr *)&target_wrapper, sizeof(target_wrapper));

                                if (bytes_sent == -1) {
                                fprintf(stderr, "Error: Failed to send the packet.");
                                }



                                fd_set read_content;
                                FD_ZERO(&read_content);
                                FD_SET(raw_socket_recieve, &read_content);

                                struct timeval timeout_struct;
                                timeout_struct.tv_usec = 0;
                                timeout_struct.tv_sec = timeout/1000;

                                int matching_ips = 1;

                                while(matching_ips == 1){

                                        int waiter = select(raw_socket_recieve + 1, &read_content, NULL, NULL, &timeout_struct);

                                        if(waiter < 0){
                                                printf("Error: Select() failed.");
                                                close(raw_socket_recieve);
                                                close(raw_socket_send);
                                                return;
                                        }

                                        if(waiter == 0){

                                                matching_ips = 0;

                                                printf("%s %d udp open\n", target_ip_str, index);

                                        }else{
                                                struct sockaddr_in6 sender;
                                               socklen_t sender_length = sizeof(sender);
                                                char buffer[1024];

                                                ssize_t recieved = recvfrom(raw_socket_recieve, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_length);

                                                matching_ips = analyze_ips6(sender.sin6_addr, target);

                                                if(matching_ips == 1){
                                                        continue;
                                                }

                                                if(recieved > 0){
                                                        int state = analyze_udp_response(buffer, true);
                                                        if(state == -1){
                                                                printf("%s %d udp open\n", target_ip_str, index);
                                                        }else if (state == 1){
                                                                printf("%s %d udp closed\n", target_ip_str, index);
                                                        }
                                                }
                                                break;
                                        }
                                }
                        sleep(1);
                }
        }
        close(raw_socket_recieve);
        close(raw_socket_send);
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
                        scan_tcp_ipv4((uint32_t)ipv4->sin_addr.s_addr, tcp_ports, source_ipv4, DEFAULT_TIMEOUT);
                        scan_udp_ipv4((uint32_t)ipv4->sin_addr.s_addr, udp_ports, source_ipv4, DEFAULT_TIMEOUT);
                        
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
                        scan_tcp_ipv6(ipv6->sin6_addr, tcp_ports, source_ipv6, DEFAULT_TIMEOUT);
                        scan_udp_ipv6(ipv6->sin6_addr, udp_ports, source_ipv6, DEFAULT_TIMEOUT);
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
	        
                struct in_addr target_ipv4;
	        uint32_t source_ipv4;
	        
                if(!convert_source_ip(interface, (void *) &source_ipv4, false)){
	                return 1;
	        }

                if(inet_pton(AF_INET, target, &target_ipv4) != 1){
                        fprintf(stderr, "Error: The conversion of the target IP from string to uint_32 failed.");
                        return 1;
                }

	        scan_tcp_ipv4(source_ipv4, tcp_ports, target_ipv4.s_addr, DEFAULT_TIMEOUT);
                scan_udp_ipv4(source_ipv4, udp_ports, target_ipv4.s_addr, DEFAULT_TIMEOUT);
	}else{
	        struct in6_addr converted_ipv6;
	        
	        if(inet_pton(AF_INET6, target, &converted_ipv6) != 1)
	                fprintf(stderr, "Error: An error occured converting the target IP address to ip6_addr struct.");
	        
	        struct in6_addr source_ipv6;
	        if(!convert_source_ip(interface, (void *) &source_ipv6, true)){
	                fprintf(stderr, "Error: The selected interface does not support ipv6 communication.");
	                return 1;
	        }
	        
	        scan_tcp_ipv6(converted_ipv6, tcp_ports, source_ipv6, DEFAULT_TIMEOUT);
                scan_udp_ipv6(converted_ipv6, udp_ports, source_ipv6, DEFAULT_TIMEOUT);
	}
	return 0;
}
