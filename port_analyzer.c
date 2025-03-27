#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>

#include "port_analyzer.h"
#include "packet_builder.h"

bool raw_socket_maker(int protocol, int* socket_var, bool ipv6_mode){

        int inet_type = AF_INET;

        if(ipv6_mode == true) 
                inet_type = AF_INET6;
        

        *socket_var = socket(inet_type, SOCK_RAW, protocol);

        if(socket_var < 0){

                fprintf(stderr, "Error: The creation of a raw socket failed.\n");
                return false;

        }

        return true;

}

int analyze_ips6(struct in6_addr real_source_ip, struct in6_addr expected_source_ip){

        //conversion of the ip to string
        char real_source_ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &real_source_ip, real_source_ip_str, INET6_ADDRSTRLEN);

        char expected_source_ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &expected_source_ip, expected_source_ip_str, INET6_ADDRSTRLEN);

        /*printf("Comparing IPs:\n");
        printf("Real Source IP: %s vs Expected Source IP: %s\n", real_source_ip_str, expected_source_ip_str);*/

        if (memcmp(&real_source_ip, &expected_source_ip, sizeof(struct in6_addr)) == 0)
                return 0;

        return 1;
}

int analyze_ips(char* buffer, uint32_t expected_source_ip){

        //extracting the ip header
        struct iphdr *ip_header = (struct iphdr*) buffer;

        uint32_t real_source_ip = ip_header->saddr;

        //conversion of the ip to string
        char real_source_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &real_source_ip, real_source_ip_str, INET_ADDRSTRLEN);

        char expected_source_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &expected_source_ip, expected_source_ip_str, INET_ADDRSTRLEN);

        /*printf("Comparing IPs:\n");
        printf("Real Source IP: %s vs Expected Source IP: %s\n", real_source_ip_str, expected_source_ip_str);*/

        if (real_source_ip == expected_source_ip)
                return 0;

        return 1;
}

int analyze_tcp_response(char* buffer, bool ipv6_mode, uint32_t seq_number){

        struct tcphdr *tcp_header;

        //extracting the tcp header
        if(ipv6_mode == false){

                struct iphdr* ip_header = (struct iphdr*)buffer;
                tcp_header = (struct tcphdr*)(buffer + (ip_header->ihl * 4)); 

        }else{

                tcp_header = (struct tcphdr*) buffer;

        }

        /*printf("TCP Header:\n");
        printf("Source Port: %u\n", ntohs(tcp_header->th_sport));
        printf("Destination Port: %u\n", ntohs(tcp_header->th_dport));
        printf("Sequence Number: %u\n", ntohl(tcp_header->th_seq));
        printf("Acknowledgment Number: %u\n", ntohl(tcp_header->th_ack));
        printf("Flags: ");
        if (tcp_header->th_flags & TH_SYN) printf("SYN ");
        if (tcp_header->th_flags & TH_ACK) printf("ACK ");
        if (tcp_header->th_flags & TH_RST) printf("RST ");
        if (tcp_header->th_flags & TH_FIN) printf("FIN ");*/

        if(ntohl(tcp_header->th_ack) != ntohl(seq_number) + 1){ //comparing wether the seq numbers match

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

            struct iphdr* ip_header = (struct iphdr*)buffer;
            struct icmphdr* icmp_header = (struct icmphdr*)(buffer + (ip_header->ihl * 4));

            /*printf("ICMP Header:\n");
            printf("Type: %u\n", icmp_header->type);
            printf("Code: %u\n", icmp_header->code);
            printf("Checksum: 0x%04x\n", ntohs(icmp_header->checksum));*/

            if(icmp_header->type == 3 && icmp_header->code == 3)
                    return 1;
    
    }else{
    
            struct icmp6_hdr* icmp6_header = (struct icmp6_hdr*)buffer;
            
            /*printf("ICMPv6 Header:\n");
            printf("Type: %u\n", icmp6_header->icmp6_type);
            printf("Code: %u\n", icmp6_header->icmp6_code);
            printf("Checksum: 0x%04x\n", ntohs(icmp6_header->icmp6_cksum));*/
            
            if(icmp6_header->icmp6_type == 1 && icmp6_header->icmp6_code == 4)
                    return 1;
            
    }
    
    return -1;

}

bool scan_tcp_ipv4(uint32_t source_ip, int* ports_array, uint32_t target, int timeout) {

        struct sockaddr_in target_wrapper;
        memset(&target_wrapper, 0, sizeof(target_wrapper));
        target_wrapper.sin_family = AF_INET;
        target_wrapper.sin_addr.s_addr = target;
        
        for(int index = 0; index < MAX_PORTS; index++){

                if(ports_array[index]){

                        int raw_socket;

                        if(!raw_socket_maker(IPPROTO_TCP, &raw_socket, false))
                                return false;

                        struct sockaddr_in src_wrapper;
                        src_wrapper.sin_family = AF_INET;
                        src_wrapper.sin_addr.s_addr = source_ip;
                        src_wrapper.sin_port = htons(index);
                        
                        if (bind(raw_socket, (struct sockaddr *)&src_wrapper, sizeof(src_wrapper)) == -1) { //binding the socket to source ip
                                        
                                fprintf(stderr,"Error: Binding source IP failed.\n");
                                close(raw_socket);
                                return false;
                        
                        }
                        
                        struct tcphdr tcp_header;
                        int verify_filtered = 0;

                        while(verify_filtered < 2){ //trying until two timeouts

                                construct_tcp_header(&target, (uint16_t) index, &tcp_header, false, &source_ip);
                                
                                ssize_t bytes_sent = sendto(raw_socket, &tcp_header, sizeof(tcp_header), 0, (struct sockaddr*)&target_wrapper, sizeof(target_wrapper));

                                if (bytes_sent == -1) {

                                        fprintf(stderr, "Error: Failed to send the packet. Didn't you try to analyze ports outside localhost via lo?\n");
                                        close(raw_socket);
                                        return false;

                                }



                                fd_set read_content;

                                struct timeval timeout_struct, start_time, recieve_time;

                                int elapsed_time = 0;

                                gettimeofday(&start_time, NULL);

                                int matching_ips = 1; //used to determine and await a packet coming from the correct IP address

                                while(matching_ips == 1){

                                        gettimeofday(&recieve_time, NULL);

                                        elapsed_time = (recieve_time.tv_sec - start_time.tv_sec) * 1000 + (recieve_time.tv_usec - start_time.tv_usec) / 1000;

                                        int remaining_time = timeout - elapsed_time; //updating the time in case of recieving a packet that is not from the scanning target

                                        if(remaining_time < 0)
                                                remaining_time = 0;

                                        int waiter = 0;

                                        if(remaining_time != 0){

                                                timeout_struct.tv_sec = remaining_time / 1000;
                                                timeout_struct.tv_usec = (remaining_time % 1000) * 1000;

                                                FD_ZERO(&read_content);
                                                FD_SET(raw_socket, &read_content);

                                                waiter = select(raw_socket + 1, &read_content, NULL, NULL, &timeout_struct);

                                        }

                                        if(waiter < 0){

                                                printf("Error: Select() failed.\n");
                                                close(raw_socket);
                                                return false;

                                        }

                                        if(waiter == 0){

                                                matching_ips = 0;

                                                verify_filtered++;

                                                if(verify_filtered == 2)  //timed out two times
                                                        printf("%s %d tcp filtered\n", inet_ntoa(target_wrapper.sin_addr), index);


                                        }else{

                                                struct sockaddr_in sender;
                                                socklen_t sender_length = sizeof(sender);
                                                char buffer[1024];

                                                ssize_t recieved = recvfrom(raw_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_length);

                                                matching_ips = analyze_ips(buffer, target); //checking wether the ips match

                                                if(matching_ips == 1) //skip if not
                                                        continue;

                                                if(recieved > 0){

                                                        int state = analyze_tcp_response(buffer,false, tcp_header.th_seq);

                                                        if(state == -1){

                                                                printf("%s %d tcp open\n", inet_ntoa(target_wrapper.sin_addr), index);
                                                                verify_filtered = 2;

                                                        }else if (state == 1){

                                                                printf("%s %d tcp closed\n", inet_ntoa(target_wrapper.sin_addr), index);
                                                                verify_filtered = 2;

                                                        }else if (state == 2){

                                                                matching_ips = 1;
                                                                continue;

                                                        }

                                                }

                                                break;

                                        }

                                }

                        }

                        close(raw_socket);

                }

        }

        return true;

}

bool scan_tcp_ipv6(struct in6_addr target, int* ports_array, struct in6_addr source_ip, int timeout) {

        struct sockaddr_in6 target_wrapper;
        memset(&target_wrapper, 0, sizeof(target_wrapper));
        target_wrapper.sin6_family = AF_INET6;
        target_wrapper.sin6_addr = target;
        
        for(int index = 0; index < MAX_PORTS; index++){

                if(ports_array[index]){

                        int raw_socket;
                        if(!raw_socket_maker(IPPROTO_TCP, &raw_socket, true))
                                return false;

                        struct sockaddr_in6 src_wrapper;
                        memset(&src_wrapper, 0, sizeof(src_wrapper));
                        src_wrapper.sin6_family = AF_INET6;
                        src_wrapper.sin6_addr = source_ip;
                        src_wrapper.sin6_port = htons(index);
                        
                        if (bind(raw_socket, (struct sockaddr *)&src_wrapper, sizeof(src_wrapper)) == -1) { //binding the socket to source ip
                                fprintf(stderr,"Error: Binding source IP failed.\n");
                                close(raw_socket);
                                return false;
                        }

                        struct tcphdr tcp_header;
                        int verify_filtered = 0;

                        char target_ip_str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &target, target_ip_str, sizeof(target_ip_str));

                        while(verify_filtered < 2){ //trying until two timeouts

                                construct_tcp_header(&target, (uint16_t) index, &tcp_header, true, &source_ip);
                                
                                ssize_t bytes_sent = sendto(raw_socket, &tcp_header, sizeof(tcp_header), 0, (struct sockaddr *)&target_wrapper, sizeof(target_wrapper));

                                if (bytes_sent == -1)
                                fprintf(stderr, "Error: Failed to send the packet.\n");

                                fd_set read_content;
                                FD_ZERO(&read_content);
                                FD_SET(raw_socket, &read_content);

                                struct timeval timeout_struct;
                                timeout_struct.tv_usec = (timeout % 1000) * 1000;
                                timeout_struct.tv_sec = timeout / 1000;

                                int matching_ips = 1; //used to determine and await a packet coming from the correct IP address

                                while(matching_ips == 1){

                                        int waiter = select(raw_socket + 1, &read_content, NULL, NULL, &timeout_struct);

                                        if(waiter < 0){

                                                fprintf(stderr,"Error: Select() failed.\n");
                                                close(raw_socket);
                                                return false;

                                        }

                                        if(waiter == 0){

                                                matching_ips = 0;

                                                verify_filtered++;

                                                if(verify_filtered == 2) //timed out two times
                                                        printf("%s %d tcp filtered\n", target_ip_str, index);

                                        }else{

                                                struct sockaddr_in6 sender;
                                                socklen_t sender_length = sizeof(sender);
                                                char buffer[1024];

                                                ssize_t recieved = recvfrom(raw_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_length);

                                                matching_ips = analyze_ips6(sender.sin6_addr, target); //checking for ip match

                                                if(matching_ips == 1) //skip if no match
                                                        continue;

                                                if(recieved > 0){

                                                        int state = analyze_tcp_response(buffer, true, tcp_header.th_seq);

                                                        if(state == -1){

                                                                printf("%s %d tcp open\n", target_ip_str, index);
                                                                verify_filtered = 2;

                                                        }else if (state == 1){

                                                                printf("%s %d tcp closed\n", target_ip_str, index);
                                                                verify_filtered = 2;

                                                        }else if(state == 2){

                                                                matching_ips = 1;
                                                                continue;

                                                        }

                                                }

                                                break;

                                        }

                                }

                        }

                        close(raw_socket);

                }

        }

        return true;

}

bool scan_udp_ipv4(uint32_t source_ip, int* ports_array, uint32_t target, int timeout) {

        //making two sockets since the udp one is for sending and icmp for recieving

        int raw_socket_recieve;
        if(!raw_socket_maker(IPPROTO_ICMP, &raw_socket_recieve, false))
                return false;

        struct sockaddr_in target_wrapper;
        memset(&target_wrapper, 0, sizeof(target_wrapper));
        target_wrapper.sin_family = AF_INET;
        target_wrapper.sin_addr.s_addr = target;
        
        for(int index = 0; index < MAX_PORTS; index++){

                if(ports_array[index]){

                                int raw_socket_send;
                                if(!raw_socket_maker(IPPROTO_UDP, &raw_socket_send, false))
                                        return false;

                                struct sockaddr_in src_wrapper;
                                src_wrapper.sin_family = AF_INET;
                                src_wrapper.sin_addr.s_addr = source_ip;
                                src_wrapper.sin_port = htons(index);

                        
                                if (bind(raw_socket_send, (struct sockaddr *)&src_wrapper, sizeof(src_wrapper)) == -1) { //binding the udp socket to source ip
                                        fprintf(stderr,"Error: Binding source IP failed.\n");
                                        close(raw_socket_recieve);
                                        close(raw_socket_send);
                                        return false;
                                }

                                struct udphdr udp_header;

                                construct_udp_header(&target, (uint16_t) index, &udp_header, false, &source_ip);
                                
                                ssize_t bytes_sent = sendto(raw_socket_send, &udp_header, sizeof(udp_header), 0, (struct sockaddr*)&target_wrapper, sizeof(target_wrapper));

                                if (bytes_sent == -1) 
                                        fprintf(stderr, "Error: Failed to send the packet.\n");

                                fd_set read_content;
                                FD_ZERO(&read_content);
                                FD_SET(raw_socket_recieve, &read_content);

                                struct timeval timeout_struct;
                                timeout_struct.tv_usec = (timeout % 1000) * 1000;
                                timeout_struct.tv_sec = timeout / 1000;

                                int matching_ips = 1; //catching packets until the ip of the source matches to the one we sent to

                                while(matching_ips == 1){

                                        int waiter = select(raw_socket_recieve + 1, &read_content, NULL, NULL, &timeout_struct);

                                        if(waiter < 0){

                                                printf("Error: Select() failed.\n");
                                                close(raw_socket_recieve);
                                                close(raw_socket_send);
                                                return false;

                                        }

                                        if(waiter == 0){

                                                matching_ips = 0;

                                                printf("%s %d udp open\n", inet_ntoa(target_wrapper.sin_addr), index);

                                        }else{

                                                struct sockaddr_in sender;
                                                socklen_t sender_length = sizeof(sender);
                                                char buffer[1024];

                                                ssize_t recieved = recvfrom(raw_socket_recieve, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_length);

                                                matching_ips = analyze_ips(buffer, target); //checking for matching ips

                                                if(matching_ips == 1) //skip if ips dont match
                                                        continue;

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
                        close(raw_socket_send);
                        sleep(1); //waiting a second after each udp request so that i don't get blacklisted from any server

                }

        }

        close(raw_socket_recieve);
        return true;

}

bool scan_udp_ipv6(struct in6_addr target, int* ports_array, struct in6_addr source_ip, int timeout) {

        //making two sockets since the udp one is for sending and icmp for recieving

        int raw_socket_recieve;
        if(!raw_socket_maker(IPPROTO_ICMPV6, &raw_socket_recieve, true))
                return false;

        struct sockaddr_in6 target_wrapper;
        memset(&target_wrapper, 0, sizeof(target_wrapper));
        target_wrapper.sin6_family = AF_INET6;
        target_wrapper.sin6_addr = target;
        
        for(int index = 0; index < MAX_PORTS; index++){

                if(ports_array[index]){

                                int raw_socket_send;
                                if(!raw_socket_maker(IPPROTO_UDP, &raw_socket_send, true))
                                        return false;

                                struct sockaddr_in6 src_wrapper;
                                memset(&src_wrapper, 0, sizeof(src_wrapper));
                                src_wrapper.sin6_family = AF_INET6;
                                src_wrapper.sin6_addr = source_ip;
                                src_wrapper.sin6_port = htons(index);

                        
                                if (bind(raw_socket_send, (struct sockaddr *)&src_wrapper, sizeof(src_wrapper)) == -1) { //binding the socket to source ip
                        
                                        fprintf(stderr,"Error: Binding source IP failed.\n");
                                        close(raw_socket_send);
                                        close(raw_socket_recieve);
                                        return false;
                        
                                }

                                struct udphdr udp_header;
                                
                                char target_ip_str[INET6_ADDRSTRLEN];
                                inet_ntop(AF_INET6, &target, target_ip_str, sizeof(target_ip_str));

                                construct_udp_header(&target, (uint16_t) index, &udp_header, true, &source_ip);
                                
                                ssize_t bytes_sent = sendto(raw_socket_send, &udp_header, sizeof(udp_header), 0, (struct sockaddr *)&target_wrapper, sizeof(target_wrapper));

                                if (bytes_sent == -1)
                                fprintf(stderr, "Error: Failed to send the packet.\n");



                                fd_set read_content;
                                FD_ZERO(&read_content);
                                FD_SET(raw_socket_recieve, &read_content);

                                struct timeval timeout_struct;
                                timeout_struct.tv_usec = (timeout % 1000) * 1000;
                                timeout_struct.tv_sec = timeout / 1000;

                                int matching_ips = 1; //catching packets until the ip of the source matches to the one we sent to

                                while(matching_ips == 1){

                                        int waiter = select(raw_socket_recieve + 1, &read_content, NULL, NULL, &timeout_struct);

                                        if(waiter < 0){

                                                printf("Error: Select() failed.\n");
                                                close(raw_socket_recieve);
                                                close(raw_socket_send);
                                                return false;

                                        }

                                        if(waiter == 0){

                                                matching_ips = 0;

                                                printf("%s %d udp open\n", target_ip_str, index);

                                        }else{

                                                struct sockaddr_in6 sender;
                                                socklen_t sender_length = sizeof(sender);
                                                char buffer[1024];

                                                ssize_t recieved = recvfrom(raw_socket_recieve, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_length);

                                                matching_ips = analyze_ips6(sender.sin6_addr, target); //checking for matching ips

                                                if(matching_ips == 1)//skip bcs ips dont match
                                                        continue;

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

                        close(raw_socket_send);
                        sleep(1); //waiting a second after each udp request so that i don't get blacklisted from any server

                }

        }

        close(raw_socket_recieve);
        return true;
        
}