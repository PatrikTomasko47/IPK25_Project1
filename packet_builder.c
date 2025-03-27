#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "packet_builder.h"

uint16_t sum_calculator(void *data, int length){
        uint32_t sum = 0;
        uint16_t o_byte = 0; // odd_byte
        uint16_t* pointer = (uint16_t*)data;
        
        while(length > 1){

                sum = sum + *pointer++;
                length = length - 2;

        }
        
        if(length == 1){

                *(unsigned char*)(&o_byte) = *(unsigned char*)pointer; //adding the odd_byte value
                sum = sum + o_byte;

        }
        
        uint32_t carry = sum >> 16;
        sum = (sum & 0xFFFF) + carry; //adding upper bits to the lower ones
        sum = sum + (sum >> 16); //adding any leftover carry
        return ~sum; //invert
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
                
                final_length = sizeof(struct pseudo_header_ipv6) + udp_length; //length of the data that will be given to calculate checksum
                buffer = malloc(final_length);
                
                memcpy(buffer, &p_header, sizeof(struct pseudo_header_ipv6));
                memcpy(buffer + sizeof(struct pseudo_header_ipv6) / 2, udp_header, udp_length); //copying the headers for the checksum calculation

        }else{

                struct pseudo_header_ipv4 p_header;

                p_header.source_ip = *((uint32_t *)source_ip);
                p_header.destination_ip = *((uint32_t *)dest_ip);
                p_header.zero = 0;
                p_header.protocol = IPPROTO_UDP;
                p_header.udp_tcp_length = htons(udp_length);
                
                final_length = sizeof(struct pseudo_header_ipv4) + udp_length; //length of the data that will be given to calculate checksum
                buffer = malloc(final_length);
                
                memcpy(buffer, &p_header, sizeof(struct pseudo_header_ipv4));
                memcpy(buffer + sizeof(struct pseudo_header_ipv4) / 2, udp_header, udp_length); //copying the headers for the checksum calculation

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
                
                final_length = sizeof(struct pseudo_header_ipv6) + tcp_length; //length of the data that will be given to calculate checksum
                buffer = malloc(final_length);
                
                memcpy(buffer, &p_header, sizeof(struct pseudo_header_ipv6));
                memcpy(buffer + sizeof(struct pseudo_header_ipv6) / 2, tcp_header, tcp_length); //copying the headers for the checksum calculation

        }else{

                struct pseudo_header_ipv4 p_header;
                p_header.source_ip = *((uint32_t *)source_ip);
                p_header.destination_ip = *((uint32_t *)dest_ip);
                p_header.zero = 0;
                p_header.protocol = IPPROTO_TCP;
                p_header.udp_tcp_length = htons(tcp_length);
                
                final_length = sizeof(struct pseudo_header_ipv4) + tcp_length; //length of the data that will be given to calculate checksum
                buffer = malloc(final_length);
                
                memcpy(buffer, &p_header, sizeof(struct pseudo_header_ipv4));
                memcpy(buffer + sizeof(struct pseudo_header_ipv4) / 2, tcp_header, tcp_length); //copying the headers for the checksum calculation

        }
        
        uint16_t checksum_value = sum_calculator(buffer, final_length);
        free(buffer);
        
        //printf("Calculated %d\n",checksum_value);
        return checksum_value;
}

void construct_tcp_header(void* target_ip, uint16_t destination_port, struct tcphdr* header, bool ipv6_mode, void* source_ip){

        memset(header, 0, sizeof(struct tcphdr));
        
        header->th_seq = htonl(rand());
        header->th_flags = TH_SYN;
        header->th_off = 5;
        header->th_win = htons(65535);
        header->th_sport = htons(SOURCE_PORT);
        header->th_dport = htons(destination_port);
        header->th_sum = 0; //temporary
        
        uint16_t sum = tcp_checksum(source_ip, target_ip, header, sizeof(struct tcphdr), ipv6_mode);
        header->th_sum = sum;
        
        return ;
        
}

void construct_udp_header(void* target_ip, uint16_t destination_port, struct udphdr* header, bool ipv6_mode, void* source_ip){

        memset(header, 0, sizeof(struct udphdr));
        
        header->uh_ulen = htons(sizeof(struct udphdr));
        header->uh_sport = htons(SOURCE_PORT);
        header->uh_dport = htons(destination_port);
        header->uh_sum = 0; //temporary
        
        uint16_t checksum = udp_checksum(source_ip, target_ip, header, sizeof(struct udphdr), ipv6_mode);
        header->uh_sum = checksum;
        
        return ;

}