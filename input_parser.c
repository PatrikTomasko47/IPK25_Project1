/**
 * @file input_parser.c
 * @brief Contains functions used to parse the user input.
 *
 *
 * @author Patrik Tomasko (xtomasp00)
 * @date 2025-03-27
 */

#include <stdlib.h>
#include <stdio.h>
#include <regex.h>
#include <ctype.h>
#include <string.h>
#include <getopt.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ifaddrs.h>

#include "input_parser.h"
#include "ip_utility.h"

#define DOMAIN_REGEX "^(([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\\.)+[a-zA-Z]{2,})$" //regex used to verify wether user entered a valid domain name

bool is_number(const char* string){

        if(*string == '\0') //string is empty
                return false;
        
        for(int index = 0; string[index] != '\0'; index++){

                if(!isdigit(string[index]))
                        return false;

        }

        return true;

}

bool port_parser(char* ports_string, int* ports_array, bool* filled){

        char* number = strtok(ports_string, ",");

        while(number){
                        
                if(strchr(number, '-')){

                        char start_str[6];
                        char end_str[6];
                        int start, end;

                        if(sscanf(number, "%5[^-]-%5s", start_str, end_str) == 2){

                                if(!is_number(start_str) || !is_number(end_str)){

                                        fprintf(stderr, "Error: A non-number value has been detected in the port range.\n");
                                        return false;

                                }

                                start = atoi(start_str);
                                end = atoi(end_str);

                                if(start > end || start <= 0 || end > MAX_PORTS){

                                        fprintf(stderr, "Error: The values in the port range are in the wrong order. The value to the left (%d) has to be smaller than the value on the right (%d).\n", start, end);
                                        return false;

                                }

                                for(int index = start; index <= end; index++){ //adding everything in between

                                        ports_array[index] = 1;
                                        *filled = true;

                                }

                        }else{

                                fprintf(stderr, "Error: Unexpected value detected in the port range. Know that in ranges, the number to the left has to be smaller or equal to the number to the right.\n");
                                return false;

                        }

                }else{

                        if(!is_number(number)){

                                fprintf(stderr, "Error: A non-number value has been detected in the ports to be scanned.\n");
                                return false;

                        }

                        int value = atoi(number);

                        if(value > 0 && value <= MAX_PORTS){

                                ports_array[value] = 1;
                                *filled = true;

                        }else{

                                fprintf(stderr, "Error: The port you entered (%d) is out of the allowed range.\n", value);
                                return false;

                        }

                }

                number = strtok(NULL, ",");

        }

        return true;

}

int get_input_params(int argc, char *argv[], char** interface, int* wait, char** target, char** udp_ports_string, char** tcp_ports_string){

        //used to see wether the user input certain important values
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

                                        if(!*interface){ //checking wether user hasn't already input it

                                                *interface = argv[optind];
                                                interface_input = false;

                                        }else{

                                                fprintf(stderr, "Error: multiple -i/--interface inputs were detected.\n");
                                                return 1;

                                        }

                                }else{
                                        //has to do it manually like this since I needed to be able to have an empty -i flag but it wasn't cooperating
                                        if (optind < argc && argv[optind][0] != '-') {

                                                if (!*interface) {

                                                        interface_input = true;
                                                        *interface = argv[optind];
                                                        optind++;

                                                } else {

                                                        fprintf(stderr, "Error: multiple -i/--interface inputs detected.\n");
                                                        return 1;

                                                }

                                        }else{

                                                if(!interface_input){ //empty -i

                                                        interface_input = true;

                                                }else{

                                                        fprintf(stderr, "Error: multiple -i/--interface inputs were detected.\n");
                                                        return 1;
                                                        
                                                }

                                        }

                                }
                                break;

                        case 'w':

                                if(is_number(optarg)){

                                        if(!wait_input){ ///checking for duplicates

                                                *wait = atoi(optarg);
                                                wait_input = 0;

                                        }else{

                                                fprintf(stderr, "Error: multiple -w/--wait inputs were detected.\n");
                                                return 1;

                                        }

                                }else{

                                        fprintf(stderr, "Error: Timeout value has to be a nubmer.\n");
                                        return 1;

                                }
                                break;

                        case 't':

                                if(!*tcp_ports_string){ //checking for duplicates

                                        *tcp_ports_string = optarg;

                                }else{

                                        fprintf(stderr, "Error: multiple -t/--pt inputs were detected.\n");
                                        return 1;

                                }
                                break;

                        case 'u':

                                if(!*udp_ports_string){ //checking for duplicates

                                        *udp_ports_string = optarg;

                                }else{

                                        fprintf(stderr, "Error: multiple -u/--pu inputs were detected.\n");
                                        return 1;

                                }

                                break;

                        case '?':

                                fprintf(stderr, "Error: An unknown flag was '%c' detected.\n", flag);
                                return 1;

                        default:

                                fprintf(stderr, "Error: An error occured whilst parsing through the flags.\n");
                                return 1;

                }
        }

        if(argc == 1){ //user didn't input anything

                if(!print_available_interfaces()){

                        return 1;

                }else{

                        return 2;

                }

        }

        if(interface_input && !*interface && !wait_input && !*udp_ports_string && !*tcp_ports_string && optind >= argc){ //the user only input enpty -i meaning interface will get printed

                if(!print_available_interfaces()){

                        return 1;

                }else{

                        return 2;

                }

        }

        if (optind < argc){ //looking for target

                *target = argv[optind];
                optind++;

        }else{

                fprintf(stderr, "Error: No target specified.\n");
                return 1;

        }

        if(optind < argc){

                fprintf(stderr, "Error: An unexpected argument was detected after the target.\n");
                return 1;

        }

        if(!*udp_ports_string && !*tcp_ports_string){

                fprintf(stderr, "Error: At least a single UDP or TCP port has to be specified.\n");
                return 1;

        }

        if(!*interface){

                fprintf(stderr, "Error: No interface specified. To wiev available interfaces -> './ipk-l4-scan -i' or './ipk-l4-scan'.\n");
                return 1;

        }

        return 0;
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

                int match = regexec(&regex, target, 0, NULL, 0);//using regex to check for domain
                regfree(&regex);

                if (match == 0){

                        return TYPE_DOMAIN;

                }

        }

        if(strcmp(target, "localhost") == 0){

                return TYPE_LOCALHOST;

        }
        
        return TYPE_UNKNOWN;	
}