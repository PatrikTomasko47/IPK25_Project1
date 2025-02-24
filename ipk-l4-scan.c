#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <stdbool.h>
#include <ifaddrs.h>
#include <regex.h>
#include <arpa/inet.h>

#define DEFAULT_TIMEOUT 5000 //the default timeout if the user doesn't specify otherwise
#define DOMAIN_REGEX "^([a-zA-Z0-9][-a-zA-Z0-9]*\\.)+[a-zA-Z]{2,}$" //regex used to verify wether user entered a valid domain name

typedef enum {
    TYPE_UNKNOWN,
    TYPE_IPV4,
    TYPE_IPV6,
    TYPE_DOMAIN
} target_type;

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

        bool interface_input = false;
        bool target_input = false;
        bool wait_input = false;
        
	static struct option long_options[] = {
		{"interface", optional_argument, NULL, 'i'},
		{"wait", optional_argument, NULL, 'w'},
		{"pt", optional_argument, NULL, 't'},
		{"pu", optional_argument, NULL, 'u'},
		{0, 0, 0, 0}
	};

	int flag;
	while((flag = getopt_long(argc, argv, "i::w:", long_options, NULL)) != -1){
		switch(flag){
			case 'i':
                                if(optind < argc && argv[optind][0] != '-'){
                                        if(!interface_input){
				                *interface = argv[optind];
                                                optind++;
                                                interface_input = true;
                                        }else{
                                                printf("Don't do the input interface thingy multiple times dumbass.");
                                                return false;
                                        }
				}else{
				        if(!print_available_interfaces()){
				                return false;
				        }
				}
				break;
			case 'w':
			        if(optarg && isdigit(*optarg)){
			                if(!wait_input){
			                        *wait = atoi(optarg);
			                        wait_input = true;
			                }else{
			                        printf("Don't do the input timeout thingy multiple times dumbass.");
                                                return false;
			                }
			        }else{
			                printf("Timeout has to be a nubmer. \n");
			                return false;
			        }
			        break;
			case 't':
			
			case '?':
				printf("What the heeeeeeeel, oh my god no wayay. \n");
				return false;
			default:
				printf("Something went wrong with the flags. \n");
				return false;
		}
	}
	
	if (optind < argc){
	        *target = argv[optind];
	}else{
	        printf("No target specified \n");
	        return false;
	}
	
	return true;
}

int main(int argc, char *argv[]){
        int timeout = DEFAULT_TIMEOUT;
	char* interface = NULL;
	char* target = NULL;
	
	if(get_input_params(argc, argv, &interface, &timeout, &target) && interface){
		printf("%s %s %d \n", interface, target, timeout);
	}
}
