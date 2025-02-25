#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <string.h>
#include <stdbool.h>
#include <ifaddrs.h>
#include <regex.h>
#include <arpa/inet.h>

#define DEFAULT_TIMEOUT 5000 //the default timeout if the user doesn't specify otherwise
#define DOMAIN_REGEX "^([a-zA-Z0-9][-a-zA-Z0-9]*\\.)+[a-zA-Z]{2,}$" //regex used to verify wether user entered a valid domain name
#define MAX_PORTS 65535 //maximum ammount of possible ports to scan through

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
        char* number = strtok(port_string, ",");
        while(number){
        
        }
}

int main(int argc, char *argv[]){
        int timeout = DEFAULT_TIMEOUT;
	char* interface = NULL;
	char* target = NULL;
	char* tcp_ports_string = NULL;
	char* udp_ports_string = NULL;
	//int tcp_ports[MAX_PORTS] = {0};
	//int udp_ports[MAX_PORTS] = {0};
	
	if(!get_input_params(argc, argv, &interface, &timeout, &target, &udp_ports_string, &tcp_ports_string) && interface){
		printf("%s %s %d \n", interface, target, timeout);
		return;
	}
}
