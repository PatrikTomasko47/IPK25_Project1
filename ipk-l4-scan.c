#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>

#define DEFAULT_TIMEOUT 5000 //the default timeout if the user doesn't specify otherwise

bool get_input_params(int argc, char *argv[], char** interface){
	static struct option long_options[] = {
		{"interface", optional_argument, NULL, 'i'},
		{0, 0, 0, 0}
	};

	int flag;
	while((flag = getopt_long(argc, argv, "i:", long_options, NULL)) != -1){
		switch(flag){
			case 'i':
			        if(optarg){
				        *interface = optarg;
				        break;
				}
			case '?':
				printf("What the heeeeeeeel, oh my god no wayay. \n");
				return false;
			default:
				printf("Something went wrong with the flags. \n");
				return false;
		}
	}
	return true;
}

int main(int argc, char *argv[]){
	char* interface = NULL;
	
	if(get_input_params(argc, argv, &interface) && interface != NULL){
		printf("%s \n", interface);
	}
}
