/**
 * @file input_parser.h
 * @brief Contains functions used to parse the user input.
 *
 *
 * @author Patrik Tomasko (xtomasp00)
 * @date 2025-03-27
 */

#include <stdbool.h>

#define MAX_PORTS 65535 //maximum ammount of possible ports to scan through

typedef enum {
    TYPE_UNKNOWN,
    TYPE_IPV4,
    TYPE_IPV6,
    TYPE_DOMAIN,
    TYPE_LOCALHOST
} target_type;

/**
 * @brief Checks wether a given string is made up of digits.
 * 
 * @param string The string containing the possible number.
 * 
 * @return true in case of it being a number, false in case of it containing non-digit characters.
 */
bool is_number(const char* string);

/**
 * @brief Extracts the ports out of the port string given by the user.
 * 
 * @param ports_string The string containing the information about the ports.
 * @param ports_array The array where the ports to be scanned will get logged.
 * @param filled Determines wether at least a single port was extracted (true at least one, false none).
 * 
 * @return true in case success, false in case of failure.
 */
bool port_parser(char* ports_string, int* ports_array, bool* filled);

/**
 * @brief Checks the user input and extracts the given information.
 * 
 * @param argc Count of the given parameters.
 * @param argv Array containing the user input.
 * @param interface Pointer to return the interface.
 * @param wait Pointer to return the timeout value.
 * @param target Pointer to return the target.
 * @param udp_ports_string Pointer to return the UDP ports to be scanned.
 * @param tcp_ports_string Pointer to return the UDP ports to be scanned.
 * 
 * @return 0 if the information was extracted successfully, 1 if an error occured or the user input wrong parameters, 2 if the interfaces were printed out.
 */
int get_input_params(int argc, char *argv[], char** interface, int* wait, char** target, char** udp_ports_string, char** tcp_ports_string);

/**
 * @brief Determines the type of the target given by the user
 * 
 * @param target String given by the user containing the target.
 * 
 * @return One of the values of the enum target_type based on the target.
 */
target_type determine_target_type(char *target);

