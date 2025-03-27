/**
 * @file ll_ip_array.h
 * @brief Defines the linked list for ipv4 and ipv6, used to not scan IP more than once when analyzing a domain.
 *
 *
 * @author Patrik Tomasko (xtomasp00)
 * @date 2025-03-27
 */

#include <stdbool.h>
#include <netinet/in.h>
#include <string.h>

struct ll_ip4{
    struct ll_ip4_element *first;
};

struct ll_ip6{
    struct ll_ip6_element *first;
};

struct ll_ip4_element{
    struct in_addr address;
    struct ll_ip4_element *next;
};

struct ll_ip6_element{
    struct in6_addr address;
    struct ll_ip6_element *next;
};

/**
 * @brief Initializes the IPV4 linked list.
 *
 * @param list The memory where the list will be initialized.
 * 
 * @return true in case of success, false in case of failure.
 */
bool ll_ip4_init(struct ll_ip4 **list);
/**
 * @brief Initializes the IPV6 linked list.
 *
 * @param list The memory where the list will be initialized.
 * 
 * @return true in case of success, false in case of failure.
 */
bool ll_ip6_init(struct ll_ip6 **list);

/**
 * @brief Appends a new IPv4 address to the list.
 *
 * @param list The list to which the IP addres will be appended.
 * @param address The address to be added to the list.
 * 
 * @return true in case of success, false in case of failure.
 */
bool ll_ip4_append(struct ll_ip4 *list, struct in_addr *address);
/**
 * @brief Appends a new IPv6 address to the list.
 *
 * @param list The list to which the IP addres will be appended.
 * @param address The address to be added to the list.
 * 
 * @return true in case of success, false in case of failure.
 */
bool ll_ip6_append(struct ll_ip6 *list, struct in6_addr *address);

/**
 * @brief Searches for a specific IPv4 address in the linked list.
 *
 * @param list The list where the IP addressed will be searched.
 * @param address The address to be searched.
 * 
 * @return true in case of success, false in case of failure.
 */
bool ll_ip4_search(struct ll_ip4 *list, struct in_addr *address);
/**
 * @brief Searches for a specific IPv6 address in the linked list.
 *
 * @param list The list where the IP addressed will be searched.
 * @param address The address to be searched.
 * 
 * @return true in case of success, false in case of failure.
 */
bool ll_ip6_search(struct ll_ip6 *list, struct in6_addr *address);

/**
 * @brief Frees up all the allocated memmory of the linked list and it's elements.
 *
 * @param list The list to be deallocated.
 */
void ll_ip4_free(struct ll_ip4 *list);
/**
 * @brief Frees up all the allocated memmory of the linked list and it's elements.
 *
 * @param list The list to be deallocated.
 */
void ll_ip6_free(struct ll_ip6 *list);