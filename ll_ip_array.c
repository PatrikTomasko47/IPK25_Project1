#include <stdlib.h>

#include "ll_ip_array.h"

bool ll_ip4_init(struct ll_ip4 **list){

    if(list == NULL)
        return false;

    *list = malloc(sizeof(struct ll_ip4));

    if(*list == NULL)
        return false;

    (*list)->first = NULL;
    return true;

}

bool ll_ip6_init(struct ll_ip6 **list){

    if(list == NULL)
        return false;

    *list = malloc(sizeof(struct ll_ip6));

    if(*list == NULL)
        return false;

    (*list)->first = NULL;
    return true;

}

bool ll_ip4_append(struct ll_ip4 *list, struct in_addr *address){

    if(list == NULL || address == NULL)
        return false;

    struct ll_ip4_element* new_element = malloc(sizeof(struct ll_ip4_element));

    if(new_element == NULL)
        return false;

    new_element->next = NULL;
    new_element->address = *address;

    if(list->first == NULL){

        list->first = new_element;

    }else{

        struct ll_ip4_element* current = list->first;

        while(current->next != NULL){ //going to the end of the list

            current = current->next;

        }

        current->next = new_element;

    }

    return true;

}

bool ll_ip6_append(struct ll_ip6 *list, struct in6_addr *address){

    if(list == NULL || address == NULL)
        return false;

    struct ll_ip6_element* new_element = malloc(sizeof(struct ll_ip6_element));

    if(new_element == NULL)
        return false;

    new_element->next = NULL;
    new_element->address = *address;

    if(list->first == NULL){

        list->first = new_element;

    }else{

        struct ll_ip6_element* current = list->first;

        while(current->next != NULL){ //going to the end fo the list

            current = current->next;

        }

        current->next = new_element;

    }

    return true;

}

bool ll_ip4_search(struct ll_ip4 *list, struct in_addr *address){

    if(list == NULL || address == NULL || list->first == NULL)
        return false;

    for(struct ll_ip4_element* current = list->first; current != NULL; current = current->next){

        if(memcmp(&current->address, address, sizeof(struct in_addr)) == 0){

            return true;

        }

    }

    return false;

}

bool ll_ip6_search(struct ll_ip6 *list, struct in6_addr *address){

    if(list == NULL || address == NULL || list->first == NULL)
        return false;

    for(struct ll_ip6_element* current = list->first; current != NULL; current = current->next){

        if(memcmp(&current->address, address, sizeof(struct in6_addr)) == 0){

            return true;

        }

    }

    return false;

}

void ll_ip4_free(struct ll_ip4 *list){

    if(list == NULL)
        return ;

    struct ll_ip4_element* current = list->first;
    struct ll_ip4_element* next;

    while(current != NULL){

        next = current->next;
        free(current);
        current = next;

    }

    list->first = NULL;

}

void ll_ip6_free(struct ll_ip6 *list){

    if(list == NULL)
        return ;

    struct ll_ip6_element* current = list->first;
    struct ll_ip6_element* next;

    while(current != NULL){

        next = current->next;
        free(current);
        current = next;
        
    }

    list->first = NULL;

}