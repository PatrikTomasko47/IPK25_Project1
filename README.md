# Documentation of project 1 of IPK 2024/2025 (variant Omega)
## Author: Patrik Tomaško (xtomasp00)
## Brno University of Technology

# ipk-l4-scan

The goal of this project was to make a program that is capable of scanning ports and finding out their status via either UDP or TCP. The program is also capable of printing out all the available network interfaces that the user can choose. The user can specify the protocol being used, ports to be scanned, interface via the scanning will take place, target IP/domain and optionally also the timeout time after which the program will preform a certain action depending on the protocol.

## Theory necessary to understand the functionality of the application
### IP address
IP address is a number that identifies a network interface within a computer network. There are two main types IPv4 and IPv6. 
IPv4 is the dominantly used one. It has 32 bites, which can be divided into four bytes (1 byte = 8 bits) and written sepparately converted to the decimal system separated by dots. That is the usual format in which IPv4 addresses appear for example 127.0.0.1, 8.8.8.8, ... 
IPv6 addresses were invented as a solutionto the insufficient number of the available IPv4 addresses, which ran out. An IPv6 address contains 128 bytes which are commonly divided into 8 groups of 16 bits. Each group is represented as a four digit hexadecimal nuber and they are divided by colons. For example: 2001:0db8:85a3:0000:8a2e:0370:7334:0000. Often times many of the groups are all zeros, thus to make the addresses more readeble, the groups of zeros next to each other are usually turned into a double colon. For example: 2001:0db8:85a3::8a2e:0370:7334.

### Packet
A packet is a small unit of data that is transmitted over computer networks. When transmitting data over networks it is better to break the data down into smaller pieces that are easier for the network infrastructure to manage. That is the reason why packets exist. They usually hold the data they are transmitting and also data necessary for the packet to be sent to it's destination.

Components of a packet:
1. Header - Contains routing information like sender and reciever IP addresses and sender and reciever ports.
2. Payload - The data that is transmitted via the packets.
3. Footer/Checksum - Packets often include a footer that holds a certain information like checksum that is used to verify that the packet didn't get deformed on it's way through the network.

 ### Ports
 Ports are logical communication endpoints used by protocols like UDP and TCP to distinguish different types of traffic on the same IP address. It is used to have the communication organised in a certain way and also for security reasons. Some ports have a protocol that is usually associated with them like for example: HTTP -> 80, SSH -> 20, ... Each of the ports can have a certain status, for our purposed we need to know that a port can be either open, closed or filtered. Open means that the port is ready to accept and react to certain packets being sent to it. Closed means that the port is not willing to communicat and filtered means that the port is not directly accessible, often due to a firewall or some other security mechanism blocking traffic to that port, preventing any communication from taking place.

 ### TCP
 TCP (Transmition control protocol) is a communication protocol used in computer networks. It ensures a reliable communication. When two devices communicate via TCP they first establish a connection between each other and maintain this connection as long as they communicate between each other. They send packets over this connection and when a packet does not arrive or is deformed during transmitting the packet will get retransmitted. This ensure that the communication is reliable. TCP is used for thing that need reliability like chatting for example.

 ### UDP
 UDP (User datagram protocol) is a communication protocol used in computer networks. Unlike TPC it does not establish any connection before sending packets. UDP is generally unreliable and mostly used for transmitting large ammounts of data, where it is not important wether some packets get lost. UDP is used for thing like streaming, playing online video games, ...

 ### Domains
 In networking and the internet, domains are human-readable addresses used to identify a specific website, server, or a network resource. Domains are a part of the Domain Name System (DNS) that translates domains into IP addresses.

 ## Implementation details

The program part of this project is implemented in multiple files. The main file that combines the other file to achieve the goal of this project is `ipk-l4-scan.c`. All the parts of the program are described lower in more detail.

### TCP construction and scanning

#### TCP Header construction
The first step of scanning via TCP is creating a packet. Fortunatelly we won't have to worry about any payload or the IP header since we aren't sending any data and the IP header is created by the kernel. What we will have to worry about is the TCP header which looks like this.

![TCP Packet](images/tcp_header.jpg)

Next to each of the elements of the TCP header is a number of bits. Fortunatelly not all the elements have to be filled out with a specific value. There are though certain elements that we have to fill out for the TCP packet to function properly, these are: 
- source port 
- destination port (scanned port)
- sequence number (used to match the TCP packet and see the sequence of the communication)
- flags (in our case the flags will determine that status of the port)
- offset
- window
- checksum (it has to be calculated correctly otherwise the packet will be considered deformed and thrown away) 
Underneath here you can see the part of my code that implements the creation of the TCP header. All the functions and utilities for the creation of TCP and UDP packets are localted in the `packet_buildre.c` file.

<pre>        memset(header, 0, sizeof(struct tcphdr));
        
        header->th_seq = htonl(rand());
        header->th_flags = TH_SYN;
        header->th_off = 5;
        header->th_win = htons(65535);
        header->th_sport = htons(SOURCE_PORT);
        header->th_dport = htons(destination_port);
        header->th_sum = 0; //temporary
        
        uint16_t sum = tcp_checksum(source_ip, target_ip, header, sizeof(struct tcphdr), ipv6_mode);
        header->th_sum = sum; </pre>

Here you can see how each of the elements I mentioned are being assigned a certain value. The `htons` function here converts the values to the from the host byte order to network byte order. The byte order refers to the endianness of the data. The endianness describes the way the information is represented in the memory. Little endian means that the least significant byte is first and the most is last (host byte order) and big endian means that the least significant byte is last and the most significant first (network byte order).
Probably the most complicated part of the TCP header generation is the checksum, which requires construction of a pseudo header to calculate it. The calculation of the checksum is described lower in the documentation.

#### TCP scanning
There are three statuses that we will be checking for when scanning via TCP.
- Open
- Closed
- Filtered

In the case of TCP we have a bit more assurance of what the status actually is, because the protocol itself is much more reliable. We will be initializing a TCP handshake with the target and his response will determine the status. We will start by sending a TCP packet with the flag SYN to initialize this handshake and waiting for the response which will also be a TCP packet.

##### Open
If we will recieve a TCP packet response with the flags SYN and ACK, it means that the target is ready for the handshake and the port is open. We will not finish this handshake and simply leave it and print out that the port is open.

##### Closed
If we will recieve a TCP packet response with the RST flag it means that the port is closed.

##### Filtered
If the TCP response does not come in the defined timeout time (either defined by the user or 5 seconds by default) we will attempt to send another handshake initialisation packet and if even the second packet times out we will declare the packet as closed.

Here's the part of the code in `port_analyzer.c` that implements this scanning logic of the ports using TCP and IPV4.

<pre>
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
</pre>

The code consists of two main while loops, the first while loop that has `verify_filter` variable in it's condition is the loop that will send the packet again in case the packet times out. 

The inner loop with the `matching_ips` variable in it's condition is used to recieve the correct packet, since the socket via which we are recieving the incoming packets can recieve a packet that is not from the target IP address. In such case we will throw the caught packet away, the new time to wait (timeout - time elapsed) will get calculated and another select (the function that waits for the response) will get called with the updated timeout value. To compare the IP addresses the function `analyze_ips` is used.

If the recieved packet is from the scanning target, the response is sent to the `analyze_tcp_response` which determines wether the TCP packet is even a response to our handshake initialisation (sequence number match), and then analyzes the flags and returns wether the port is open or closed.

### UDP construction and scanning
The first step of scanning via UDP is also creating a packet. As with the TCP packet the only thing we have to create and fill out is the UDP header which is in the picture below.

![UDP Packet](images/udp_packet.png)

Underneath each of the elements of the UDP header is a number of bytes. We will have to fill out all of the parts of the header which are: 
- source port 
- destination port (scanned port)
- length
- checksum (it has to be calculated correctly otherwise the packet will be considered deformed and thrown away) 
Underneath here you can see the part of my code that implements the creation of the UDP header. All the functions and utilities for the creation of TCP and UDP packets are localted in the `packet_buildre.c` file.

<pre>        memset(header, 0, sizeof(struct udphdr));
        
        header->uh_ulen = htons(sizeof(struct udphdr));
        header->uh_sport = htons(SOURCE_PORT);
        header->uh_dport = htons(destination_port);
        header->uh_sum = 0; //temporary
        
        uint16_t checksum = udp_checksum(source_ip, target_ip, header, sizeof(struct udphdr), ipv6_mode);
        header->uh_sum = checksum; </pre>

Here you can see how each of the elements I mentioned are being assigned a certain value. The `htons` function is once again used to convert values from host byte order to the network byte order. Once again the checksum calculation is neede which is described lower in the documentation.

#### UDP scanning
There are two statuses that we will be checking for when scanning via UDP.
- Open
- Closed

In the case of UDP we don't really have a reliable way to tell wether the port is open or filtered. The only thing we can tell for sure is wether the port is closed. If the port is closed we will recieve an ICMP/ICMPv6 packet with the code 3 and type 3 (in the case of IPV4) or code 4 and type 1 (in the case of IPV6).

Here's the part of the code in `port_analyzer.c` that implements this scanning logic of the ports using UDP and IPV4.

<pre>
struct udphdr udp_header;

construct_udp_header(&target, (uint16_t) index, &udp_header, false, &source_ip);

ssize_t bytes_sent = sendto(raw_socket_send, &udp_header, sizeof(udp_header), 0, (struct sockaddr*)&target_wrapper, sizeof(target_wrapper));

if (bytes_sent == -1){

        fprintf(stderr, "Error: Failed to send the packet.\n");
        close(raw_socket_recieve);
        close(raw_socket_send);
        return false;

}

fd_set read_content;

struct timeval timeout_struct, start_time, recieve_time;

int elapsed_time = 0;

gettimeofday(&start_time, NULL);

int matching_ips = 1; //catching packets until the ip of the source matches to the one we sent to

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
                FD_SET(raw_socket_recieve, &read_content);

                waiter = select(raw_socket_recieve + 1, &read_content, NULL, NULL, &timeout_struct);

        }

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
</pre>

Compared to the TCP algorithm we can see that the loop trying to send a second packet in the case of timeout isn't here, since we do not have the filtered option in UDP, the port is immediatelly considered open. This is because the response to the UDP packet in the case of an open port can be another protocol like DNS for example and thus we will just consider the port open if the ICMP closing packet isn't recieved. 
Same as the TCP there is a function `analyze_udp_response` that checks the recieved icmp/icmpv6 packet for the closing codes and types. One last important thing to note with the udp scanning is that after each scan the program waits a second. This is done so that the source IP from which we are sending the packets doesn't get blacklisted, since this can occur if the target gets overwhelmed by UDP packets from one IP address.

### Checksum calculation

The calculation of the checksum is the most complex part of creating TCP/UDP header. It requires the creation of a temporary pseudo header to calculate it.

#### Pseudo header

When calculating a checksum a pseudo header is needed. The reasoning behind this is security. When we are generating the TCP/UDP header we do not yet have the IP header available but we still need a way to calculate the checksum and incorporate things that would be in the IP header such as the destination and source IP, this is where the pseudo header comes in which fills this position for the time of the TCP/UCP packet construction. The pseudo headers themselves are pretty simple. You can see the parts of the code in the `packet_builder.c` that implement the pseudo header generation.

TCP (IPV4)

<pre>
struct pseudo_header_ipv4{
    uint32_t source_ip;
    uint32_t destination_ip;
    uint8_t zero;
    uint8_t protocol;
    uint16_t udp_tcp_length;
};
</pre>

Here we can see how the Pseudo header for IPV4 looks like. The IPV6 version is basically the same, only having different types of the source and destination IP.

#### Checksum calculation

After the pseudo header gets constructed, it gets copied into a buffer and after it the tcp header that we have constructed so far gets copied. This buffer along with the leng off the total buffer gets forwarded to the `sum_calculator` function .

<pre>
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
</pre>

This first calculates the buffer by summing the 16-bit words in the buffer. In case of an odd byte it gets added to the sum asswell. After that the overflow is processed by carrying the upper bits to the lower bits and repeating the process if necessary. Last but not least the bits of the result get inverted.

### User input processing

The user input gets processed by the functions defined in the `input_parser.c/.h` files. The main function is the `get_input_params` function which parses the user input using the `getopt_long` function which extracts the values of defined flags. The function also checks for missing values, target (has no flag) and value redefinition in which case it returns an error.
It also calls the `print_available_interfaces` function if the user's input is either empty or there is just an empty -i flag.

Apart from the `get_input params`. To process the user defined ports to be scanned there is the `port_parser` function which parses the given string and returns an array that holds ones on the indexes where the index equals to the port to be scanned. This function also uses the utility function `is_number` which checks wether a string is made up of digit characters.

Last but not least the `determine_target_type` along with the `target_type` enum are used to check and determine the type of the given target (IPV4/IPV6/DOMAIN/LOCALHOST).

### Support utility

The file `ip_utility.h/c` and `ll_ip_array.h/.c` contains functions that are used to assist other parts of the program. 

The `ll_ip_array.c` defines two linked lists, one for IPV4 and the second for IPV6. It is used to avoid duplicate scanning when itterating through the IP addresses of a domain.

The `ip_utility.c` defines 3 functions each with a different purpose.

- `print_available_interfaces`: Prints out available interfaces in the special cases as defined in the assignment. For more detail look at Usage.

- `convert_source_ip`: Takes the string containing the interface given by the user and converts it to an IP address.

- `itterate_domain_ips`: Itterates through all the available IP addresses of a given domain. Avoids duplicates using the linked list from `ll_ip_array.c` and in the case of IP addresses that cannot be scanned due to the chosen interface not having a viable address of such version, notifies the user and skips such IP addresses.

## Testing

### Tested system
The test we're executed on a Virtual Machine running on a host PC. The specifications are:

Host PC:

- OS: Microsoft Windows 11 Pro (10.0.26100 Build 26100)
- CPU: Intel(R) Core(TM) i5-9600KF CPU @ 3.70GHz, 3696 Mhz, cores: 6, logical processors: 6
- RAM: 16GB
- GPU: NVIDIA GeForce RTX 2070 SUPER
- NIC: D-Link DWA-582 Wireless AC1200 Dual Band PCI Express Adapter
- Hypervision used: VirtualBox

VM:

- OS: Ubuntu 24.04.1 LTS
- Number of vCPUs: 4
- Allocated RAM: 2GB
- Disk size: 32GB
- Networking: NAT

Each of the tests will have a result log located in the `test_results` folder. The name of the log and pcap will be written next to the name of the test. Within the .log files will be the stdout/stderr and underneath that will be the program exit code.

Note that before testing the <pre>make setuid</pre> was launched to not have to launch the program with sudo.

### Input parameters testing

The first part tests the input parameters to see wether the program can handle missing and/or unexpected input parameters. The special behavior described in the assignment like interface printing and help will also be tested.

#### Error testing

##### Multiple interfaces test (m_i_test.log)

Testing wether the program returns an error message and exits with a 1 if a user inputs multiple interfaces.

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan 8.8.8.8 -t 53 -w 2000 -i enp0s3 -i lo</pre>

- Actual output: <pre>Error: multiple -i/--interface inputs detected.
1
</pre>

- Result: success

##### Multiple empty interface flags test (m_if_test.log)

Testing wether the program returns an error message and exits with a 1 if a user inputs multiple interface flags.

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan 8.8.8.8 -t 53 -w 2000 -i -i -i lo</pre>

- Actual output: <pre>Error: multiple -i/--interface inputs were detected.
1
</pre>

- Result: success

##### Multiple tcp ports declarations test (m_t_test.log)

Testing wether the program returns an error message and exits with a 1 if a user inputs multiple tcp port inputs.

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan 8.8.8.8 -t 53 -t 1-5 -w 2000 -i enp0s3</pre>

- Actual output: <pre>Error: multiple -t/--pt inputs were detected.
1
</pre>

- Result: success

##### Multiple tcp ports declarations test (m_u_test.log)

Testing wether the program returns an error message and exits with a 1 if a user inputs multiple udp port inputs.

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan 8.8.8.8 -u 53 -u 1-5 -w 2000 -i enp0s3</pre>

- Actual output: <pre>Error: multiple -u/--pu inputs were detected.
1
</pre>

- Result: success

##### An unknown flag test (uf_test.log)

Testing wether the program returns an error message and exits with a 1 if a user inputs an unidentified flag.

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan 8.8.8.8 -u 53 -w 2000 -i enp0s3 -g</pre>

- Actual output: <pre>./ipk-l4-scan: invalid option -- 'g'
Error: An unknown flag was '?' detected.
1</pre>

- Result: success

##### Missing target test (miss_t_test.log)

Testing wether the program returns an error message and exits with a 1 if a user doesn't specify a target.

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan -u 53 -w 2000 -i enp0s3</pre>

- Actual output: <pre>Error: No target specified.
1</pre>

- Result: success

##### Extra parameter test (e_p_test.log)

Testing wether the program returns an error message and exits with a 1 if a user inputs more than one targets.

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan -u 53 -w 2000 -i enp0s3 8.8.8.8 1.1.1.1</pre>

- Actual output: <pre>Error: An unexpected argument was detected after the target.
1</pre>

- Result: success

##### Missing ports test (miss_p_test.log)

Testing wether the program returns an error message and exits with a 1 if a user doesn't specify any UDP or TCP ports.

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan -w 2000 -i enp0s3 8.8.8.8</pre>

- Actual output: <pre>Error: At least a single UDP or TCP port has to be specified.
1</pre>

- Result: success

##### Missing interface test (miss_i_test.log)

Testing wether the program returns an error message and exits with a 1 if a user doesn't specify an interface.

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan -w 2000 -t 50 8.8.8.8</pre>

- Actual output: <pre>Error: No interface specified. To wiev available interfaces -> './ipk-l4-scan -i' or './ipk-l4-scan'.
1</pre>

- Result: success

##### Bad_interface_test (b_i_test.log)

Testing wether the program returns an error message and exits with a 1 if a the interface specified by the user id not of suported format.

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan -w 2000 -t 50 8.8.8.8 -i nonexistingbadinterface1234.</pre>

- Actual output: <pre>Error: The interface you want to use 'nonexistingbadinterface1234.' does not have an suitable ipv4 address.
1</pre>

- Result: failure, the error was caught by another if, the type of the interface was wrongly incorrectly as ipv4

##### Non-number port test (nn_p_test.log)

Testing wether the program returns an error message and exits with a 1 if a user provides a port that is not a number.

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan -w 2000 -t 5a 8.8.8.8 -i enp0s3</pre>

- Actual output: <pre>Error: A non-number value has been detected in the ports to be scanned.
1</pre>

- Result: success

##### Non_number port range test (nn_pr_test.log)

Testing wether the program returns an error message and exits with a 1 if a user provides a port range where one of the number is not a number.

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan -w 2000 -t 5a-90 8.8.8.8 -i enp0s3</pre>

- Actual output: <pre>Error: A non-number value has been detected in the port range.
1</pre>

- Result: success

##### Wrong order port range test (wo_pr_test.log)

Testing wether the program returns an error message and exits with a 1 if a user provides a port range where the number on the left is bigger than the number on righ.

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan -w 2000 -t 6-5 8.8.8.8 -i enp0s3</pre>

- Actual output: <pre>Error: The values in the port range are in the wrong order or out of the allowed range.
The value to the left (6) has to be smaller than the value on the right (5) and both have to be inside 0-65535.
1</pre>

- Result: success

##### Port out of allowed range test (or_p_test.log)

Testing wether the program returns an error message and exits with a 1 if a user provides a port that is out of the possible port range.

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan -w 2000 -t 70000 8.8.8.8 -i enp0s3</pre>

- Actual output: <pre>Error: The port you entered (70000) is out of the allowed range.
1</pre>

- Result: success

##### Port range out of allowed range test (or_pr_test.log)

Testing wether the program returns an error message and exits with a 1 if a user provides a port range in which one of the numbers is out of the possible port range.

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan -w 2000 -t 20-70500 8.8.8.8 -i enp0s3</pre>

- Actual output: <pre>Error: The values in the port range are in the wrong order or out of the allowed range.
The value to the left (20) has to be smaller than the value on the right (70500) and both have to be inside 0-65535.
1</pre>

- Result: success

#### Help printing (help_test.log)

Testing wether the program prints out the help text when user enters the help flag.

- Expected output: Help text and exit code 0.

- Input: <pre>./ipk-l4-scan --help</pre>

- Actual output: <pre>Usage:
  ./ipk-l4-scan [-i interface | --interface interface]
                [--pt port-ranges | --pu port-ranges] | [-t port-ranges | -u port-ranges]
                [-w timeout | --wait timeout]
                [hostname | ip-address | 'localhost']

Options:
  -h, --help
      Show this help message.

  -i interface, --interface interface
      Select the network interface for scanning (e.g., eth0).
      If only an empty interface flag is detected or no input value at all, lists all active interfaces.

  -t port-ranges, --pt port-ranges
      Specify TCP ports to scan.
        e.g., --pt 22,80-85,443

  -u port-ranges, --pu port-ranges
      Specify UDP ports to scan.
        e.g., --pu 53,67-69,161-162

  -w timeout, --wait timeout
      Set the timeout in milliseconds to wait for a response per scanned port.
      Default is 5000 ms.

  hostname | ip-address
      Target domain name or IPv4/IPv6 address or localhost to scan.

Examples:
  ./ipk-l4-scan --interface eth0 -t 22,80-85 -u 53,67-69 example.com
  ./ipk-l4-scan -i eth0 --pt 22,443 --pu 53 192.168.1.1
  ./ipk-l4-scan --interface       # Lists all available interfaces

Output Format:
  Each result of a scan is printed as a single line in the format:
    [IP address] [port number] [protocol] [status]

  Example output:
    127.0.0.1 22 tcp open
    127.0.0.1 53 udp closed

Note that if you want to use the program and have it function properly you either have to launch it with sudo or use 'make setuid' to give it the necessary privileges.0
</pre>

- Result: success

#### Interface printing variant 1(i_test1.log)

Testing wether the program prints out available interfaces if the user doesnt enter anything

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan</pre>

- Actual output: <pre>Active network interfaces:
lo
enp0s3
0</pre>

- Result: success

#### Interface printing variant 2(i_test2.log)

Testing wether the program prints out available interfaces if the user doesnt enter anything

- Expected output: Error message and exit code 1.

- Input: <pre>./ipk-l4-scan -i</pre>

- Actual output: <pre>Active network interfaces:
lo
enp0s3
0</pre>

- Result: success

### Port scanning testing (IPV4)

#### TCP

##### Scanning multiple ports (t_4_mp_test.log, t_4_mp_test.pcap)

Testing wether the program succesfully scans multiple ports.

- Expected output: Scan results and exit code 0, visible packets in the pcap file.

- Input: <pre>sudo ./ipk-l4-scan -i enp0s3 8.8.8.8 -t 52-54</pre>

- Actual output: <pre>8.8.8.8 52 tcp filtered
8.8.8.8 53 tcp open
8.8.8.8 54 tcp filtered
0</pre>

- Result: success, the ports are visible in the pcap file and printed out correctly.

##### Scanning open port (t_4_o_test.log, t_4_o_test.pcap)

Testing wether the program succesfully scans an open port.

- Expected output: Scan results and exit code 0, visible packets in the pcap file.

- Input: <pre>sudo ./ipk-l4-scan -i enp0s3 8.8.8.8 -t 53</pre>

- Actual output: <pre>8.8.8.8 53 tcp open
0</pre>

- Result: success, the ports are visible in the pcap file and printed out correctly.

##### Scanning closed port (t_4_c_test.log, t_4_c_test.pcap)

Testing wether the program succesfully scans an closed port.

- Expected output: Scan results and exit code 0, visible packets in the pcap file.

- Input: <pre>sudo ./ipk-l4-scan -i enp0s3 127.0.0.1 -t 50</pre>

- Actual output: <pre>127.0.0.1 50 tcp closed
0</pre>

- Result: success, the ports are visible in the pcap file and printed out correctly.

##### Scanning filtered port (t_4_f_test.log, t_4_f_test.pcap)

Testing wether the program succesfully scans an filtered port.

- Expected output: Scan results and exit code 0, visible packets in the pcap file.

- Input: <pre>sudo ./ipk-l4-scan -i enp0s3 8.8.8.8 -t 50</pre>

- Actual output: <pre>8.8.8.8 50 tcp filtered
0</pre>

- Result: success, the ports and the resend are visible in the pcap file and printed out correctly.

#### UDP

##### Scanning open port (u_4_o_test.log, u_4_o_test.pcap)

Testing wether the program succesfully scans an open port.

- Expected output: Scan results and exit code 0, visible packets in the pcap file.

- Input: <pre>sudo ./ipk-l4-scan -i enp0s3 8.8.8.8 -u 53</pre>

- Actual output: <pre>8.8.8.8 53 udp open
0</pre>

- Result: success, can see that the udp didn't recieve any icmp in the pcap.

##### Scanning closed port (u_4_c_test.log, u_4_c_test.pcap)

Testing wether the program succesfully scans an closed port.

- Expected output: Scan results and exit code 0, visible packets in the pcap file.

- Input: <pre>sudo ./ipk-l4-scan -i enp0s3 127.0.0.1 -u 53</pre>

- Actual output: <pre>127.0.0.1 53 udp closed
0</pre>

- Result: success, can see that the udp recieved the icmp in the pcap.

### Port scanning testing (IPV6)

#### TCP

##### Scanning multiple ports (t_6_mp_test.log, t_6_mp_test.pcap)

Testing wether the program succesfully scans multiple ports.

- Expected output: Scan results and exit code 0, visible packets in the pcap file.

- Input: <pre>sudo ./ipk-l4-scan -i tun0 2001:4860:4860::8888 -t 52-54 -w 500</pre>

- Actual output: <pre>2001:4860:4860::8888 52 tcp filtered
2001:4860:4860::8888 53 tcp open
2001:4860:4860::8888 54 tcp filtered
0</pre>

- Result: success, the ports are visible in the pcap file and printed out correctly.

##### Scanning open port (t_6_o_test.log, t_6_o_test.pcap)

Testing wether the program succesfully scans an open port.

- Expected output: Scan results and exit code 0, visible packets in the pcap file.

- Input: <pre>sudo ./ipk-l4-scan -i tun0 2001:4860:4860::8888 -t 53</pre>

- Actual output: <pre>2001:4860:4860::8888 53 tcp open
0</pre>

- Result: success, the ports are visible in the pcap file and printed out correctly.

##### Scanning closed port (t_6_c_test.log, t_6_c_test.pcap)

Testing wether the program succesfully scans an closed port.

- Expected output: Scan results and exit code 0, visible packets in the pcap file.

- Input: <pre>sudo ./ipk-l4-scan -i tun0 ::1 -t 50</pre>

- Actual output: <pre>::1 50 tcp closed
0</pre>

- Result: success, the ports are visible in the pcap file and printed out correctly.

##### Scanning filtered port (t_6_f_test.log, t_6_f_test.pcap)

Testing wether the program succesfully scans an filtered port.

- Expected output: Scan results and exit code 0, visible packets in the pcap file.

- Input: <pre>sudo ./ipk-l4-scan -i tun0 2001:4860:4860::8888 -t 50 -w 500</pre>

- Actual output: <pre>2001:4860:4860::8888 50 tcp filtered
0
</pre>

- Result: success, the ports and the resend are visible in the pcap file and printed out correctly.

#### UDP

##### Scanning closed port (u_6_c_test.log, u_6_c_test.pcap)

Testing wether the program succesfully scans an closed port.

- Expected output: Scan results and exit code 0, visible packets in the pcap file.

- Input: <pre>sudo ./ipk-l4-scan -i tun0 2001:4860:4860::8888 -u 53 -w 500</pre>

- Actual output: <pre>2001:4860:4860::8888 53 udp open
0</pre>

- Result: failure, in the pcap we can see that the icmpv6 arrives but it doesn't have the code 4 type 1 that my script checks for.

### Domain scanning

#### Scanning a domain (d_s_test.log, d_s_test.pcap)

Testing wether the program can scan a domain.

- Expected output: Scan results and exit code 0, visible packets in the pcap file.

- Input: <pre>sudo ./ipk-l4-scan -i tun0 scanme.nmap.org -u 51-55 -t 52-53,55 -w 500</pre>

- Actual output: <pre>2600:3c01::f03c:91ff:fe18:bb2f 52 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 53 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 55 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 51 udp closed
2600:3c01::f03c:91ff:fe18:bb2f 52 udp closed
2600:3c01::f03c:91ff:fe18:bb2f 53 udp closed
2600:3c01::f03c:91ff:fe18:bb2f 54 udp closed
2600:3c01::f03c:91ff:fe18:bb2f 55 udp closed
45.33.32.156 52 tcp closed
45.33.32.156 53 tcp closed
45.33.32.156 55 tcp closed
45.33.32.156 51 udp closed
45.33.32.156 52 udp closed
45.33.32.156 53 udp closed
45.33.32.156 54 udp closed
45.33.32.156 55 udp closed
0</pre>

- Result: success.

#### Scanning a domain without IPV6 (d_s_wo6_test.log, d_s_wo6_test.pcap)

Testing wether the program can scan a domain.

- Expected output: Scan results and exit code 0, visible packets in the pcap file, the ipv6 will be skipped.

- Input: <pre>sudo ./ipk-l4-scan -i tun0 scanme.nmap.org -u 51-55 -t 52-53,55 -w 500</pre>

- Actual output: <pre>45.33.32.156 52 tcp filtered
45.33.32.156 53 tcp filtered
45.33.32.156 55 tcp filtered
45.33.32.156 51 udp open
45.33.32.156 52 udp open
45.33.32.156 53 udp open
45.33.32.156 54 udp open
45.33.32.156 55 udp open
Skipping IPV6 since the chosen interface has no suitable IPV6 address.
0</pre>

- Result: success.

### Localhost scanning (lh_test.log, lh_test.pcap)

Testing wether the program can scan localhost without any issues.

- Expected output: Scan results and exit code 0, visible packets in the pcap file.

- Input: <pre>sudo ./ipk-l4-scan -i tun0 scanme.nmap.org -u 51-55 -t 52-53,55 -w 500</pre>

- Actual output: <pre>127.0.0.1 52 tcp closed
127.0.0.1 53 tcp closed
127.0.0.1 55 tcp closed
127.0.0.1 51 udp closed
127.0.0.1 52 udp closed
127.0.0.1 53 udp closed
127.0.0.1 54 udp closed
127.0.0.1 55 udp closed
0</pre>

- Result: success.

## Extra functionality

There are a few extra functionalities that my implementation does and was not defined in the assignment, these are:

- In the case of a domain having and IP of a version that cannot be scanned via the chosen interface the user is notified and the program skips such addresses.

- When scanning UDP port the program always waits a second between each packet send to not get blacklisted by the target.

- The user can input the ports it this format number-number,number-number,number, ... Basically he can input multiple intervals divided by a comma.

- Makefile has the ability to set up the script to run as root so the user doesn't have to always write sudo before it. It is done by launching <pre>make setuid</pre>.

## Sources
1. **IANA Service Names and Port Numbers**  
   Available from: [IANA - Service Names and Port Numbers](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)

2. **What is a Packet?**  
   Cisco. Available from: [Cisco - What is a Packet?](https://www.cisco.com/c/en/us/solutions/small-business/resource-center/networking/what-is-a-packet.html)

3. **IOS XR Software Overview**  
   Cisco. Available from: [Cisco - IOS XR Overview](https://www.cisco.com/c/en/us/solutions/collateral/enterprise-networks/ios-xr-software/white-paper-c11-740335.html)

4. **UDP Overview**  
   Cisco. Available from: [Cisco - UDP Overview](https://www.cisco.com/c/en/us/solutions/collateral/ios-xr-software/udp-overview.html)

5. **DNS Resources**  
   ICANN. Available from: [ICANN - DNS Resources](https://www.icann.org/resources/pages/dns-2012-02-25-en)

6. **htons Function in Linux**  
   Linux Man Pages. Available from: [Linux Man Pages - htons](https://linux.die.net/man/3/htons)

7. **Understanding the TCP Checksum Function**  
   Stack Overflow. Available from: [Stack Overflow - TCP Checksum](https://stackoverflow.com/questions/22374040/understanding-the-tcp-checksum-function)


## Photo sources
1. **TCP Header Details**  
   Network Urge. Available from: [Network Urge - TCP Header Details](https://www.networkurge.com/2017/10/tcp-header-details.html)

2. **TCPv1 Diagram**  
   Available from: [TCPv1 Diagram](https://notes.shichao.io/tcpv1/ch10/)
