# Documentation of project 1 of IPK 2024/2025
## Author: Patrik Tomaško (xtomasp00)
## Brno University of Technology

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

 ## ipk-l4-scan
The goal of this project was to make a programme that is capable of scanning ports and finding out their status via either UDP or TCP. The programme is also capable of printing out all the available network interfaces that the user can choose. The user can specify the protocol being used, ports to be scanned, interface via the scanning will take place, target IP/domain and optionally also the timeout time after which the programme will preform a certain action depending on the protocol.

### TCP construction and scanning

#### TCP Header construction
The first step of scanning via TCP is creating a packet. Fortunatelly we won't have to worry about any payload or the IP header since we aren't sending any data and the IP header is created by the kernel. What we will have to worry about is the TCP header which looks like this.

![TCP Packet](images/tcp_header.jpg)

Next to each of the elements of the TCP header is a number of bits. Fortunatelly not all the elements have to be filled out with a specific value. There are though certain elements that we have to fill out for the TCP packet to function properly, these are: source port, destination port, sequence number, flags, offset, window and last but certainly not least the checksum. Underneath here you can see the part of my code that implements the creation of the TCP header. All the functions and utilities for the creation of TCP and UDP packets are localted in the packet_buildre.c file.

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

Here you can see how each of the elements I mentioned are being assigned a certain value. 

#### TCP scanning

### UDP construction and scanning

#### UDP Header construction

### Checksum calculation

![UDP Packet](images/udp_packet.png)

#### UDP scanning

### User input processing

### Network interfaces

## Usage

## Testing

### Tested system

### Input parameters testing

#### Interface printing

#### Missing arguments

#### Bad input values

### Port scanning testing (IPV4)

#### TCP

#### UDP

### Port scanning testing (IPV6)

#### TCP

#### UDP

## Extra functionality

## Sources
https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
https://www.cisco.com/c/en/us/solutions/small-business/resource-center/networking/what-is-a-packet.html
https://www.cisco.com/c/en/us/solutions/collateral/enterprise-networks/ios-xr-software/white-paper-c11-740335.html
https://www.cisco.com/c/en/us/solutions/collateral/ios-xr-software/udp-overview.html
https://www.icann.org/resources/pages/dns-2012-02-25-en

## Photo sources
https://www.networkurge.com/2017/10/tcp-header-details.html
https://notes.shichao.io/tcpv1/ch10/
