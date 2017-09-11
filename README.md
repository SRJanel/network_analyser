# network_analyser
A mini packet sniffer coded in C using raw sockets which prints the raw data in hex/ascii style and currently dissects packets for Ethernet, ARP, ICMP, IPv4, TCP and UDP.

## Usage
Use -i (or --interface) [interface] to bind the raw socket and listen on a specific interface. If not specified then the socket listens on all interfaces.  
Use -p (or --promiscious) alongside -i to set the interface to promiscious mode.  
Use -f (or --filter) [filter] to use Linux Socket Filtering (LSF) to attach a filter onto the socket and allow only certain types of data to come through the socket. ```tcpdump``` needs to be installed on the system as it is used to create the filter codes before sending them to the kernel.
