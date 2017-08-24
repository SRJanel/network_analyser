/*
** print_packet.c for print_packet in /home/janel/Documents/coding/my_network_analyser
** 
** Made by SRJanel
** Login SRJanel <n******.*********@epitech.eu>
** 
** Started on  Sat Aug 19 21:29:04 2017 
** Last update Wed Aug 23 21:28:10 2017 
*/

#include <unistd.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include "utils.h"
#include "protocols.h"
#include "debug.h"

void		arp_packet(const unsigned char *packet)
{
  PRINT_POSITION;
  fprintf(stdout, "ARP packet detected !!\n");
  /* sleep(42); */
  (void)packet;
}

void		ip_packet(const unsigned char *packet)
{
  struct iphdr	*iphdr;

  PRINT_POSITION;
  iphdr = (struct iphdr *)(packet + sizeof(struct ethhdr));
 
  fprintf(stdout, "Version: %u\n", iphdr->version);
  fprintf(stdout, "Header Length: %u\n", iphdr->ihl);
  fprintf(stdout, "iphdr->tos: %u\n", ntohs(iphdr->tos));
  fprintf(stdout, "Total Length: %u\n", ntohs(iphdr->tot_len));
  fprintf(stdout, "Identification: 0x%x\n", ntohs(iphdr->id));
  fprintf(stdout, "Fragment offset: %u\n", ntohs(iphdr->frag_off));
  fprintf(stdout, "Time to live: %d\n", ntohs(iphdr->ttl));
  fprintf(stdout, "Protocol: %d\n", ntohs(iphdr->protocol));
  fprintf(stdout, "Header Checksum: 0x%x\n", ntohs(iphdr->check));
  /* PRINT_IP_ADDRESS("Source Address: ", inet_ntoa((struct in_addr){iphdr->saddr})); */
  fprintf(stdout, "Source Address: %s\n", inet_ntoa((struct in_addr){iphdr->saddr}));
  fprintf(stdout, "Destination Address: %s\n", inet_ntoa((struct in_addr){iphdr->daddr}));
  
  (void)packet;
}

void		tcp_packet(const unsigned char *packet)
{
  PRINT_POSITION;
  sleep(1);
  (void)packet;
}

void		icmp_packet(const unsigned char *packet)
{
  PRINT_POSITION;
  sleep(3);
  (void)packet;
}

void		unknown_packet(const unsigned char *packet)
{
  PRINT_POSITION;
  (void)packet;
}

void		print_ethernet_frame(const unsigned char *packet)
{
  struct ethhdr	*ethhdr;

  ethhdr = (struct ethhdr *)packet;
  PRINT_MAC_ADDRESS("ethhdr->h_dest", ethhdr->h_dest);
  PRINT_MAC_ADDRESS("ethhdr->h_source", ethhdr->h_source);
  fprintf(stdout, "ethhdr->h_proto: %d\n", ntohs(ethhdr->h_proto));

  protocol_switcher(packet, ntohs(ethhdr->h_proto));
  
}
