/*
** print_packet.c for print_packet in /home/janel/Documents/coding/my_network_analyser
** 
** Made by SRJanel
** Login SRJanel <n******.*********@epitech.eu>
** 
** Started on  Sat Aug 19 21:29:04 2017 
** Last update Mon Sep  4 13:23:15 2017 
*/

#include <unistd.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include "network_analyzer.h"
#include "utils.h"
#include "protocols.h"
#include "debug.h"

typedef struct		s_arp_payload
{
  unsigned char		ar_sha[ETH_ALEN];
  unsigned char		ar_sip[4];
  unsigned char		ar_tha[ETH_ALEN];
  unsigned char		ar_tip[4];
}			t_arp_payload;

void		arp_packet(const unsigned char *packet)
{
  struct arphdr	*arphdr;
  t_arp_payload	*payload;
  
  PRINT_POSITION;
  arphdr = (struct arphdr *)(packet + sizeof(struct ethhdr));
  fprintf(stdout, "Hardware type: %u\n", ntohs(arphdr->ar_hrd));
  fprintf(stdout, "Protocol type: 0x%x\n", ntohs(arphdr->ar_pro));
  fprintf(stdout, "Hardware size: %d\n", arphdr->ar_hln);
  fprintf(stdout, "Protocol size: %d\n", arphdr->ar_pln);  
  fprintf(stdout, "Opcode: %u\n", ntohs(arphdr->ar_op));
  payload = (t_arp_payload *)((unsigned long)arphdr + sizeof(struct arphdr));
  PRINT_MAC_ADDRESS("Sender MAC address: ", payload->ar_sha);
  PRINT_IP_ADDRESS("Sender IP address: ", payload->ar_sip);
  PRINT_MAC_ADDRESS("Target MAC address: ", payload->ar_tha);  
  PRINT_IP_ADDRESS("Target IP address: ", payload->ar_tip);
  dump_packet(packet + sizeof(struct ethhdr), sizeof(struct arphdr));

}

void		ip_packet(const unsigned char *packet)
{
  struct iphdr	*iphdr;

  PRINT_POSITION;
  iphdr = (struct iphdr *)(packet + sizeof(struct ethhdr)); 
  fprintf(stdout, "Version: %u\n", iphdr->version);
  fprintf(stdout, "Header Length: %u\n", iphdr->ihl);
  fprintf(stdout, "iphdr->tos: %u\n", iphdr->tos);
  fprintf(stdout, "Total Length: %u\n", ntohs(iphdr->tot_len));
  fprintf(stdout, "Identification: 0x%x\n", ntohs(iphdr->id));
  /* apply masks */
  fprintf(stdout, "Fragment offset: %u\n", ntohs(iphdr->frag_off));
  fprintf(stdout, "Time to live: %d\n", iphdr->ttl);
  fprintf(stdout, "Protocol: %d\n", iphdr->protocol);
  fprintf(stdout, "Header Checksum: 0x%x\n", ntohs(iphdr->check));
  fprintf(stdout, "Source Address: %s\n", inet_ntoa((struct in_addr){iphdr->saddr}));
  fprintf(stdout, "Destination Address: %s\n", inet_ntoa((struct in_addr){iphdr->daddr}));

  dump_packet(packet + sizeof(struct ethhdr), sizeof(struct iphdr));
  protocol_switcher(packet, iphdr->protocol);
}

void		tcp_segment(const unsigned char *packet)
{
  struct tcphdr	*tcphdr;

  PRINT_POSITION;
  tcphdr = (struct tcphdr *)(packet + sizeof(struct ethhdr)
  			     + (((struct iphdr *)(packet + sizeof(struct ethhdr)))->ihl * 4));
  fprintf(stdout, "Source port: %u\n", ntohs(tcphdr->source));
  fprintf(stdout, "Dest port: %u\n", ntohs(tcphdr->dest));

  /* seq and ack seq incorrect */
  fprintf(stdout, "Seq : %d\n", ntohs(tcphdr->seq));
  fprintf(stdout, "Ack Seq : %d\n", ntohs(tcphdr->ack_seq));
  
  /* flags missing */
  fprintf(stdout, "Window : %u\n", ntohs(tcphdr->window));
  fprintf(stdout, "Checksum : 0x%x\n", ntohs(tcphdr->check));
  fprintf(stdout, "URG Ptr : %u\n", ntohs(tcphdr->urg_ptr));

  dump_packet(packet + sizeof(struct ethhdr)
	      + (((struct iphdr *)(packet + sizeof(struct ethhdr)))->ihl * 4), sizeof(struct tcphdr));
  /* WRONG !! dump packet further than sizeof(struct tcphdr) !! */
}

/* CHECK!! no WORD * ihl ? */
void		udp_segment(const unsigned char *packet)
{
  struct udphdr	*udphdr;

  PRINT_POSITION;
  udphdr = (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
  fprintf(stdout, "Source Port: %u\n", ntohs(udphdr->source));
  fprintf(stdout, "Destination Port: %u\n", ntohs(udphdr->dest));
  fprintf(stdout, "Length: %u\n", ntohs(udphdr->len));
  fprintf(stdout, "Checksum: 0x%x\n", ntohs(udphdr->check));
}

void			icmp_packet(const unsigned char *packet)
{
  struct icmphdr	*icmphdr;

  PRINT_POSITION;
  icmphdr = (struct icmphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
  fprintf(stdout, "Type: %d\n", icmphdr->type);
  fprintf(stdout, "Code: %d\n", icmphdr->code);
  fprintf(stdout, "Checksum: 0x%x\n", ntohs(icmphdr->checksum));

  dump_packet(packet + sizeof(struct ethhdr) + sizeof(struct iphdr), sizeof (struct icmphdr));
  sleep(30);
}

void		unknown_packet(const unsigned char *packet)
{
  PRINT_POSITION;
  /* unknown_packet can be called at any moment (ex: if it is a x25 packet, or even after an ip packet if the ip->protocol is "unknown" */
  /* -> solutions: print whole packet ? */

  /* dump_packet(packet + sizeof(struct ethdr) +  */
  (void)packet;
}

static void	ethernet_frame(const unsigned char *packet)
{
  struct ethhdr	*ethhdr;

  PRINT_POSITION;
  ethhdr = (struct ethhdr *)packet;
  PRINT_MAC_ADDRESS("Destination: ", ethhdr->h_dest);
  PRINT_MAC_ADDRESS("Source: ", ethhdr->h_source);
  fprintf(stdout, "Type: %d\n", ntohs(ethhdr->h_proto));
  dump_packet(packet, sizeof(struct ethhdr));
  protocol_switcher(packet, ntohs(ethhdr->h_proto));
}

void		analyze_packet(const unsigned char *packet)
{
  ethernet_frame(packet);
}
