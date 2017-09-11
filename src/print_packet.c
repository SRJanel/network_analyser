/*
** print_packet.c for print_packet in /home/janel/Documents/coding/my_network_analyser
** 
** Made by SRJanel
** Login SRJanel <n******.*********@epitech.eu>
** 
** Started on  Sat Aug 19 21:29:04 2017 
** Last update Sat Sep  9 19:53:24 2017 
*/

#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include "utils.h"
#include "protocols.h"

typedef struct	s_arp_payload
{
  unsigned char	ar_sha[ETH_ALEN];
  unsigned char	ar_sip[4];
  unsigned char	ar_tha[ETH_ALEN];
  unsigned char	ar_tip[4];
}		t_arp_payload;

static void	dump_raw_data(const unsigned char * const packet,
			      const size_t size)
{
  ssize_t	i;
  ssize_t	temp;
  
  i = -1;
  fprintf(stdout, " | Data:");
  while (++i < (ssize_t)size)
    {
      if (!(i % RAW_DATA_BYTE_PER_LINE))
	{
	  fprintf(stdout, "\n |\t");
	  temp = i;
	  fprintf(stdout, "%02x ", packet[temp++]);
	  while (temp < (ssize_t)size
		 && (temp % RAW_DATA_BYTE_PER_LINE))
	    fprintf(stdout, "%02x ", packet[temp++]);
	  fprintf(stdout, "\t");
	}
      fflush(stdout);
      write(1, (isprint(packet[i]))
	    ? (&packet[i])
	    : (const unsigned char *)("."), 1);
    }
  fprintf(stdout, "\n |");
  fflush(stdout);
}

void		dump_arp_packet(const unsigned char *packet,
				size_t packet_size)
{
  struct arphdr	*arphdr;
  t_arp_payload	*payload;

  PRINT_POSITION;
  arphdr = (struct arphdr *)(packet + sizeof(struct ethhdr));
  fprintf(stdout, " | Hardware type: %u\n", ntohs(arphdr->ar_hrd));
  fprintf(stdout, " | Protocol type: 0x%x\n", ntohs(arphdr->ar_pro));
  fprintf(stdout, " | Hardware size: %d\n", arphdr->ar_hln);
  fprintf(stdout, " | Protocol size: %d\n", arphdr->ar_pln);  
  fprintf(stdout, " | Opcode: %u\n", ntohs(arphdr->ar_op));
  payload = (t_arp_payload *)((unsigned long)arphdr + sizeof(struct arphdr));
  PRINT_MAC_ADDRESS(" | Sender MAC address: ", payload->ar_sha);
  PRINT_IP_ADDRESS(" | Sender IP address: ", payload->ar_sip);
  PRINT_MAC_ADDRESS(" | Target MAC address: ", payload->ar_tha);  
  PRINT_IP_ADDRESS(" | Target IP address: ", payload->ar_tip);
  dump_raw_data(packet + sizeof(struct ethhdr), sizeof(struct arphdr));
  (void)packet_size;
}

void		dump_ip_packet(const unsigned char *packet,
			       size_t packet_size)
{
  struct iphdr	*iphdr;

  PRINT_POSITION;
  iphdr = (struct iphdr *)(packet + sizeof(struct ethhdr)); 
  fprintf(stdout, " | Version: %u\n", iphdr->version);
  fprintf(stdout, " | Header Length: %u\n", iphdr->ihl);
  fprintf(stdout, " | Differentiated Services Field: 0x%02x\n", iphdr->tos);
  fprintf(stdout, " | Total Length: %u\n", ntohs(iphdr->tot_len));
  fprintf(stdout, " | Identification: 0x%x\n", ntohs(iphdr->id));
  /* apply masks */
  fprintf(stdout, " | Fragment offset: %u\n", ntohs(iphdr->frag_off));
  fprintf(stdout, " | Time to live: %d\n", iphdr->ttl);
  fprintf(stdout, " | Protocol: %d\n", iphdr->protocol);
  fprintf(stdout, " | Header Checksum: 0x%x\n", ntohs(iphdr->check));
  fprintf(stdout, " | Source Address: %s\n", inet_ntoa((struct in_addr){iphdr->saddr}));
  fprintf(stdout, " | Destination Address: %s\n", inet_ntoa((struct in_addr){iphdr->daddr}));
  dump_raw_data(packet + sizeof(struct ethhdr), iphdr->ihl * 4);
  protocol_switcher(packet, packet_size, iphdr->protocol);
}

void		dump_tcp_segment(const unsigned char *packet,
				 size_t packet_size)
{
  struct tcphdr	*tcphdr;

  PRINT_POSITION;
  tcphdr = (struct tcphdr *)(packet + sizeof(struct ethhdr)
  			     + (((struct iphdr *)(packet + sizeof(struct ethhdr)))->ihl * 4));
  fprintf(stdout, " | Source port: %u\n", ntohs(tcphdr->source));
  fprintf(stdout, " | Dest port: %u\n", ntohs(tcphdr->dest));
  fprintf(stdout, " | Sequence number: %u\n", ntohl(tcphdr->seq));
  fprintf(stdout, " | Acknowledgment number: %u\n", ntohl(tcphdr->ack_seq));
  fprintf(stdout, " | Header Length: %u\n", tcphdr->doff * 4);
  fprintf(stdout, " | Flags:\n");
  fprintf(stdout, " | |-Reserved: %u\n", tcphdr->res1);
  fprintf(stdout, " | |-Congestion Window Reduced: %u\n", tcphdr->cwr);
  fprintf(stdout, " | |-ECN-Echo: %u\n", tcphdr->ece);
  fprintf(stdout, " | |-Urgent: %u\n", tcphdr->urg);
  fprintf(stdout, " | |-Acknowledgment: %u\n", tcphdr->ack);
  fprintf(stdout, " | |-Push: %u\n", tcphdr->psh);
  fprintf(stdout, " | |-Reset: %u\n", tcphdr->rst);
  fprintf(stdout, " | |-Syn: %u\n", tcphdr->syn);
  fprintf(stdout, " | |-Fin: %u\n", tcphdr->fin);
  fprintf(stdout, " | Window size value: %u\n", ntohs(tcphdr->window));
  fprintf(stdout, " | Checksum: 0x%x\n", ntohs(tcphdr->check));
  fprintf(stdout, " | Urgent Pointer: %u\n", ntohs(tcphdr->urg_ptr));
  dump_raw_data(packet + sizeof(struct ethhdr)
	      + ((struct iphdr *)(packet + sizeof(struct ethhdr)))->ihl * 4,
	      packet_size - (sizeof(struct ethhdr)
			     + ((struct iphdr *)(packet + sizeof(struct ethhdr)))->ihl * 4));
}

void		dump_udp_segment(const unsigned char *packet,
				 size_t packet_size)
{
  struct udphdr	*udphdr;
  struct iphdr	*iphdr;

  PRINT_POSITION;
  iphdr = (struct iphdr *)(packet + sizeof(struct ethhdr));
  udphdr = (struct udphdr *)(packet + sizeof(struct ethhdr) + iphdr->ihl * 4);
  fprintf(stdout, " | Source Port: %u\n", ntohs(udphdr->source));
  fprintf(stdout, " | Destination Port: %u\n", ntohs(udphdr->dest));
  fprintf(stdout, " | Length: %u\n", ntohs(udphdr->len));
  fprintf(stdout, " | Checksum: 0x%x\n", ntohs(udphdr->check));
  dump_raw_data(packet + sizeof(struct ethhdr) + (iphdr->ihl * 4),
	      packet_size - (sizeof(struct ethhdr) + (iphdr->ihl * 4)));
}

void			dump_icmp_packet(const unsigned char *packet,
					 size_t packet_size)
{
  struct icmphdr	*icmphdr;
  struct iphdr		*iphdr;

  PRINT_POSITION;
  iphdr = (struct iphdr *)(packet + sizeof(struct ethhdr));
  icmphdr = (struct icmphdr *)(packet + sizeof(struct ethhdr) + (iphdr->ihl * 4));
  fprintf(stdout, " | Type: %d\n", icmphdr->type);
  fprintf(stdout, " | Code: %d\n", icmphdr->code);
  fprintf(stdout, " | Checksum: 0x%x\n", ntohs(icmphdr->checksum));
  fprintf(stdout, " | Identifier: %u (0x%x)\n", ntohs(icmphdr->un.echo.id),
	  ntohs(icmphdr->un.echo.id));
  fprintf(stdout, " | Sequence number: %u (0x%x)\n", ntohs(icmphdr->un.echo.sequence),
	  ntohs(icmphdr->un.echo.sequence));
  dump_raw_data(packet + sizeof(struct ethhdr) + (iphdr->ihl * 4),
	      packet_size - (sizeof(struct ethhdr) + (iphdr->ihl * 4)));
}

void	dump_unknown_packet(const unsigned char *packet,
			    size_t packet_size)
{
  PRINT_POSITION;
  dump_raw_data(packet + sizeof(struct ethhdr),
	      packet_size - sizeof (struct ethhdr));
}

void		dump_ethernet_frame(const unsigned char *packet,
				    size_t packet_size)
{
  struct ethhdr	*ethhdr;

  PRINT_POSITION;
  ethhdr = (struct ethhdr *)packet;
  PRINT_MAC_ADDRESS(" | Destination: ", ethhdr->h_dest);
  PRINT_MAC_ADDRESS(" | Source: ", ethhdr->h_source);
  fprintf(stdout, " | Type: %d\n", ntohs(ethhdr->h_proto));
  dump_raw_data(packet, sizeof(struct ethhdr));
  protocol_switcher(packet, packet_size, ntohs(ethhdr->h_proto));
}
