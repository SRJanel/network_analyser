/*
** protocols.h for PROTOCOLS_H_ in /home/janel/Documents/coding/my_network_analyser
** 
** Made by SRJanel
** Login SRJanel <n******.*********@epitech.eu>
** 
** Started on  Sat Aug 19 21:50:07 2017 
** Last update Mon Oct 23 03:16:52 2017 
*/

#ifndef PROTOCOLS_H_
# define PROTOCOLS_H_

# include <netinet/in.h>
# include <netinet/if_ether.h>

void			dump_arp_packet(const unsigned char *, const size_t);
void			dump_ip_packet(const unsigned char *, const size_t);
void			dump_tcp_segment(const unsigned char *, const size_t);
void			dump_udp_datagram(const unsigned char *, const size_t);
void			dump_icmp_packet(const unsigned char *, const size_t);
void			dump_unknown_packet(const unsigned char *, const size_t);
void			dump_ethernet_frame(const unsigned char *, const size_t);
void			protocol_switcher(const unsigned char *,
					  const size_t,
					  const unsigned int);

typedef struct          s_protocols
{
  char			*protocol_tag;
  unsigned int		value;
  void			(*function)(const unsigned char *packet,
				    size_t packet_size);
}                       t_protocols;

# define PROTOCOLS_TABLE						\
  ENTRY(ARP = 0,	"ARP",		ETH_P_ARP,	&dump_arp_packet) \
  ENTRY(IPv4,		"IPv4",		ETH_P_IP,	&dump_ip_packet) \
  ENTRY(TCP,		"TCP",		IPPROTO_TCP,	&dump_tcp_segment) \
  ENTRY(UDP,		"UDP",		IPPROTO_UDP,	&dump_udp_datagram) \
  ENTRY(ICMP,		"ICMP",		IPPROTO_ICMP,	&dump_icmp_packet) \
  ENTRY(UNKNOWN,	"UNKNOWN",	0xDEAD,		&dump_unknown_packet) \


enum {
# define ENTRY(a, b, c, d) a,
  PROTOCOLS_TABLE
# undef ENTRY
  LIMIT
};

extern t_protocols         g_protocols[LIMIT];

#endif /* !PROTOCOLS_H_ */
