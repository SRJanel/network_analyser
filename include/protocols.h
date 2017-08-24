/*
** protocols.h for PROTOCOLS_H_ in /home/janel/Documents/coding/my_network_analyser
** 
** Made by SRJanel
** Login SRJanel <n******.*********@epitech.eu>
** 
** Started on  Sat Aug 19 21:50:07 2017 
** Last update Sun Aug 20 19:32:04 2017 
*/

#ifndef PROTOCOLS_H_
# define PROTOCOLS_H_

# include <linux/if_ether.h>
# include <linux/in.h>

void			arp_packet(const unsigned char *);
void			ip_packet(const unsigned char *);
void			tcp_packet(const unsigned char *);
void			icmp_packet(const unsigned char *);
void			unknown_packet(const unsigned char *);
char			protocol_switcher(const unsigned char *,
					  const unsigned int);

typedef struct          s_protocols
{
  char			*protocol_tag;
  unsigned int		value;
  void			(*function)(const unsigned char *buffer);
}                       t_protocols;

# define PROTOCOLS_TABLE						\
  ENTRY(ARP = 0,	"ARP",		ETH_P_ARP, &arp_packet)		\
  ENTRY(IPv4,		"IPv4",		ETH_P_IP, &ip_packet)		\
  ENTRY(TCP,		"TCP",		IPPROTO_TCP, &tcp_packet)	\
  ENTRY(ICMP,		"ICMP",		IPPROTO_ICMP, &icmp_packet)	\
  ENTRY(UNKNOWN,	"unknown",	0xDEAD, &unknown_packet)	\

enum {
# define ENTRY(a, b, c, d) a,
  PROTOCOLS_TABLE
# undef ENTRY
  LIMIT
};

extern t_protocols         g_protocols[LIMIT];

#endif /* !PROTOCOLS_H_ */
