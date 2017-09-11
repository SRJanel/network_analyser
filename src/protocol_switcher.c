/*
** protocol_switcher.c for protocol_switcher in /home/janel/Documents/coding/my_network_analyser
** 
** Made by SRJanel
** Login SRJanel <n******.*********@epitech.eu>
** 
** Started on  Sat Aug 19 22:27:44 2017 
** Last update Mon Sep 11 04:40:34 2017 
*/

#include "utils.h"
#include "protocols.h"

t_protocols         g_protocols[LIMIT] =
  {
# define ENTRY(a, b, c, d) {b, c, d},
    PROTOCOLS_TABLE
# undef ENTRY
  };

void		protocol_switcher(const unsigned char *packet,
				  const size_t packet_size,
				  const unsigned int protocol_value)
{
  size_t	protocol;

  protocol = 0;
  while (protocol < LIMIT
	 && g_protocols[protocol].value != protocol_value)
    ++protocol;
  g_protocols[(protocol != LIMIT)
	      ? (protocol)
	      : (LIMIT - 1)].function(packet, packet_size);
}
