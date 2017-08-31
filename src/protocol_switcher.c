/*
** protocol_switcher.c for protocol_switcher in /home/janel/Documents/coding/my_network_analyser
** 
** Made by SRJanel
** Login SRJanel <n******.*********@epitech.eu>
** 
** Started on  Sat Aug 19 22:27:44 2017 
** Last update Wed Aug 30 16:03:07 2017 
*/

#include <stdio.h>
#include "utils.h"
#include "protocols.h"

t_protocols         g_protocols[LIMIT] =
  {
# define ENTRY(a, b, c, d) {b, c, d},
    PROTOCOLS_TABLE
# undef ENTRY
  };

char		protocol_switcher(const unsigned char *packet,
				  const unsigned int protocol_value)
{
  size_t	protocol;

  protocol = 0;
  while (protocol < LIMIT
	 && g_protocols[protocol].value != protocol_value)
    ++protocol;
  
  if (protocol != LIMIT)
    {
      fprintf(stdout, "g_protocols[%ld].protocol_tag: %s\n", protocol, g_protocols[protocol].protocol_tag);
      fprintf(stdout, "g_protocols[%ld].value: 0x%x\n", protocol, g_protocols[protocol].value);
      g_protocols[protocol].function(packet);
      return (TRUE);
    }
  g_protocols[LIMIT - 1].function(packet);
  return (FALSE);
}
