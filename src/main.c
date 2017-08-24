/*
** main.c for main in /home/janel/Documents/coding/my_network_analyser
** 
** Made by SRJanel
** Login SRJanel <n******.*********@epitech.eu>
** 
** Started on  Sat Aug 19 21:02:34 2017 
** Last update Sun Aug 20 18:54:57 2017 
*/

#include <unistd.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include "network_analyzer.h"
#include "debug.h"

void		dump_packet(const char *packet)
{
  /* size_t	i; */

  /* i = 0; */
  /* PRINT_POSITION; */
  /* while (i < IP_MAXPACKET) */
  /*   { */
  /*     write(1, &packet[i], IP_MAXPACKET); */
  /*     ++i; */
  /*   } */
  print_ethernet_frame(packet);
}

void	capture_packet(const int sd)
{
  char	buffer[IP_MAXPACKET] = {0};

  PRINT_POSITION;
  if (recvfrom(sd, buffer, IP_MAXPACKET, 0, NULL, NULL) <= 0)
    return ;
  dump_packet(buffer);
}

int	main(void)
{
  int	sd;

  if ((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    return (EXIT_FAILURE);

  while (1)
    {
      capture_packet(sd);
      /* analyze_packet(); */
      /* dump_packet(sd); */
    }

  return (EXIT_SUCCESS);
}
