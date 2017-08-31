/*
** main.c for main in /home/janel/Documents/coding/my_network_analyser
** 
** Made by SRJanel
** Login SRJanel <n******.*********@epitech.eu>
** 
** Started on  Sat Aug 19 21:02:34 2017 
** Last update Wed Aug 30 16:37:20 2017 
*/




#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <netinet/ip.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include "network_analyzer.h"
#include "debug.h"

static void	__attribute__((unused))usage(char *prog_name)
{
  fprintf(stdout, "USAGE: %s <iface>\n" \
	  "<iface>\tIf not specified, listening on all interfaces\n", prog_name);
}

/* void		dump_packet(const char *packet) */
/* { */
  /* size_t	i; */

  /* i = 0; */
  /* PRINT_POSITION; */
  /* while (i < IP_MAXPACKET) */
  /*   { */
  /*     write(1, &packet[i], IP_MAXPACKET); */
  /*     ++i; */
  /*   } */
/* } */

static char		raw_bind_iface(const int sd, const char *iface)
{
  struct ifreq		ifr;
  struct sockaddr_ll	sockaddr;

  memset(&ifr, 0, sizeof ifr);
  strncpy(ifr.ifr_name, iface, IFNAMSIZ);
  if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) == -1
      || ioctl(sd, SIOCGIFINDEX, &ifr) == -1)
    return (-1);
  memset(&sockaddr, 0, sizeof(struct sockaddr_ll));
  sockaddr.sll_family = AF_PACKET;
  sockaddr.sll_ifindex = ifr.ifr_ifindex;
  sockaddr.sll_protocol = htons(ETH_P_ALL);
  return (bind(sd, (struct sockaddr *)&sockaddr, sizeof sockaddr) == -1);
}

int			main(int argc, char *argv[])
{
  int			sd;
  unsigned char		packet[IP_MAXPACKET] = {0};

  if ((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    return (EXIT_FAILURE);
  if (argc == 2 && raw_bind_iface(sd, argv[1]) == -1)
    return (PRINT_ERROR("Bind failed:"), EXIT_FAILURE);
  while ("true")
    {
      if (recvfrom(sd, packet, IP_MAXPACKET, 0, NULL, NULL) <= 0)
	return (PRINT_ERROR("Cannot capture:"), EXIT_FAILURE);
      fprintf(stdout, "************ New Packet <%s> ************\n", __TIME__);
      analyze_packet(packet);
      /* dump_packet(sd); */
    }

  return (EXIT_SUCCESS);
}
