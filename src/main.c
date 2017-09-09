/*
** main.c for main in /home/janel/Documents/coding/my_network_analyser
** 
** Made by SRJanel
** Login SRJanel <n******.*********@epitech.eu>
** 
** Started on  Sat Aug 19 21:02:34 2017 
** Last update Sat Sep  9 04:27:49 2017 
*/

#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include "protocols.h"
#include "utils.h"

inline static void	usage(const char * const prog_name)
{
  fprintf(stderr, "USAGE: %s <iface>\n"					\
	  "\t<iface>\t\tIf not specified, listening on all interfaces\n", prog_name);
}

static char		raw_bind_iface(const int sd, const char *iface)
{
  struct ifreq		ifr;
  struct sockaddr_ll	sockaddr;

  memset(&ifr, 0, sizeof ifr);
  strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
  if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) == -1
      || ioctl(sd, SIOCGIFINDEX, &ifr) == -1)
    return (-1);
  memset(&sockaddr, 0, sizeof(struct sockaddr_ll));
  sockaddr.sll_family = AF_PACKET;
  sockaddr.sll_ifindex = ifr.ifr_ifindex;
  sockaddr.sll_protocol = htons(ETH_P_ALL);
  return (bind(sd, (struct sockaddr *)&sockaddr, sizeof sockaddr));
}

int			main(int argc, char *argv[])
{
  int			sd;
  unsigned char		packet[IP_MAXPACKET] = {0};
  ssize_t		byte_read;
  time_t		tm;
  char			tm_formatted[256];

  if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")))
    return (usage(argv[0]), EXIT_FAILURE);
  if ((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    return (PRINT_ERROR("Socket creation failed:"), EXIT_FAILURE);
  if (argc == 2 && raw_bind_iface(sd, argv[1]) == -1)
    return (PRINT_ERROR("Bind failed:"), EXIT_FAILURE);
  while ("true")
    {
      tm = time(NULL);
      strftime(tm_formatted, 256, "%B %d %Y-%T", localtime(&tm));
      if ((byte_read = recvfrom(sd, packet, IP_MAXPACKET, 0, NULL, NULL)) <= 0)
	return (PRINT_ERROR("Cannot capture:"), EXIT_FAILURE);
      fprintf(stdout, "\n\n******************* New Packet "	\
	      "<%s> *******************\n", tm_formatted);
      dump_ethernet_frame(packet, byte_read);
    }
  return (EXIT_SUCCESS);
}
