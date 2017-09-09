/*
** main.c for main in /home/janel/Documents/coding/my_network_analyser
** 
** Made by SRJanel
** Login SRJanel <n******.*********@epitech.eu>
** 
** Started on  Sat Aug 19 21:02:34 2017 
** Last update Sat Sep  9 04:58:01 2017 
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

static volatile int	g_sd;

static void		signal_handler(int signum)
{
  close(g_sd);
  (void)signum;
}

inline static void	usage(const char * const prog_name)
{
  fprintf(stderr, "USAGE: %s <iface>\n"					\
	  "\t<iface>\t\tIf not specified, listening on all interfaces\n", prog_name);
}

static char		raw_bind_iface(const char *iface)
{
  struct ifreq		ifr;
  struct sockaddr_ll	sockaddr;

  memset(&ifr, 0, sizeof ifr);
  strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
  if (setsockopt(g_sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) == -1
      || ioctl(g_sd, SIOCGIFINDEX, &ifr) == -1)
    return (-1);
  memset(&sockaddr, 0, sizeof(struct sockaddr_ll));
  sockaddr.sll_family = AF_PACKET;
  sockaddr.sll_ifindex = ifr.ifr_ifindex;
  sockaddr.sll_protocol = htons(ETH_P_ALL);
  return (bind(g_sd, (struct sockaddr *)&sockaddr, sizeof sockaddr));
}

int			main(int argc, char *argv[])
{
  /* int			sd; */
  unsigned char		packet[IP_MAXPACKET] = {0};
  ssize_t		byte_read;
  struct tm		*tm;
  char			tm_formatted[256];
  struct sigaction	signal;
  
  signal.sa_handler = signal_handler;
  sigaction(SIGINT, &signal, NULL);
  if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")))
    return (usage(argv[0]), EXIT_FAILURE);
  if ((g_sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    return (PRINT_ERROR("Socket creation failed:"), EXIT_FAILURE);
  if (argc == 2 && raw_bind_iface(argv[1]) == -1)
    return (PRINT_ERROR("Bind failed:"), EXIT_FAILURE);
  while ("it's on")
    {
      if ((tm = localtime((time_t[1]){time(NULL)})) != (struct tm *)-1)
	strftime(tm_formatted, 256, "%B %d %Y-%T", tm);
      if ((byte_read = recvfrom(g_sd, packet, IP_MAXPACKET, 0, NULL, NULL)) <= 0)
	return (PRINT_ERROR("Cannot capture:"), EXIT_FAILURE);
      fprintf(stdout, "\n\n******************* New Packet "	\
	      "<%s> *******************\n", tm_formatted);
      dump_ethernet_frame(packet, byte_read);
    }
  return (EXIT_SUCCESS);
}
