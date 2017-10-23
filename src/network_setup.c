/*
** network_setup.c for network_setup
** 
** Made by SRJanel
** Login SRJanel <n******.******s@epitech.eu>
** 
** Started on  Sat Sep  9 17:36:32 2017 
** Last update Mon Oct 23 02:59:50 2017 
*/

#include <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include "utils.h"

int			g_sd;

char			raw_bind_iface(const char *iface)
{
  struct ifreq		ifr = {0};
  struct sockaddr_ll	sockaddr;

  strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
  if (ioctl(g_sd, SIOCGIFINDEX, &ifr) == -1
      || setsockopt(g_sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr) == -1)
    return (-1);
  memset(&sockaddr, 0, sizeof(struct sockaddr_ll));
  sockaddr.sll_family = AF_PACKET;
  sockaddr.sll_ifindex = ifr.ifr_ifindex;
  sockaddr.sll_protocol = htons(ETH_P_ALL);
  return (bind(g_sd, (struct sockaddr *)&sockaddr, sizeof sockaddr));
}

char			set_promiscuous_mode(const char *iface)
{
  struct packet_mreq	mreq = {0};
  struct ifreq		ifr = {0};
  
  strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
  if (ioctl(g_sd, SIOCGIFINDEX, &ifr) == -1)
    return (PRINT_ERROR("Could not get interface index:"), -1);
  mreq.mr_ifindex = ifr.ifr_ifindex;  
  mreq.mr_type = PACKET_MR_PROMISC;
  if (setsockopt(g_sd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof mreq) != 0)
    return (PRINT_ERROR("Could not enter promiscuous mode"), -1);
  fprintf(stdout, "[+] Entered promiscuous mode on %s\n", iface);
  return (0);
}
