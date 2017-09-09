/*
** main.c for main in /home/janel/Documents/coding/my_network_analyser
** 
** Made by SRJanel
** Login SRJanel <n******.*********@epitech.eu>
** 
** Started on  Sat Aug 19 21:02:34 2017 
** Last update Sat Sep  9 17:57:45 2017 
*/

#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include "protocols.h"
#include "network.h"
#include "utils.h"

extern volatile int	g_sd;

static void		signal_handler(int signum)
{
  close(g_sd);
  (void)signum;
}

inline static void	usage(const char * const prog_name)
{
  fprintf(stderr, "USAGE: %s [-iph]\n"					\
	  "\t-i, --interface\t\tIf not specified, listening on all interfaces.\n" \
	  "\t-p, --promiscious\tSet device to promiscious mode. Must be combined\n" \
	  "\t\t\t\twith option -i (--interface).\n" \
	  "\t-h, --help\t\tDisplays this message.\n", prog_name);
}

static struct s_options {int help;
  char *interface; int promiscious;}	get_args(int argc, char **argv)
  {
    int					c;
    int					index;
    static struct s_options		options = {.0, NULL, .0};
    static struct option		long_options[] =
      {
	{"interface", required_argument, NULL, 'i'},
	{"promiscious", no_argument, &options.promiscious, 1},
	{"help", no_argument, &options.help, 1},
	{NULL, 0, NULL, 0}
      };
    while (1)
      {
	if ((c = getopt_long(argc, argv, "hpi:",
			     long_options, &index)) == -1)
	  break ;
	else if (c == 'i')
	  options.interface = optarg;
	else if (c == 'p')
	  options.promiscious = 1;
	else if (c == 'h' || c == '?')
	  options.help = 1;
      }
    return (options);
}

char			setup(int argc, char *argv[])
{
  struct s_options	options;
  struct sigaction	signal = {0};

  options = get_args(argc, argv);
  signal.sa_handler = signal_handler;
  sigaction(SIGINT, &signal, NULL);
  if (options.help)
    return (usage(argv[0]), EXIT_FAILURE);
  if ((g_sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    return (PRINT_ERROR("Socket creation failed:"), EXIT_FAILURE);
  if (options.promiscious && options.interface
      && set_promiscious_mode(options.interface) == -1)
    return (EXIT_FAILURE);
  return ((options.interface && raw_bind_iface(options.interface) == -1)
	  ? (PRINT_ERROR("Bind failed:"), EXIT_FAILURE)
	  : (EXIT_SUCCESS));
}

int			main(int argc, char *argv[])
{
  unsigned char		packet[IP_MAXPACKET] = {0};
  ssize_t		byte_read;
  struct tm		*tm;
  char			tm_formatted[256];

  if (setup(argc, argv) == EXIT_FAILURE)
    return (EXIT_FAILURE);
  sleep(1);

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
