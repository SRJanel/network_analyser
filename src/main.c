/*
** main.c for main in /home/janel/Documents/coding/my_network_analyser
** 
** Made by SRJanel
** Login SRJanel <n******.*********@epitech.eu>
** 
** Started on  Sat Aug 19 21:02:34 2017 
** Last update Mon Oct 23 01:35:49 2017 
*/

#include <time.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <linux/filter.h>
#include <netinet/if_ether.h>
#include "protocols.h"
#include "network.h"
#include "options.h"
#include "utils.h"

extern volatile int	g_sd;

static void		signal_handler(int signum)
{
  close(g_sd);
  (void)signum;
}

inline static void	usage(const char * const prog_name)
{
  fprintf(stderr, "USAGE: %s [-ipfh]\n"					\
	  "\t-i, --interface\t\tIf not specified, listening on all interfaces.\n" \
	  "\t-p, --promiscuous\tSet device to promiscuous mode. Must be combined\n" \
	  "\t\t\t\twith option -i (--interface).\n"			\
	  "\t-f, --filter\t\tYou can set a Linux Socket Filter (LSF).\n" \
	  "\t\t\t\tExamples:\t-f \"tcp\".\n"				\
	  "\t\t\t\t\t\t-f \"udp && src 127.0.0.1 && src port 4242\".\n" \
	  "\t\t\t\t\t\t-f \"tcp[13] & 2!=0\". (Shows only SYN packets).\n" \
	  "\t-h, --help\t\tDisplays this message.\n", prog_name);
}

char			set_linux_socket_filter(const char * const filter_string)
{
  struct sock_fprog	filter;
  int			i;
  int			line_counter;
  char			tcpdump_command[1024] = {0};
  FILE			*tcpdump_output;

  line_counter = 0;
  if (strlen(filter_string) < 1000)
    sprintf(tcpdump_command, "tcpdump \"%s\" -ddd", filter_string);
  if (!(tcpdump_output = popen(tcpdump_command, "r"))
      || fscanf(tcpdump_output, "%d\n", &line_counter) != 1
      || !(filter.filter = calloc(sizeof(struct sock_filter)*line_counter, 1)))
    return (PRINT_ERROR("[*] Cannot use filter"), 0);
  filter.len = line_counter;
  i = -1;
  while (++i < line_counter)
    if (fscanf(tcpdump_output, "%hu %hhu %hhu %u\n", &(filter.filter[i].code),
	       &(filter.filter[i].jt), &(filter.filter[i].jf),
	       &(filter.filter[i].k)) != 4)
      return (PRINT_ERROR("[*] Cannot use filter"), 0);
  pclose(tcpdump_output);
  if (setsockopt(g_sd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) == -1)
    return (PRINT_ERROR("[*] Cannot set filter"), 0);
  return (1);
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
  if (options.promiscuous && options.interface
      && set_promiscuous_mode(options.interface) == -1)
    return (EXIT_FAILURE);

  if (options.filter)
    set_linux_socket_filter(options.filter);
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
