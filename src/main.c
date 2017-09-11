/*
** main.c for main in /home/janel/Documents/coding/my_network_analyser
** 
** Made by SRJanel
** Login SRJanel <n******.*********@epitech.eu>
** 
** Started on  Sat Aug 19 21:02:34 2017 
** Last update Sat Sep  9 20:56:57 2017 
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
#include <linux/filter.h>
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
  fprintf(stderr, "USAGE: %s [-ipfh]\n"					\
	  "\t-i, --interface\t\tIf not specified, listening on all interfaces.\n" \
	  "\t-p, --promiscious\tSet device to promiscious mode. Must be combined\n" \
	  "\t\t\t\twith option -i (--interface).\n"			\
	  "\t-f, --filter\t\tYou can set a Linux Socket Filter (LSF).\n" \
	  "\t\t\t\tExamples:\t-f \"tcp\".\n"				\
	  "\t\t\t\t\t\t-f \"udp && src 127.0.0.1 && src port 4242\".\n" \
	  "\t\t\t\t\t\t-f \"tcp[13] & 2!=0\". (Shows only SYN packets).\n" \
	  "\t-h, --help\t\tDisplays this message.\n", prog_name);
}

# define FORMAT int help; char *interface; int promiscious; char *filter;
static struct s_options {FORMAT}	get_args(int argc, char **argv)
  {
    # undef FORMAT
    int					c;
    int					index;
    struct s_options			options = {.0, NULL, .0, NULL};
    struct option			long_options[] =
      {
	{"interface", required_argument, NULL, 'i'},
	{"filter", required_argument, NULL, 'f'},
	{"promiscious", no_argument, &options.promiscious, 1},
	{"help", no_argument, &options.help, 1},
	{NULL, 0, NULL, 0}
      };
    while (1)
      {
	if ((c = getopt_long(argc, argv, "hpi:f:",
			     long_options, &index)) == -1)
	  break ;
	else if (c == 'i')
	  options.interface = optarg;
	else if (c == 'f')
	  options.filter = optarg;
	else if (c == 'p')
	  options.promiscious = 1;
	else if (c == 'h' || c == '?')
	  options.help = 1;
      }
    return (options);
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
  if (options.promiscious && options.interface
      && set_promiscious_mode(options.interface) == -1)
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
