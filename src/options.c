/*
** options.c for options
** 
** Made by SRJanel
** Login SRJanel <n******.******s@epitech.eu>
** 
** Started on  Mon Oct 23 01:26:58 2017 
** Last update Mon Oct 23 01:36:41 2017 
*/

#include <stdlib.h>
#include <getopt.h>
#include "options.h"

struct s_options	options;

static struct option	g_long_options[] =
  {
    {"interface", required_argument, NULL, 'i'},
    {"filter", required_argument, NULL, 'f'},
    {"promiscuous", no_argument, &options.promiscuous, 1},
    {"help", no_argument, &options.help, 1},
    {NULL, 0, NULL, 0}
  };

struct s_options	get_args(int argc, char **argv)
  {
    int			c;
    int			index;
    struct s_options	options = {.0, NULL, .0, NULL};

    while (1)
      {
	if ((c = getopt_long(argc, argv, "hpi:f:",
			     g_long_options, &index)) == -1)
	  break ;
	else if (c == 'i')
	  options.interface = optarg;
	else if (c == 'f')
	  options.filter = optarg;
	else if (c == 'p')
	  options.promiscuous = 1;
	else if (c == 'h' || c == '?')
	  options.help = 1;
      }
    return (options);
}
