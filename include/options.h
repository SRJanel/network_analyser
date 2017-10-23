/*
** options.h for OPTIONS_H_
** 
** Made by SRJanel
** Login SRJanel <n******.******s@epitech.eu>
** 
** Started on  Mon Oct 23 01:27:28 2017 
** Last update Mon Oct 23 01:33:31 2017 
*/

#ifndef OPTIONS_H_
# define OPTIONS_H_

struct	s_options {
  int		help;
  char		*interface;
  int		promiscuous;
  char		*filter;
}		get_args(int argc, char **argv);

#endif /* !OPTIONS_H_ */
