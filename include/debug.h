/*
** debug.h for DEBUG_H_ in /home/janel/Documents/coding/my_network_analyser
** 
** Made by SRJanel
** Login SRJanel <n******.*********@epitech.eu>
** 
** Started on  Sat Aug 19 21:14:39 2017 
** Last update Wed Aug 30 16:42:05 2017 
*/

#ifndef DEBUG_H_
# define DEBUG_H_

# include <stdio.h>
# include <errno.h>

# define PRINT_POSITION		fprintf(stderr, "\n******** %s ********\n", \
					__extension__ __FUNCTION__)
# define PRINT_ERROR(MESG)	fprintf(stderr, "%s ERROR: %s\n", MESG, strerror(errno))

#endif /* !DEBUG_H_ */
