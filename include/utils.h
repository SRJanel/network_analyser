/*
** utils.h for UTILS_H_ in /home/janel/Documents/coding/my_network_analyser
** 
** Made by SRJanel
** Login SRJanel <n******.*********@epitech.eu>
** 
** Started on  Sat Aug 19 21:37:31 2017 
** Last update Sat Sep  9 02:02:11 2017 
*/

#ifndef UTILS_H_
# define UTILS_H_

# include <stdio.h>
# include <errno.h>

# define RAW_DATA_BYTE_PER_LINE		16
# define PRINT_POSITION			fprintf(stdout, "\n |-------- %s ----------\n", \
						__extension__ __FUNCTION__)

# define PRINT_ERROR(MESG)		fprintf(stderr, "%s ERROR: %s\n", MESG, strerror(errno))
# define PRINT_MAC_ADDRESS(MESG, X)	fprintf(stdout, "%s %02X:%02X:%02X:%02X:%02X:%02X\n", \
						MESG,			\
						X[0],			\
						X[1],			\
						X[2],			\
						X[3],			\
						X[4],			\
						X[5]);
# define PRINT_IP_ADDRESS(MESG, X)	fprintf(stdout, "%s %02d.%02d.%02d.%02d\n", \
						MESG,			\
						X[0],			\
						X[1],			\
						X[2],			\
						X[3]);

#endif /* !UTILS_H_ */
