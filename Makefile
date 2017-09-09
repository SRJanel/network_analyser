##
## Makefile for Makefile in /home/janel/Documents/coding/my_network_analyser
## 
## Made by SRJanel
## Login SRJanel <n******.*********@epitech.eu>
## 
## Started on  Sat Aug 19 20:58:06 2017 
## Last update Sat Sep  9 17:37:53 2017 
##

SRC	= src/main.c \
	src/print_packet.c \
	src/protocol_switcher.c \
	src/network_setup.c \

OBJ	= $(SRC:.c=.o)

NAME	= my_network_analyzer

RM	= rm -f

CC	= gcc

CFLAGS	+= -I./include
CFLAGS	+= -Wall -Wextra -Werror
CFLAGS	+= -pedantic-errors # -ansi
#CFLAGS	+= -ggdb3

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(OBJ) -o $(NAME)

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(NAME)

re: fclean all

.PHONY: all clean fclean re
