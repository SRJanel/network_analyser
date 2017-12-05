/*
** options.h for OPTIONS_H_
** 
** Made by SRJanel
** Login SRJanel <n******.******s@epitech.eu>
** 
** Started on  Sat Oct 14 21:57:19 2017 
** Last update Mon Dec  4 18:46:07 2017 
*/

#ifndef OPTIONS_H_
# define OPTIONS_H_

# define STRINGIFY(x) #x
# define MAKE_STRING(x) STRINGIFY(x)

# define OPTIONS_WITH_ARG_TABLE						\
  ENTRY(interface, required_argument, 'i')				\
  ENTRY(filter, required_argument, 'f')					\

# define OPTIONS_WITHOUT_ARG_TABLE		\
  ENTRY(promiscuous, 'p')			\
  ENTRY(help, 'h')

# define OPTSTRING	"hpi:f:"

extern struct s_options {
# define ENTRY(FIELD, UNUSED1, UNUSED2) char *FIELD;
  OPTIONS_WITH_ARG_TABLE
# undef ENTRY
# define ENTRY(FIELD, UNUSED1) int FIELD;
  OPTIONS_WITHOUT_ARG_TABLE
# undef ENTRY
}	get_args(int argc, char **argv);

#endif /* !OPTIONS_H_ */
