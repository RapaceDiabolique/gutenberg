CFLAGS		:= -W -Wall -Wextra -m32

LDFLAGS		:= -m32

NAME_STDIN	:= format_string_stdin
SRC_STDIN	:= format_string_stdin.c
OBJ_STDIN	:= $(SRC_STDIN:.c=.o)

NAME_ARGS	:= format_string_args
SRC_ARGS	:= format_string_args.c
OBJ_ARGS	:= $(SRC_ARGS:.c=.o)


all: $(NAME_STDIN) $(NAME_ARGS)

$(NAME_STDIN): $(OBJ_STDIN)
	$(CC) -o $(NAME_STDIN) $(OBJ_STDIN) $(LDFLAGS)

$(NAME_ARGS): $(OBJ_ARGS)
	$(CC) -o $(NAME_ARGS) $(OBJ_ARGS) $(LDFLAGS)

clean:
	$(RM) $(OBJ_STDIN) $(OBJ_ARGS) $(NAME_STDIN) $(NAME_ARGS)

re: clean all

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

.PHONY: all clean fclean re
