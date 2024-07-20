NAME	 = udp_test
SRCS	 = udp_test.c udp.c read_config.c
OBJS	 = $(SRCS:.c=.o)
CC		 = gcc
CFLAGS	 = -Wall -Wextra
LIBS	 = 
LDFLAGS	 = 

.PHONY: all
all: $(NAME) objclean
$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) $(LIBS) -o $(NAME)

.PHONY: objclean
objclean:
	rm -f $(OBJS)

.PHONY: clean
clean:
	rm -f $(NAME)
	rm -f $(OBJS)

.PHONY: re
re: clean all
