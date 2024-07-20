NAME	 = raw_test
SRCS	 = raw_test.c src/raw.c src/common.c src/arp.c src/read_config.c src/linked_list.c src/ip.c src/udp.c src/icmp.c
OBJS	 = $(SRCS:.c=.o)
CC		 = gcc
CFLAGS	 = -Wall -Wextra -I./inc
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
