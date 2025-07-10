CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lssl -lcrypto -lgmp

SRCS = main.c group.c signatures.c hashes.c keys.c
OBJS = $(SRCS:.c=.o)

TARGET = el

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

