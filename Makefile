CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11
LDFLAGS ?=

TARGET = process_memory_scanner
SOURCES = main.c Process.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)
