# makefile for the trace router project

CC = gcc
CFLAGS = -c
TARGET = tracert

#defining phony for compiling, running and cleaning
.PHONY: all runtcp rundup clean

all: $(TARGET)

$(TARGET): tracert.o

tracert.o: tracert.c tracert.h
	$(CC) $(CFLAGS) $< -o $@

run:
	sudo ./$(TARGET) -a 1.1.1.1

clean:
	rm tracert.o tracert	 		