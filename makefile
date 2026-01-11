# makefile for the trace router project

CC = gcc
CFLAGS = -c
TARGET = tracert
OBJ = tracert.o

#defining phony for compiling, running and cleaning
.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(OBJ)

$(OBJ): tracert.c tracert.h
	$(CC) $(CFLAGS) $< -o $@

run:
	sudo ./$(TARGET) -a 1.1.1.1

clean:
	rm $(TARGET) $(OBJ)		