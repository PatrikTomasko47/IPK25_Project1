CC = gcc
CFLAGS = -Wall -g -std=c17

TARGET = ipk-l4-scan
SRC = ipk-l4-scan.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean: 
	rm -f $(TARGET)
