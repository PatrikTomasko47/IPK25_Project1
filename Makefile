CC = gcc
CFLAGS = -Wall -D_GNU_SOURCE -g -std=c17

TARGET = ipk-l4-scan
SRC = ipk-l4-scan.c ll_ip_array.c input_parser.c ip_utility.c packet_builder.c port_analyzer.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean: 
	rm -f $(TARGET)
