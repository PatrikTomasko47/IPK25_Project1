CC = gcc
CFLAGS = -Wall -D_GNU_SOURCE -g -std=c17

TARGET = ipk-l4-scan
SRC = ipk-l4-scan.c ll_ip_array.c input_parser.c ip_utility.c packet_builder.c port_analyzer.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

setuid: $(TARGET)
	@echo "Setting root ownership and setuid bit on $(TARGET)..."
	sudo chown root:root $(TARGET)
	sudo chmod u+s $(TARGET)

clean: 
	rm -f $(TARGET)
