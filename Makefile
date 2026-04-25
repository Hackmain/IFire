TARGET = ifire

SRC_DIR = src
SRC = $(filter-out $(SRC_DIR)/sniffer.c, $(wildcard $(SRC_DIR)/*.c))
OBJ = $(SRC:.c=.o)

CC      = cc
CFLAGS  = -Wall -Wextra -g -I$(SRC_DIR)
LIBS    = -lpcap
LDFLAGS =

.PHONY: all clean debug install

all: $(TARGET)

debug: CFLAGS += -ggdb -O0 -DDEBUG
debug: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) $(LDFLAGS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) -c $< -o $@ $(CFLAGS)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)

clean:
	rm -f $(SRC_DIR)/*.o $(TARGET)
