CC = gcc

TARGET = testapi
SRC = testapi.c

LIB_PATH = ../src/lib
LIB_NAME = elfutil

CFLAGS = -I$(LIB_PATH)
LDFLAGS = -L$(LIB_PATH) -l$(LIB_NAME)

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SRC) $(CFLAGS) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)