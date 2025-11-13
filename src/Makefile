# obtain GCC main version
GCC_VERSION := $(shell gcc -dumpversion | cut -d. -f1)

BIN=elfspirit
LIB=libelfspirit
OUT=/usr/local/bin/
SRCS = $(wildcard *.c cJSON/cJSON.c)
OBJS = $(SRCS:.c=.o)
CFLAGS = -w -c
# LDFLAGS = -L./lib -lelfutil

# static link
ifeq ($(static),true)
    LDFLAGS += -static
endif

# debug mode
ifeq ($(debug),true)
    CXXFLAGS=-g -fsanitize=address
    CXXFLAGS+=-Ddebug
else
    CXXFLAGS=-O3
endif

# if gcc version is larger than 14, add new flags
# 如果GCC版本>=14，添加额外警告抑制选项
ifeq ($(shell test $(GCC_VERSION) -ge 14; echo $$?),0)
    CFLAGS += -Wno-int-conversion -Wno-incompatible-pointer-types \
                -Wno-int-conversion -Wno-implicit-function-declaration
endif

# HarmonyOS cross build: aarch64-linux-ohos
ifeq ($(findstring aarch64-linux-ohos,$(CC)),aarch64-linux-ohos)
CFLAGS += -DOHOS
endif

# Android cross build: aarch64-linux-ohos
ifeq ($(findstring aarch64-linux-android,$(CC)),aarch64-linux-android)
CFLAGS += -DANDROID
endif

all: $(LIB) $(BIN)

$(BIN) : $(OBJS)
	$(CC) $(CXXFLAGS) $(LDFLAGS) $(OBJS) -o $(BIN)

# generate dynamic library
$(LIB):
	@echo "Building library in lib directory..."
	$(MAKE) -C lib

.PHONY: clean
clean:
	rm -rvf *.o
	rm -rvf cJSON/*.o
	rm -vf $(BIN)
	$(MAKE) -C lib clean

.PHONY: install
install:$(BIN)
	@echo "begin install "$(BIN)
	cp $(BIN) $(OUT)
	@echo $(BIN) "install success!"