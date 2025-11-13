# abtain GCC main version
GCC_VERSION := $(shell gcc -dumpversion | cut -d. -f1)

DYNAMIC_LIB = libelfutil.so
OUT_LIB=/usr/lib/
LIB_SRCS = $(wildcard *.c)
LIB_OBJS = $(LIB_SRCS:.c=.o)
CFLAGS = -w -c -fPIC

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

# HarmonyOS cross build: aarch64-linux-ohos
ifeq ($(findstring aarch64-linux-ohos,$(CC)),aarch64-linux-ohos)
CFLAGS += -DOHOS
endif

# Android cross build: aarch64-linux-android
ifeq ($(findstring aarch64-linux-android,$(CC)),aarch64-linux-android)
CFLAGS += -DANDROID
endif

# default target
all: $(DYNAMIC_LIB)

# generate dynamic link library
$(DYNAMIC_LIB) : $(LIB_OBJS)
	$(CC) -shared $(LIB_OBJS) -o $(DYNAMIC_LIB)

.PHONY: clean
clean:
	rm -rvf *.o
	rm -vf $(DYNAMIC_LIB)

.PHONY: install
install:$(DYNAMIC_LIB)
	@echo "begin install "$(DYNAMIC_LIB)
	cp $(DYNAMIC_LIB) $(OUT_LIB)
	@echo $(DYNAMIC_LIB) "install success!"
