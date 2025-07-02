# 获取GCC主版本号
GCC_VERSION := $(shell gcc -dumpversion | cut -d. -f1)

TARGET=elfspirit
OUT=/usr/local/bin/
SRCS = $(wildcard *.c cJSON/cJSON.c)
OBJS = $(SRCS:.c=.o)
CFLAGS = -w -c

# 静态链接控制开关
ifeq ($(static),true)
    LDFLAGS += -static
endif

# 调试模式控制
ifeq ($(debug),true)
    CXXFLAGS=-g -fsanitize=address
    CXXFLAGS+=-Ddebug
else
    CXXFLAGS=-O3
endif

# 如果GCC版本>=14，添加额外警告抑制选项
ifeq ($(shell test $(GCC_VERSION) -ge 14; echo $$?),0)
    CFLAGS += -Wno-int-conversion -Wno-incompatible-pointer-types \
                -Wno-int-conversion -Wno-implicit-function-declaration
endif

$(TARGET) : $(OBJS)
	$(CC) $(CXXFLAGS) $(LDFLAGS) $(OBJS) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) $(CXXFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -rvf *.o
	rm -rvf cJSON/*.o
	rm -vf $(TARGET)

.PHONY: install
install:$(TARGET)
	@echo "begin install "$(TARGET)
	cp $(TARGET) $(OUT)
	@echo $(TARGET) "install success!"
