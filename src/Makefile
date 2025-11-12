# 获取GCC主版本号
GCC_VERSION := $(shell gcc -dumpversion | cut -d. -f1)

TARGET=elfspirit
DYNAMIC_LIB = libelfutil.so
LIB_SRCS = elfutil.c section_manager.c
LIB_OBJS = $(LIB_SRCS:.c=.o)
OUT=/usr/local/bin/
OUT_LIB=/usr/lib/
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

# 断是否为aarch64-linux-ohos
ifeq ($(findstring aarch64-linux-ohos,$(CC)),aarch64-linux-ohos)
CFLAGS += -DOHOS
endif

# 断是否为aarch64-linux-android
ifeq ($(findstring aarch64-linux-android,$(CC)),aarch64-linux-android)
CFLAGS += -DANDROID
endif

# 默认目标
all: $(DYNAMIC_LIB) $(TARGET)

# 生成动态链接库
$(DYNAMIC_LIB) : $(LIB_OBJS)
	$(CC) -shared $(LIB_OBJS) -o $(DYNAMIC_LIB)

# 编译动态库对象文件（使用-fPIC）
elfutil.o: elfutil.c elfutil.h
	$(CC) $(CFLAGS) -fPIC $< -o $@

# 生成可执行文件
$(TARGET) : $(OBJS)
	$(CC) $(CXXFLAGS) $(LDFLAGS) $(OBJS) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) $(CXXFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -rvf *.o
	rm -rvf cJSON/*.o
	rm -vf $(TARGET)
	rm -vf $(DYNAMIC_LIB)

.PHONY: install
install:$(TARGET)
	@echo "begin install "$(TARGET)
	cp $(TARGET) $(OUT)
	cp $(DYNAMIC_LIB) $(OUT_LIB)
	@echo $(TARGET) "install success!"
