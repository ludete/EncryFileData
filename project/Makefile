CC=gcc
CPPFLAGS= -I./incl -I/home/yyx/02/openssl-1.0.1t/include
CFLAGS=-Wall -g
LIBPATH = -L /usr/lib
LIBS=  -lssl -lcrypto -lpthread -lm -ldl


#找到当前目录下所有的.c文件
src = $(wildcard ./src/*.c)

#将当前目录下所有的.c  转换成.o给obj
obj = $(patsubst %.c, %.o, $(src))

encry_dec_data = encry_dec_data
test = test_debug

target = $(encry_dec_data) $(test)

ALL:$(target)
    
#生成所有的.o文件
$(obj):%.o:%.c
	$(CC) -c $< -o $@ $(CPPFLAGS) $(LIBPATH) $(LIBS) $(CFLAGS) -D _OS_LINUX_
	
	
	
#encry_dec_data
$(encry_dec_data):./src/test_encry_dec.o  ./src/encryptData.o
	$(CC) $^ -o $@ $(CPPFLAGS)  $(LIBPATH) $(LIBS) $(CFLAGS)  
	
#test
$(test):./src/test.o
	$(CC) $^ -o $@ $(CPPFLAGS)
	
	
#clean指令

clean:
	-rm -rf $(obj) $(target) ./src/*.o


#将clean目标 改成一个虚拟符号
.PHONY: clean ALL 