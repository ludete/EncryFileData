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
test_thread_pool = test_thread_pool
mutilProcessCopy = mutilProcessCopy

#target = $(encry_dec_data) $(test_thread_pool)
target =  $(encry_dec_data)	$(test) $(mutilProcessCopy)

ALL:$(target)
    
#生成所有的.o文件
$(obj):%.o:%.c
	$(CC) -c $< -o $@ $(CPPFLAGS) $(LIBPATH) $(LIBS) $(CFLAGS) -D _OS_LINUX_
	
	
	
#encry_dec_data
$(encry_dec_data):./src/test_encry_dec.o  ./src/encryptData.o ./src/include_sub_function.o ./src/thread_pool.o
	$(CC) $^ -o $@ $(CPPFLAGS)  $(LIBPATH) $(LIBS) $(CFLAGS)  
	
#test
$(test):./src/test.o
	$(CC) $^ -o $@ $(CPPFLAGS) $(LIBPATH) $(LIBS) $(CFLAGS)  

	
#test_thread_pool
$(test_thread_pool):./src/test_thread_pool.o  ./src/thread_pool.o ./src/include_sub_function.o
	$(CC) $^ -o $@ $(CPPFLAGS)  $(LIBPATH) $(LIBS) $(CFLAGS)  	

#mutilProcessCopy
$(mutilProcessCopy):./src/mult_process_cp.o
	$(CC) $^ -o $@ $(CPPFLAGS)  $(LIBPATH) $(LIBS) $(CFLAGS)  
	
#clean指令

clean:
	-rm -rf $(obj) $(target) ./src/*.o


#将clean目标 改成一个虚拟符号
.PHONY: clean ALL 