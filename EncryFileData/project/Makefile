CC=gcc
CPPFLAGS= -I./incl -I/home/yyx/02/openssl-1.0.1t/include
CFLAGS=-Wall -g
LIBPATH = -L /usr/lib
LIBS=  -lssl -lcrypto -lpthread -lm -ldl
#LIBS=  -lpthread -lm -ldl

#找到当前目录下所有的.c文件
src = $(wildcard ./src/*.c)

#将当前目录下所有的.c  转换成.o给obj
obj = $(patsubst %.c, %.o, $(src))

encry_dec_data = encry_dec_data
test = test_debug
test_thread_pool = test_thread_pool
mutilProcessCopy = mutilProcessCopy
test_create_citi_file = test_create_citi_file
libencrydecry = libencrydecry.so
release_version = release_EncryDecry_File
test_write_log = test_write_log


#target =  $(release_version) $(libencrydecry) $(test_create_citi_file) $(test) $(test_write_log)
#target =  $(encry_dec_data)	$(test) $(mutilProcessCopy) $(test_create_citi_file) $(libencrydecry) $(release_version)

target = $(test_write_log) $(libencrydecry) $(release_version)
ALL:$(target)
    
#生成所有的.o文件
$(obj):%.o:%.c
	$(CC) -c $< -o $@ $(CPPFLAGS) $(LIBPATH) $(LIBS) $(CFLAGS) 
	
	
	
#encry_dec_data
$(encry_dec_data):./src/test_encry_dec.o  ./src/encryptData.o ./src/include_sub_function.o ./src/thread_pool.o
	$(CC) $^ -o $@ $(CPPFLAGS)  $(LIBPATH) $(LIBS) $(CFLAGS)  

#release_version
$(release_version):./src/test_release.o  ./src/encryDecryFile.o ./src/include_sub_function.o ./src/include_EncryDecry.o
	$(CC) $^ -o $@ $(CPPFLAGS)  $(LIBPATH) $(LIBS) $(CFLAGS) 
	
#libencrydecry
$(libencrydecry): ./src/encryDecryFile.c ./src/include_sub_function.c ./src/include_EncryDecry.c
	$(CC) $^ -fPIC -shared -o $@ $(CPPFLAGS)  $(LIBPATH) $(LIBS) $(CFLAGS)  

#test
$(test):./src/test.o
	$(CC) $^ -o $@ $(CPPFLAGS) $(LIBPATH) $(LIBS) $(CFLAGS)  


#test
$(test_write_log):./src/test_log.o ./src/socklog.o
	$(CC) $^ -o $@ $(CPPFLAGS) $(LIBPATH) $(LIBS) $(CFLAGS)  

#test_create_citi_file
$(test_create_citi_file):./src/test_create_certifile.o
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
