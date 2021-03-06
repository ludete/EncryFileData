#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>

void err_int(int ret, const char *err)
{
    if (ret == -1) {
        perror(err);
        exit(1);
    }

    return ;
}

void err_str(char *ret, const char *err)
{
    if (ret == MAP_FAILED) {
        perror(err);
        exit(1);
    }
}

int main(int argc, char *argv[])
{   
    int fd_src, fd_dst, ret, len, i, n;
    char *mp_src, *mp_dst, *tmp_srcp, *tmp_dstp;
    pid_t pid;
    struct stat sbuf;

	//1. 程序名, 原始文件, 目标文件, 进程数
    if (argc < 3 || argc > 4) {
        printf("Enter like this please: ./a.out file_src file_dst [process number]\n");
        exit(1);
    } else if (argc == 3) {
        n = 5;                  //鐢ㄦ埛鏈寚瀹�,榛樿鍒涘缓5涓瓙杩涚▼
    } else if (argc == 4) {
        n = atoi(argv[3]);
    }

	//2. 打开文件
    fd_src = open(argv[1], O_RDONLY);
    err_int(fd_src, "open dict.txt err");
    fd_dst = open(argv[2], O_RDWR | O_CREAT | O_TRUNC, 0664);
    err_int(fd_dst, "open dict.cp err");

	//3. 获取原始文件的属性, 并计算拷贝的进程数
    ret = fstat(fd_src, &sbuf);
    err_int(ret, "fstat err");
    len = sbuf.st_size;
    if (len < n)                //鏂囦欢闀垮害灏忎簬杩涚▼涓暟
        n = len;

	//4. set The target File Size
    ret = ftruncate(fd_dst, len);
    err_int(ret, "truncate fd_dst err");

	//5.映射文件至内存;
    mp_src = (char *)mmap(NULL, len, PROT_READ, MAP_SHARED, fd_src, 0);
    err_str(mp_src, "mmap src err");

    mp_dst = (char *)mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd_dst, 0);
    err_str(mp_dst, "mmap dst err");

    tmp_dstp = mp_dst;
    tmp_srcp = mp_src;

	//6. 计算每个进程的读取量
    int bs = len / n;    //每个进程的平均读取数据长度
    int mod = len % bs;  //剩余的数据量

	//7. 创建指定数量的进程
    for (i = 0; i < n; i++) {
        if ((pid = fork()) == 0) {
            break;
        }
    }

	//8. 主进程操作逻辑, 回收所有的子进程
    if (n == i) {               
        for (i = 0; i < n; i++)
            wait(NULL);
    } else if (i == (n-1)){     //最后一个子进程读取最多的数据,平均数据+剩余数据量
        memcpy(tmp_dstp+i*bs, tmp_srcp+i*bs, bs+mod); 
    } else if (i == 0) {        //绗竴涓瓙杩涚▼
        memcpy(tmp_dstp, tmp_srcp, bs); 
    } else {                    //鍏朵粬瀛愯繘绋�
        memcpy(tmp_dstp+i*bs, tmp_srcp+i*bs, bs); 
    }

    munmap(mp_src, len);
    munmap(mp_dst, len);

    return 0;
}
