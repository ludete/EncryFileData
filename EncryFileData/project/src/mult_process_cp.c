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

	//1. ³ÌĞòÃû, Ô­Ê¼ÎÄ¼ş, Ä¿±êÎÄ¼ş, ½ø³ÌÊı
    if (argc < 3 || argc > 4) {
        printf("Enter like this please: ./a.out file_src file_dst [process number]\n");
        exit(1);
    } else if (argc == 3) {
        n = 5;                  //ç”¨æˆ·æœªæŒ‡å®š,é»˜è®¤åˆ›å»º5ä¸ªå­è¿›ç¨‹
    } else if (argc == 4) {
        n = atoi(argv[3]);
    }

	//2. ´ò¿ªÎÄ¼ş
    fd_src = open(argv[1], O_RDONLY);
    err_int(fd_src, "open dict.txt err");
    fd_dst = open(argv[2], O_RDWR | O_CREAT | O_TRUNC, 0664);
    err_int(fd_dst, "open dict.cp err");

	//3. »ñÈ¡Ô­Ê¼ÎÄ¼şµÄÊôĞÔ, ²¢¼ÆËã¿½±´µÄ½ø³ÌÊı
    ret = fstat(fd_src, &sbuf);
    err_int(ret, "fstat err");
    len = sbuf.st_size;
    if (len < n)                //æ–‡ä»¶é•¿åº¦å°äºè¿›ç¨‹ä¸ªæ•°
        n = len;

	//4. set The target File Size
    ret = ftruncate(fd_dst, len);
    err_int(ret, "truncate fd_dst err");

	//5.Ó³ÉäÎÄ¼şÖÁÄÚ´æ;
    mp_src = (char *)mmap(NULL, len, PROT_READ, MAP_SHARED, fd_src, 0);
    err_str(mp_src, "mmap src err");

    mp_dst = (char *)mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd_dst, 0);
    err_str(mp_dst, "mmap dst err");

    tmp_dstp = mp_dst;
    tmp_srcp = mp_src;

	//6. ¼ÆËãÃ¿¸ö½ø³ÌµÄ¶ÁÈ¡Á¿
    int bs = len / n;    //Ã¿¸ö½ø³ÌµÄÆ½¾ù¶ÁÈ¡Êı¾İ³¤¶È
    int mod = len % bs;  //Ê£ÓàµÄÊı¾İÁ¿

	//7. ´´½¨Ö¸¶¨ÊıÁ¿µÄ½ø³Ì
    for (i = 0; i < n; i++) {
        if ((pid = fork()) == 0) {
            break;
        }
    }

	//8. Ö÷½ø³Ì²Ù×÷Âß¼­, »ØÊÕËùÓĞµÄ×Ó½ø³Ì
    if (n == i) {               
        for (i = 0; i < n; i++)
            wait(NULL);
    } else if (i == (n-1)){     //×îºóÒ»¸ö×Ó½ø³Ì¶ÁÈ¡×î¶àµÄÊı¾İ,Æ½¾ùÊı¾İ+Ê£ÓàÊı¾İÁ¿
        memcpy(tmp_dstp+i*bs, tmp_srcp+i*bs, bs+mod); 
    } else if (i == 0) {        //ç¬¬ä¸€ä¸ªå­è¿›ç¨‹
        memcpy(tmp_dstp, tmp_srcp, bs); 
    } else {                    //å…¶ä»–å­è¿›ç¨‹
        memcpy(tmp_dstp+i*bs, tmp_srcp+i*bs, bs); 
    }

    munmap(mp_src, len);
    munmap(mp_dst, len);

    return 0;
}
