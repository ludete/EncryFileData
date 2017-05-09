#include <stdio.h>  
#include <stdlib.h>  
  
int main(int argc, char* argv[])  
{  
      
#ifdef DEBUG  
    printf("gcc -D test\n");  
#endif  
  
    return 0;  
} 

