#include <stdio.h>
#include <stdlib.h>

int main(){    
    int f = 986;
    while (f != 1){
        printf("%d\n", f);
        if ((f & 1) == 1){
            f *= 3;
            f += 1;
        }
        else{
            f /= 2;
        }
    }
    
    return f;
}
