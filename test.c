#include <stdio.h>

int main(){
    int a, b, c, d, e;
    a = 17;
    b = 3;
    c = a + b;
    d = c * 2;
    printf("%d \n",d);
    e = d ^ c;
    printf("%d \n",e);
    a = 56;
    b = a | e;
    printf("%d \n",b);
    c = b & a;
    printf("%d \n",c);
    d = c - 25;
    printf("%d \n",d);
    return 0;
}
