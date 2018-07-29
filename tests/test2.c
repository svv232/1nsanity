#include <stdio.h>
#include <stdlib.h>

int main(){    
    int num = 0;
    if (num == 0){
        num = 5;
    }
    printf("%d\n",num);

    int arr[] = {1,2,3,4,5,6,7,8,9};
    int total = 0;
    for (int i = 0; i < (sizeof(arr)/ sizeof(int)); ++i){
        total += arr[i];
    }
    printf("%d\n", total);
    
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

    int num2 = 1;
	int num3 = 0;
	  while(1) {
		switch(num3) {
		  case 0:
			if(num2 == 0)
			  num2 = 1;
			else
			  num3 = 2;
			break;
		  case 1:
            printf("%d %d\n", a,b);
			return 1;
		  case 2:
            printf("%d %d\n", a,b);
			return 10;
		  default:
			break;
		}
	  }

    int f = 986;
    while (f != 1){
        printf("%d\n", c);
        if ((f & 1) == 1){
            f *= 3;
            f += 1;
        }
        else{
            f /= 2;
        }
    }
    
    return c;
}
