#include <stdio.h>
#include <unistd.h>


int main() {
    char a[69] = {0};

    scanf("GET /%s", a);
    printf("HTTP 200\r\n\r\n");
    fflush(stdout);
    
    execlp("cat", a, a, 0);

    return 0;
}
