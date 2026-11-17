#include <stdio.h>

int sum6(int a, int b, int c, int d, int e, int f) {
    return a + b + c + d + e + f;
}

int main(int argc, char **argv) {
    int s = sum6(1, 2, 3, 4, 5, 6);
    if (s > 10)
        puts("big");
    else
        puts("small");
    printf("%d\n", s);
    return 0;
}
