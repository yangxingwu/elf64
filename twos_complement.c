#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: %s [input]\n", argv[0]);
        return -1;
    }

    int32_t number = strtol(argv[1], NULL, 16);

    printf("%d: 0x%x\n", number, number);

    return 0;
}
