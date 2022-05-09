#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef BUF_SIZE
#define BUF_SIZE 106
#endif

int bof(char *str) {
    char buffer[BUF_SIZE];
    printf("test\n");
    strcpy(buffer, str);
    return 1;
}

int main(int argc, char **argv) {
    char str[517];
    FILE *badfile;
    char dummy[BUF_SIZE];
    memset(dummy, 0, BUF_SIZE);
    badfile = fopen("benign_payload", "r");
    fread(str, sizeof(char), 517, badfile);
    bof(str);
    printf("Returned Properly\n");
    return 1;
}
