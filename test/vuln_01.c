/* This program has a buffer overflow vulnerability. */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Set BUF_SIZE as described in the lab document.
#ifndef BUF_SIZE
#define BUF_SIZE 104
#endif

int bof(char *str)
{
    char buffer[BUF_SIZE];
    /* The following statement has a buffer overflow problem */
    strcpy(buffer, str);
    return 1;
}

int main(int argc, char **argv)
{
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
