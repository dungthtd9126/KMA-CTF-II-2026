typedef struct source{
    char enabled[8];
    char name[0x10];
    char path[0x40];
} source;