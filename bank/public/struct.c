typedef struct acc{
    char name[0x50];
    char balance[8]; // 0x50
    char segment[8]; // 0x58
    char product_name[0x8]; // 0x60
    char rate[8]; // 0x68
    long long loan; // 0x70
    char opened[8];
    char last_act[8];
    char pad2[0x10];

    char time[0x10];
} acc;