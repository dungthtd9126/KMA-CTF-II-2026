typedef struct mail{
    char id[5];
    char sender[0x30];
    char recipe[0x30];
    char subj[0x60];
    char body[100];
} mail;

typedef struct archive{
    char name[4];
    char inuse;
    char sender_len[2];
    char recipe_len[2];
    char subj_len[2];
    char body_len[2];
    mail mail;

} archive;