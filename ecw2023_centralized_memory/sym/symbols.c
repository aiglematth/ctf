// gcc -w -g -c symbols.c -o symbols.o ; ld -o symbols -T link.ld symbols.o

struct Client {
    char pad[8];
    int client_fd;
} __attribute__((packed));

struct RAMContent {
    short checksum;
    short content_size;
    short aligned_size;
    short pad;
    int id;
    char data[1];
} __attribute__((packed));

struct RAMChunk {
    struct RAM *next;
    struct RAMChunk *prev;
} __attribute__((packed));

struct RAM {
    char should_use_crypto; 
    char unk[7]; 
    struct RAMContent *content; 
    struct RAMChunk chunk;
} __attribute__((packed));

char KEY[16];
char IV[16];
char *RAM_CONTENT;
int RAM_CONTENT_INDEX;
int RAM_ID;
void *LOCK;
struct RAMChunk RAM_INIT_CHUNK;

int (*main)(int argc, char **argv);
void (*accept_clients)(void);
void (*command_0_send_informations)(int client_fd);
void (*command_RAM_available_size)(int client_fd);
void (*command_RAM_decrypt)(int client_fd);
void (*command_RAM_encrypt)(int client_fd);
void (*command_RAM_free)(int client_fd);
void (*command_RAM_free_all)(int client_fd);
void (*command_RAM_malloc)(int client_fd);
void (*command_RAM_unfragment)(int client_fd);
int (*AES_decrypt)(char *in,int size,char *key,char *iv,char *out);
int (*AES_encrypt)(char *in,int size,char *key,char *iv,char *out);
void (*init_mem)(void);
int (*mul_by_0xdeabbeef)(int to_mul);
int (*RAM_available_size)(int *ret);
int (*RAM_decrypt)(struct RAMContent *c,char command,char *out,short *content_size);
int (*RAM_encrypt)(struct RAMContent *c,char command,void *in,short size);
int (*RAM_free)(int id);
int (*RAM_free_all)(void);
int (*RAM_get)(int id,struct RAMContent **content);
int (*RAM_malloc)(short asked_size,int id,char is_aligned);
int (*RAM_unfragment)(void);
int (*RAM_should_use_crypto)(int id,char *should_use_crypto);
void (*send_int)(int client_fd,int from);
int (*treat_client)(struct Client *_client);
void (*treat_client_command)(int client_fd,int command);