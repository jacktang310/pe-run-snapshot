#define SEND_END_OF_PACKAGE send(NULL, -1);

typedef enum{
    P_MEMORY_TRACE,
    P_SNAPSHOT,
    P_CPU_SNAPSHOT,
    P_FORK
}OPCODE;


typedef struct {
    OPCODE code;
    int length;
} package_header;

typedef struct _cpu_snapshot_t
{
    unsigned int ebp;
    unsigned int esp;
    unsigned int eip;

    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;
    unsigned int esi;
    unsigned int edi;
    unsigned int eflags;

    unsigned int fs_base;
}cpu_snapshot_t;

typedef struct {
    int address;
    int length;
    char data[1];
} mem_trace_t;

typedef struct {
    int address;
    int length;
    char data[1];
} snapshot_t;