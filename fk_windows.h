#ifndef __FK_WINDOWS_H__

#define __FK_WINDOWS_H__

#include <stdint.h>




//
// NtCreateFile Result Flags
//
#define FK_FILE_SUPERSEDED                         0x00000000
#define FK_FILE_OPENED                             0x00000001
#define FK_FILE_CREATED                            0x00000002
#define FK_FILE_OVERWRITTEN                        0x00000003
#define FK_FILE_EXISTS                             0x00000004
#define FK_FILE_DOES_NOT_EXIST                     0x00000005


typedef struct _FK_IO_STATUS_BLOCK
{
    union
    {
        uint32_t Status;
        void* Pointer;
    };

    uint32_t Information;

}FK_IO_STATUS_BLOCK, * PFK_IO_STATUS_BLOCK;




#endif