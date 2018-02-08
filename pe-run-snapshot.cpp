#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <algorithm>
#include <iostream>
#include <string>
#include <map>
#include <vector>

#include <unicorn/unicorn.h>
// #include <LIEF/PE.hpp>
// using namespace LIEF::PE;

#include <experimental/filesystem>
namespace stdfs = std::experimental::filesystem ;

#include "syscall_win7.h"

#include "pe_socket.h"
#include "package.h"

//////////////////////////////////////////////////////////////////
FILE *log_file = NULL;
#define OUT_LOG (0)
#define OUT_TRACE (1)

#define out_string(TYPE, ...) {                 \
    if (TYPE == OUT_TRACE) {                    \
        if (log_file == NULL)                   \
            printf(__VA_ARGS__);                \
        else                                    \
            printf(__VA_ARGS__);     \
    } else {                                    \
        printf(__VA_ARGS__);                    \
    }                                           \
}                           


#define TEST_EMU(ret,txt) if(ret) { printf("%s fail! errno: 0x%x\n" , txt, ret );  return -1; }


uint8_t* g_guest_space = NULL;

uint64_t g_guest_space_size = (0x80000000);

uint64_t gdt_address = 0xf0000000;

uc_engine* g_uc = NULL;

uint32_t r_cs = 0x73;
uint32_t r_ss = 0x88;
uint32_t r_ds = 0x7b;
uint32_t r_es = 0x7b;
uint32_t r_fs = 0x83;

#pragma pack(push, 1)
struct SegmentDescriptor {
   union {
      struct {   
#if __BYTE_ORDER == __LITTLE_ENDIAN
         unsigned short limit0;
         unsigned short base0;
         unsigned char base1;
         unsigned char type:4;
         unsigned char system:1;      /* S flag */
         unsigned char dpl:2;
         unsigned char present:1;     /* P flag */
         unsigned char limit1:4;
         unsigned char avail:1;
         unsigned char is_64_code:1;  /* L flag */
         unsigned char db:1;          /* DB flag */
         unsigned char granularity:1; /* G flag */
         unsigned char base2;
#else
         unsigned char base2;
         unsigned char granularity:1; /* G flag */
         unsigned char db:1;          /* DB flag */
         unsigned char is_64_code:1;  /* L flag */
         unsigned char avail:1;
         unsigned char limit1:4;
         unsigned char present:1;     /* P flag */
         unsigned char dpl:2;
         unsigned char system:1;      /* S flag */
         unsigned char type:4;
         unsigned char base1;
         unsigned short base0;
         unsigned short limit0;
#endif
      };
      uint64_t desc;
   };
};
#pragma pack(pop)


typedef struct _emu_state_t
{
    uint32_t ebp;
    uint32_t esp;
    uint32_t eip;

    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t eflags;

    uint32_t fs_base;

}emu_state_t;

emu_state_t emu_state{0};

//this represents the content before DR's hook point
#define MAX_HOOK_SIZE (14)
typedef struct{
    uint8_t * target_addr;
    uint8_t buffer[14];
}before_hook_t;

std::vector<before_hook_t> g_before_hook;
/////////////////////////////////


static void init_descriptor(struct SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code)
{
    desc->desc = 0;  //clear the descriptor
    desc->base0 = base & 0xffff;
    desc->base1 = (base >> 16) & 0xff;
    desc->base2 = base >> 24;
    if (limit > 0xfffff) {
        //need Giant granularity
        limit >>= 12;
        desc->granularity = 1;
    }
    desc->limit0 = limit & 0xffff;
    desc->limit1 = limit >> 16;

    //some sane defaults
    desc->dpl = 3;
    desc->present = 1;
    desc->db = 1;   //32 bit
    desc->type = is_code ? 0xb : 3;
    desc->system = 1;  //code or data
}


int init_gdt(uc_engine *uc, uint32_t fs_start_address )
{
    printf("enter init_gdt\n");

    
    struct SegmentDescriptor *gdt = NULL;
    uc_x86_mmr gdtr;
    uc_err err;

    //////
    //fs_start_address = 0x7ffdf000;

    gdt =  (struct SegmentDescriptor*)malloc( 31 *  sizeof( struct SegmentDescriptor));

    

    gdtr.base = gdt_address;
    gdtr.limit = 31*sizeof(struct SegmentDescriptor) -1;

    init_descriptor(&gdt[14], 0, 0xfffff000, 1);  //code segment
    init_descriptor(&gdt[15], 0, 0xfffff000, 0);  //data segment
    init_descriptor(&gdt[16], fs_start_address, 0xfff, 0);  //one page data segment simulate fs
    init_descriptor(&gdt[17], 0, 0xfffff000, 0);  //ring 0 data
    gdt[17].dpl = 0;  //set descriptor privilege level


    printf("jack: after init_descriptor\n");

   err = uc_mem_map(uc, gdt_address, 0x1000, UC_PROT_WRITE | UC_PROT_READ);
   TEST_EMU(err, "uc_mem_map(gdt_address)");

    

    printf("jack: after uc_mem_map(gdt_address)\n");

    err = uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr);
    TEST_EMU(err, "uc_reg_write(UC_X86_REG_GDTR)");

    printf("gdt: %x , gdt end: %x\n", gdt_address, gdt_address + 31 * sizeof(struct SegmentDescriptor));

    err = uc_mem_write(uc, gdt_address, gdt, 31 * sizeof(struct SegmentDescriptor));
    TEST_EMU(err, "uc_mem_write(gdt_address)");

    err = uc_reg_write(uc, UC_X86_REG_SS, &r_ss);
    TEST_EMU(err, "uc_reg_write(UC_X86_REG_SS)");

    err = uc_reg_write(uc, UC_X86_REG_CS, &r_cs);
    TEST_EMU(err, "uc_reg_write(UC_X86_REG_CS)");

    err = uc_reg_write(uc, UC_X86_REG_DS, &r_ds);
    TEST_EMU(err, "uc_reg_write(UC_X86_REG_DS)");

    err = uc_reg_write(uc, UC_X86_REG_ES, &r_es);
    TEST_EMU(err, "uc_reg_write(UC_X86_REG_ES)");

    err = uc_reg_write(uc, UC_X86_REG_FS, &r_fs);
    TEST_EMU(err, "uc_reg_write(UC_X86_REG_FS)");

    free(gdt);

    printf("exit init_gdt\n");

    return 0;

}



int simulator_initialisation(uc_engine* uc) 
{
    uc_err err;

    err = uc_reg_write(uc, UC_X86_REG_EBP, &emu_state.ebp);

    TEST_EMU(err, "uc_reg_write UC_X86_REG_EBP");

    err = uc_reg_write(uc, UC_X86_REG_ESP, &emu_state.esp);

    TEST_EMU(err, "uc_reg_write UC_X86_REG_ESP");

    err = uc_reg_write(uc, UC_X86_REG_EIP, &emu_state.eip);

    TEST_EMU(err, "uc_reg_write UC_X86_REG_EIP");

    err = uc_reg_write(uc, UC_X86_REG_EAX, &emu_state.eax);

    TEST_EMU(err, "uc_reg_write UC_X86_REG_EAX");

    err = uc_reg_write(uc, UC_X86_REG_EBX, &emu_state.ebx);

    TEST_EMU(err, "uc_reg_write UC_X86_REG_EBX");

    err = uc_reg_write(uc, UC_X86_REG_ECX, &emu_state.ecx);

    TEST_EMU(err, "uc_reg_write UC_X86_REG_ECX");

    err = uc_reg_write(uc, UC_X86_REG_EDX, &emu_state.edx);

    TEST_EMU(err, "uc_reg_write UC_X86_REG_EDX");

    err = uc_reg_write(uc, UC_X86_REG_ESI, &emu_state.esi);

    TEST_EMU(err, "uc_reg_write UC_X86_REG_ESI");

    err = uc_reg_write(uc, UC_X86_REG_EDI, &emu_state.edi);

    TEST_EMU(err, "uc_reg_write UC_X86_REG_EDI");

    err = uc_reg_write(uc, UC_X86_REG_EFLAGS, &emu_state.eflags);

    printf("------------------eflags:%x\n", emu_state.eflags);

    TEST_EMU(err, "uc_reg_write UC_X86_REG_EFLAGS");

    int ret = 0;

    ret = init_gdt(uc, emu_state.fs_base);

    if (ret < 0)
        return -1;


    return 0;
}

int load_part(std::string part_path, uint8_t* guest_space, uint64_t guest_space_size)
{
    FILE * pF = NULL;

    size_t ret = 0;

    pF = fopen(part_path.c_str(), "rb");

    if(!pF)
    {
        printf("fopen(%s) fail!\n", part_path.c_str());
        return -1;
    }

    uint32_t buffer_address = 0;

    ret = fread(&buffer_address, 1,  sizeof(buffer_address),  pF);

    if(ret != sizeof(buffer_address))
    {
        printf("fread address fail!\n");
        return -1;
        
    }

    uint32_t buffer_len = 0;

    ret = fread(&buffer_len, 1,  sizeof(buffer_len),  pF);

    if(ret != sizeof(buffer_len))
    {
        printf("fread len fail!\n");
        return -1;
    }

    uint8_t * pTarget = guest_space + buffer_address;

    ret = fread(pTarget, 1, buffer_len, pF);

    if(ret != buffer_len)
    {
        printf("fread content fail!\n");
        return -1;
    }

    fclose(pF);

    

    return 0;
}

int load_state(std::string part_path )
{
    FILE * pF = NULL;

    size_t ret = 0;

    pF = fopen(part_path.c_str(), "rb");

    if(!pF)
    {
        printf("fopen(%s) fail!\n", part_path.c_str());
        return -1;
    }


    ret = fread(&emu_state, 1,  sizeof(emu_state),  pF);

    if(ret != sizeof(emu_state))
    {
        printf("fread address fail!\n");
        return -1;
        
    }

    printf("emu_state:  ebp: %x \
                        esp: %x \
                        eip: %x \
                        eax: %x \
                        ebx: %x \
                        ecx: %x \
                        edx: %x \
                        esi: %x \
                        edi: %x \
                        eflags: %x \
                        fs_base: %x \
                    \n"
                       , emu_state.ebp
                       , emu_state.esp
                       , emu_state.eip
                       , emu_state.eax
                       , emu_state.ebx
                       , emu_state.ecx
                       , emu_state.edx
                       , emu_state.esi
                       , emu_state.edi
                       , emu_state.eflags
                       , emu_state.fs_base);

    fclose(pF);

    return 0;


}

int load_content_before_hook(std::string part_path )
{
    FILE * pF = NULL;

    size_t ret = 0;

    int i = 0;

    pF = fopen(part_path.c_str(), "rb");

    if(!pF)
    {
        printf("fopen(%s) fail!\n", part_path.c_str());
        return -1;
    }

    uint32_t count = 0;

    ret = fread(&count, 1,  sizeof(count),  pF);

    if(ret != sizeof(count))
    {
        printf("fread before hook count fail!\n");
        return -1;
    }

    for (; i< count; i++)
    {
        before_hook_t before_hook = {0};
        
        ret = fread( &before_hook.target_addr, 1, sizeof(uint32_t), pF);

        if(ret != sizeof(uint32_t))
        {
             printf("fread before hook address fail!\n");
            return -1;

        }


        ret = fread( before_hook.buffer, 1, sizeof(before_hook.buffer), pF);

        if(ret != sizeof(before_hook.buffer))
        {
             printf("fread before hook buffer fail!\n");
            return -1;

        }

        g_before_hook.push_back(before_hook);
    }



    fclose(pF);

    return 0;


}

// int load_snapshot(char * snapshot_path, uint8_t* guest_space, uint64_t guest_space_size)
// {
//     std::vector<std::string> filenames ;


//     const stdfs::directory_iterator end{} ;
    

//     for( stdfs::directory_iterator iter{snapshot_path} ; iter != end ; ++iter )
//     {
//         stdfs::path file_path = (*iter);
        
//         if( stdfs::is_regular_file(*iter) && file_path.extension() == ".mem") 
//             filenames.push_back( iter->path().string() ) ;

//         if(stdfs::is_regular_file(*iter) && file_path.extension() == ".rfs")
//         {

//            load_state(iter->path().string() );     
//         }

//         if(stdfs::is_regular_file(*iter) && file_path.extension() == ".rhk")
//         {

//            load_content_before_hook(iter->path().string() );     
//         }

        

//     }

//     std::vector<std::string>::iterator it = filenames.begin();

//     for(; it != filenames.end(); it++)
//     {
//         int ret = 0;
//         ret = load_part(*it, guest_space, guest_space_size);
//         if(ret < 0)
//         {
//             printf("load_part(%s) fail!\n", it->c_str());
//             return -1;
//         }
//     }


//     std::vector<before_hook_t>::iterator it_before = g_before_hook.begin();

//     for(; it_before != g_before_hook.end(); it_before++)
//     {

//         uint8_t * host_address = guest_space + (uint64_t)it_before->target_addr; 

//         printf("dr hook address: %p\n" , it_before->target_addr);

//         memcpy(host_address, it_before->buffer, sizeof(it_before->buffer));

//     }


//     return 0;
// }


#define SERVICE_CALL_ARGS_COUNT_DEFAULT 20

void stack_traceback(uc_engine * uc, uint32_t ebp)
{
    uint32_t ret_address = 0xffffffff;

    printf("         stack trace: ");

    uint32_t ebp_tmp = ebp;

    uint32_t ebp_tmp1 = ebp;

    while(ebp_tmp)
    {
        uint32_t err = 0;

        err = uc_mem_read(uc, ebp_tmp, &ebp_tmp1, sizeof(ebp_tmp1));
        if(err)
            break;

        err = uc_mem_read(uc, ebp_tmp+4, &ret_address, sizeof(ret_address));
        if(err)
            break;

        printf("%x , %x -> \n", ebp_tmp,ret_address);

        ebp_tmp = ebp_tmp1;
    }

    printf("\n");

}

void print_memory_32bit(uc_engine* uc, uint32_t address, uint32_t len)
{

    uint32_t* mem = new uint32_t[len];

    fprintf(log_file, "++++++\n");
    fprintf(log_file, "%x:\n", address);

    uc_mem_read(uc, address, mem, sizeof(uint32_t)*len);

    for(int i = 0; i < len ; i++)
    {
        if(i%4 == 0)
            printf("\n");
        fprintf(log_file, "%x ", mem[i]);
    }

    delete [] mem;

    fprintf(log_file, "\n------\n");
}

void print_string(uc_engine* uc, uint32_t address)
{
    char content[0x100] = {0};

    uc_mem_read(uc, address, content, sizeof(content));

    fprintf(log_file, "%s\n", content);

}


void hook_sysenter(uc_engine *mu, void *user_data)
{
    

    int ret = 0;

    uint32_t esp = 0;
    uint32_t ebp = 0;
    uint32_t eip = 0;
    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;
    uint32_t esi = 0;
    uint32_t edi = 0;
    uint32_t eflags = 0;
    
    fprintf(log_file, "jack: enter hook_sysenter\n");

    uc_reg_read(mu, UC_X86_REG_ESP, &esp);

    uc_reg_read(mu, UC_X86_REG_EIP, &eip);

    uc_reg_read(mu, UC_X86_REG_EBP, &ebp);

    uc_reg_read(mu, UC_X86_REG_EAX, &eax);

    uc_reg_read(mu, UC_X86_REG_EBX, &ebx);

    uc_reg_read(mu, UC_X86_REG_ECX, &ecx);

    uc_reg_read(mu, UC_X86_REG_EDX, &edx);

    uc_reg_read(mu, UC_X86_REG_ESI, &esi);

    uc_reg_read(mu, UC_X86_REG_EDI, &edi);

    uc_reg_read(mu, UC_X86_REG_EFLAGS, &eflags);

    fprintf(log_file, "[hook_sysenter][0x%x]current:eip: 0x%x , esp: 0x%x ebp: 0x%x eax: 0x%x ebx: 0x%x ecx: 0x%x edx: 0x%x esi: 0x%x edi: 0x%x eflags: 0x%x \n", 
    eip, eip, esp , ebp, eax, ebx, ecx, edx , esi, edi, eflags);

    uint32_t stack_content[8] = {0};

    uc_mem_read(mu, esp, stack_content, sizeof(stack_content));

    fprintf(log_file, "            stack_content: %x, %x, %x, %x, %x, %x, %x, %x\n",  
          stack_content[0],
           stack_content[1],
           stack_content[2],
           stack_content[3],
           stack_content[4],
           stack_content[5],
           stack_content[6],
           stack_content[7]
           );


    uint8_t content[8] = {0};

    uc_mem_read(mu, eip, content, 8);

    fprintf(log_file, "            content: %x, %x, %x, %x, %x, %x, %x, %x\n",  
          content[0],
           content[1],
           content[2],
           content[3],
           content[4],
           content[5],
           content[6],
           content[7]
           );
    

    if(content[0] == 0x0 && content[1] == 0x0 && content[2] == 0x0 && content[3] == 0x0)
    {
        uc_emu_stop(mu);
    }

      fprintf(log_file, "sysenter: service id: 0x%x\n", eax);



        ice_syscall_entry_t syscall_entry = {0};


        ret = ice_get_syscall_by_id(eax, &syscall_entry);

        if(ret < 0)
        {
            fprintf(log_file, "sys call doesn't find by id\n");
            uc_emu_stop(mu);
        }

        fprintf(log_file, "sysenter: service name: %s\n", syscall_entry.syscall_name.c_str());

        uint32_t args[SERVICE_CALL_ARGS_COUNT_DEFAULT] ={0};

        uc_mem_read(mu, esp+8, args, sizeof(args) );

        fprintf(log_file, "sysenter args: %x, %x,%x,%x\n", args[0],  args[1], args[2] ,  args[3]);


        ice_syscall(mu, eax, args, SERVICE_CALL_ARGS_COUNT_DEFAULT);


}


int g_show_trace = 1; 

int hook_code(uc_engine* mu)
{
    int ret = 0;

    uint32_t esp = 0;
    uint32_t ebp = 0;
    uint32_t eip = 0;
    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;
    uint32_t esi = 0;
    uint32_t edi = 0;
    uint32_t eflags = 0;
    
    //printf("jack: enter hook_code\n");

    uc_reg_read(mu, UC_X86_REG_ESP, &esp);

    uc_reg_read(mu, UC_X86_REG_EIP, &eip);

    uc_reg_read(mu, UC_X86_REG_EBP, &ebp);

    uc_reg_read(mu, UC_X86_REG_EAX, &eax);

    uc_reg_read(mu, UC_X86_REG_EBX, &ebx);

    uc_reg_read(mu, UC_X86_REG_ECX, &ecx);

    uc_reg_read(mu, UC_X86_REG_EDX, &edx);

    uc_reg_read(mu, UC_X86_REG_ESI, &esi);

    uc_reg_read(mu, UC_X86_REG_EDI, &edi);

    uc_reg_read(mu, UC_X86_REG_EFLAGS, &eflags);

    if(g_show_trace)
    {

        fprintf(log_file, "[0x%x]current:eip: 0x%x , esp: 0x%x ebp: 0x%x eax: 0x%x ebx: 0x%x ecx: 0x%x edx: 0x%x esi: 0x%x edi: 0x%x eflags: 0x%x \n", 
        eip, eip, esp , ebp, eax, ebx, ecx, edx , esi, edi, eflags);
    }

    uint32_t stack_content[8] = {0};

    uc_mem_read(mu, esp, stack_content, sizeof(stack_content));

    if(g_show_trace)
    {
        fprintf(log_file, "            stack_content: %x, %x, %x, %x, %x, %x, %x, %x\n",  
          stack_content[0],
           stack_content[1],
           stack_content[2],
           stack_content[3],
           stack_content[4],
           stack_content[5],
           stack_content[6],
           stack_content[7]
           );
    }

     


    uint8_t content[8] = {0};

    uc_mem_read(mu, eip, content, 8);

    if(g_show_trace)
    {

    fprintf(log_file, "            content: %x, %x, %x, %x, %x, %x, %x, %x\n",  
          content[0],
           content[1],
           content[2],
           content[3],
           content[4],
           content[5],
           content[6],
           content[7]
           );

    }
    

    if(content[0] == 0x0 && content[1] == 0x0 && content[2] == 0x0 && content[3] == 0x0)
    {
        uc_emu_stop(mu);
    }

    

    if(content[0] == 0x0f && content[1] == 0x34)
    { //sysenter

        //uc_emu_stop(mu);
      

    }

    // if(eip == 0x401055)
    // {
    //            uint32_t tmp;
    //     uc_mem_read(mu, esp, &tmp, sizeof(tmp) );

    //     uint8_t tmp_content[8];

    //     uc_mem_read(mu, tmp, &tmp_content, sizeof(tmp_content));

    //    printf("0x%x : %x, %x, %x, %x, %x, %x, %x, %x\n", 
    //        tmp, 
    //       tmp_content[0],
    //        tmp_content[1],
    //        tmp_content[2],
    //        tmp_content[3],
    //        tmp_content[4],
    //        tmp_content[5],
    //        tmp_content[6],
    //        tmp_content[7]
    //        );
        
    // }



    //if(eip == 0x770d760f) 
    if(eip == 0x770d7614)
   // if(eip == 0x770dd055)
    {


       
        
        //  uint32_t tmp;
        //  uc_mem_read(mu, ebp-0x0c, &tmp, sizeof(tmp) );

         
        //  //printf("%x\n", tmp);

        // print_memory_32bit(mu, tmp, 0x10);

        // uc_emu_stop(mu);

    //     uint8_t tmp_content[8];

    //     uc_mem_read(mu, tmp, &tmp_content, sizeof(tmp_content));

    //    printf("0x%x : %x, %x, %x, %x, %x, %x, %x, %x\n", 
    //        tmp, 
    //       tmp_content[0],
    //        tmp_content[1],
    //        tmp_content[2],
    //        tmp_content[3],
    //        tmp_content[4],
    //        tmp_content[5],
    //        tmp_content[6],
    //        tmp_content[7]
    //        );



    }





    if(eip == 0x401017)
    {

        eip = 0x401019;
        uc_reg_write(mu, UC_X86_REG_EIP, &eip);

    }


    
    if(eip == 0x772670b2)
    //if(eip == 0x7727f2f0)
    //if(eip == 0x7727efa9)
    //if(eip == 0x7727ef67)
    {
       // stack_traceback(mu, ebp);

        //uc_emu_stop(mu);


        // //dd ecx
        // print_memory_32bit(mu, ecx, 8);

        // //dd [ecx+0xbc]
        // printf("[+0xbc]\n");
        // uint32_t tmp = 0;
        // uc_mem_read(mu, ecx+0xbc, &tmp, sizeof(tmp));
        // print_memory_32bit(mu, tmp, 8);

        // printf("[+0x18]\n");
        // uc_mem_read(mu, tmp+0x18, &tmp, sizeof(tmp));
        // print_memory_32bit(mu, tmp, 8);


        // printf("[+0x4]\n");
        // uc_mem_read(mu, tmp+0x4, &tmp, sizeof(tmp));
        // print_memory_32bit(mu, tmp, 8);

        // printf("[+0x14]\n");
        // uc_mem_read(mu, tmp+0x14, &tmp, sizeof(tmp));
        // print_memory_32bit(mu, tmp, 8);


        // uc_emu_stop(mu);
    }

    // if(eip == 0x77338b0b)
    // {
    //     uint32_t tmp;
    //     uc_mem_read(mu, esp+0xc, &tmp, sizeof(tmp) );

    //     print_memory_32bit(mu,tmp, 0x2 );

        
    //     uc_mem_read(mu, tmp+4, &tmp, sizeof(tmp) );

    //     print_memory_32bit(mu,tmp, 0x10 );

    //     uc_emu_stop(mu);
    // }

   

    // if(eip == 0x755233e0)
    // {
    //     uint32_t tmp;
    //     uc_mem_read(mu, esp+0x8, &tmp, sizeof(tmp) );

    //     printf("GetProcAddress:");
    //     print_string(mu, tmp);
    //     //uc_emu_stop(mu);

    // }



    // static int sflag1 = 0;

    //  static uint32_t tmp;

    // if(eip == 0x4145a6)
    // {
    //     sflag1 = 1;

        
    //     uc_mem_read(mu, esp+0x4, &tmp, sizeof(tmp) );

    //     printf("%x\n", tmp);


    // }

    if(eip == 0x414e5b)
    {   
            
        
    }


    if(eip == 0x414f15)
    {
         
       
       
    }

    if(eip == 0x4152a9)
    {
        // g_show_trace = 1;

    }

    if (eip == 0x415478)
        printf("HIT\n");    
    
    
    if(eip == 0x41548e)    //for real sample patch point
    {

        
        static int s_once = 0;

        if(!s_once)
        {
            uint32_t tmp =  0x000507e1;
            uc_mem_write(mu, 0x00473348, &tmp, sizeof(tmp));

            uc_mem_write(mu, 0x00473330, &tmp, sizeof(tmp));

            // uc_emu_stop(mu);

            // eip = 0x41548e;
            // uc_reg_write(mu, UC_X86_REG_EIP, &eip);

        }


        s_once = 1;
      

    }


   return 0;
    
}


static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data)
{
    switch(type) {
        default:
            // return false to indicate we want to stop emulation
            return false;
        case UC_MEM_WRITE_UNMAPPED:
                printf("UC_MEM_WRITE_UNMAPPED\n");
        case UC_MEM_READ_UNMAPPED:
                printf("UC_MEM_READ_UNMAPPED\n");
        
        uint32_t eip = 0;

        uc_reg_read(uc, UC_X86_REG_EIP, &eip);

        printf("eip: %x, address: %lx, size: %x, value: %lx\n",
                         eip, address, size, value);
        
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////  unpackage
static int load_cpu_snapshot(cpu_snapshot_t *cpu_snapshot, int body_length)
{
    // ASSERT(body_length == sizeof(cpu_snapshot_t));

    uc_err err;

    // out_string(OUT_LOG, "load cpu snapshot\n");

    // err = uc_reg_write(g_uc, UC_X86_REG_EBP, &cpu_snapshot->ebp);
    // TEST_EMU(err, "uc_reg_write UC_X86_REG_EBP");

    // err = uc_reg_write(g_uc, UC_X86_REG_ESP, &cpu_snapshot->esp);
    // TEST_EMU(err, "uc_reg_write UC_X86_REG_ESP");

    // err = uc_reg_write(g_uc, UC_X86_REG_EIP, &cpu_snapshot->eip);
    // TEST_EMU(err, "uc_reg_write UC_X86_REG_EIP");

    // err = uc_reg_write(g_uc, UC_X86_REG_EAX, &cpu_snapshot->eax);
    // TEST_EMU(err, "uc_reg_write UC_X86_REG_EAX");

    // err = uc_reg_write(g_uc, UC_X86_REG_EBX, &cpu_snapshot->ebx);
    // TEST_EMU(err, "uc_reg_write UC_X86_REG_EBX");

    // err = uc_reg_write(g_uc, UC_X86_REG_ECX, &cpu_snapshot->ecx);
    // TEST_EMU(err, "uc_reg_write UC_X86_REG_ECX");

    // err = uc_reg_write(g_uc, UC_X86_REG_EDX, &cpu_snapshot->edx);
    // TEST_EMU(err, "uc_reg_write UC_X86_REG_EDX");

    // err = uc_reg_write(g_uc, UC_X86_REG_ESI, &cpu_snapshot->esi);
    // TEST_EMU(err, "uc_reg_write UC_X86_REG_ESI");

    // err = uc_reg_write(g_uc, UC_X86_REG_EDI, &cpu_snapshot->edi);
    // TEST_EMU(err, "uc_reg_write UC_X86_REG_EDI");

    // err = uc_reg_write(g_uc, UC_X86_REG_EFLAGS, &cpu_snapshot->eflags);
    // TEST_EMU(err, "uc_reg_write UC_X86_REG_EFLAGS");

    // init_gdt(g_uc, cpu_snapshot->fs_base);
    emu_state.ebp = cpu_snapshot->ebp;
    emu_state.esp = cpu_snapshot->esp;
    emu_state.eip = cpu_snapshot->eip;
    emu_state.eax = cpu_snapshot->eax;
    emu_state.ebx = cpu_snapshot->ebx;
    emu_state.ecx = cpu_snapshot->ecx;
    emu_state.edx = cpu_snapshot->edx;
    emu_state.esi = cpu_snapshot->esi;
    emu_state.edi = cpu_snapshot->edi;
    emu_state.eflags = cpu_snapshot->eflags;
    emu_state.fs_base = cpu_snapshot->fs_base;

    // printf("fs_base : 0x%08x\n", cpu_snapshot->fs_base);

    return 1;
}

static void load_memory_trace(mem_trace_t *mem_trace, int body_length)
{
    // ASSERT(sizeof(char *) + sizeof(int) + mem_trace->length == body_length);
    out_string(OUT_LOG, "load memory trace at 0x%08x\n", mem_trace->address);

    uc_mem_write(g_uc, mem_trace->address, mem_trace->data, mem_trace->length);
}

static void load_snapshot(snapshot_t *snapshot, int body_length)
{
    // ASSERT(sizeof(char *) + sizeof(int) + mem_trace->length == body_length);
    out_string(OUT_LOG, "load snapshot : 0x%08x : 0x%08x\n", snapshot->address, snapshot->length);
    
    uc_mem_write(g_uc, snapshot->address, snapshot->data, snapshot->length);
}

static void fork_emu(int *target_pc, int bodylength)
{
    out_string(OUT_LOG, "fork to 0x%08x\n", *target_pc);

    // if (*target_pc == 0x401037)
        // return;

    if (fork() == 0) {
        char log_file_path[0x100];

        snprintf(log_file_path, 0x100, "./%d_%x.log", getpid(), *target_pc);
        printf("OPEN FILE\n");

        log_file = fopen(log_file_path, "w");
        if (log_file != NULL) {
            emu_state.eip = *target_pc;
            simulator_initialisation(g_uc);


            printf("return error : %d\n", uc_emu_start(g_uc, *target_pc, g_guest_space_size, 0, 0));
            fclose(log_file);
            log_file = NULL;
            exit(0);
        } else {
            out_string(OUT_LOG, "open file error\n");
        }
    }
}

static bool unpackage_internal(package_header *header, char *body)
{
    // printf("unpackage : 0x%08x\n", header->code);

    switch (header->code) {
        case P_MEMORY_TRACE:
            load_memory_trace((mem_trace_t*)body, header->length);
            break;
        case P_SNAPSHOT:
            load_snapshot((snapshot_t *)body, header->length);
            break;
        case P_CPU_SNAPSHOT:
            load_cpu_snapshot((cpu_snapshot_t *)body, header->length);
            break;
        case P_FORK:
            fork_emu((int*)body, header->length);
            return false;
        default:
            // std::cout<<"SHOULD NOT BE HERE"<<std::endl;
            out_string(OUT_LOG, "SHOULD NOT BE HERE\n");
    }
    return true;
}

void unpackage(char *buf)
{
    package_header *header = (package_header *)buf;

    unpackage_internal(header, (char*)(header + 1));
}

static void load_snapshot_from_socket(uc_engine *g_uc, uint8_t *g_guest_space)
{
    package_header header;
    char *buf;

    while (true) {
        recv_buf_by_length((unsigned char *)&header, sizeof(header));
        // printf("header length : 0x%08x\n", header.length);

        if (header.length != 0) {
            buf = (char*)malloc(header.length);
            if (buf == NULL) {
                out_string(OUT_LOG, "Allocate memory error : 0x%08x\n", header.length);
                exit(0);
            }

            recv_buf_by_length((unsigned char *)buf, header.length);
        } else {
            buf = NULL;
        }

        unpackage_internal(&header, buf);

        if (buf != NULL)
            free(buf);
    }
}

static void load_snapshot_file(uc_engine *g_uc, uint8_t *g_guest_space)
{
    // int fd = open("./output", O_RDONLY);
    FILE *file = fopen("./output", "rb");
    struct stat STAT;
    package_header *header;



    if (stat("./output", &STAT) != 0) {
        printf("stat file error\n");
        exit(0);
    }
    printf("file size : 0x%08x\n", STAT.st_size);

    char *buf = (char*)malloc(STAT.st_size);
    // read(fd, buf, STAT.st_size);
    fread(buf, 1, STAT.st_size, file);

    printf("0x%08x : 0x%08x : 0x%08x\n", *(int*)buf, *(int*)(buf+4), *(int*)(buf+8));

    // exit(0);

    char *ptr;
    bool valid;

    valid = true;
    ptr = buf;
    while (ptr < buf + STAT.st_size) {
        header = (package_header *)ptr;
        // printf("header length : 0x%08x\n", header->code);
        // printf("header length : 0x%08x\n", header->length);
        // printf("body 1 : 0x%08x\n", *(int*)(ptr + 8));
        // printf("body 2 : 0x%08x\n", *(int*)(ptr + 12));

        // if (header->length != 0) {
        //     buf = (char*)malloc(header.length);
        //     if (buf == NULL) {
        //         out_string(OUT_LOG, "Allocate memory error : 0x%08x\n", header.length);
        //         exit(0);
        //     }

        //     read(fd, buf, header.length);
        // } else {
        //     buf = NULL;
        // }

        // valid = unpackage_internal(header, ((char*)header) + header->length);
        valid = unpackage_internal(header, ptr + 8);
        ptr = ((char*)header) + sizeof(package_header) + header->length;
        // if (buf != NULL)
        //     free(buf);

        // if(valid == false)
        //      return;
    }
}



int main(int argc, const char** argv)
{
    uc_err err;
    /////////////////////////////////////file//////////////////////////////////////
    #ifdef MYFILE
    if(argc < 2)
    {
        printf("usage pe-run-snapshot <snapshot path>\n");
        return -1;
    }
    #endif
    /////////////////////////////////////file//////////////////////////////////////



    err = uc_open(UC_ARCH_X86, UC_MODE_32, &g_uc);

    TEST_EMU(err, "uc_open");

    ice_syscall_init_win7(g_uc);

    printf("g_mp_syscalls len:%d\n", g_mp_syscalls.size());

	printf("g_mp_syscalls_id len:%d\n", g_mp_syscalls_id.size());



    g_guest_space = (uint8_t*)mmap(NULL, g_guest_space_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

    if(g_guest_space == MAP_FAILED)
    {
        printf("mmap fail!\n");
        exit(0);
    }

    printf("g_guest_space: %p\n", g_guest_space);

    err = uc_mem_map_ptr(g_uc, 0, g_guest_space_size, UC_PROT_ALL, g_guest_space );

    TEST_EMU(err, "uc_mem_map_ptr");

    // load_snapshot((char*)argv[1], g_guest_space, g_guest_space_size);

    // simulator_initialisation(g_uc);
    //init_gdt(g_uc, 0);

    uc_hook hook , hook2, hook3;
    uc_hook_add(g_uc, &hook, UC_HOOK_CODE, (void*)hook_code, NULL, 1, 0);

    uc_hook_add(g_uc, &hook3, UC_HOOK_INSN, (void*)hook_sysenter, NULL, 1, 0, UC_X86_INS_SYSENTER);

    uc_hook_add(g_uc, &hook2, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, 
                (void*)hook_mem_invalid, NULL, 1, 0);

    /////////////////////////////////////socket//////////////////////////////////////
    #ifdef MYSOCKET
    int err_thread;
    pthread_t tid;
    void *tret;
    err_thread = pthread_create(&tid,NULL,pe_recv_buf,NULL);
    load_snapshot_from_socket(g_uc, g_guest_space);
    #endif

    /////////////////////////////////////socket//////////////////////////////////////


    /////////////////////////////////////file//////////////////////////////////////
    #ifdef MYFILE
    load_snapshot_file(g_uc, g_guest_space);
    #endif
    /////////////////////////////////////file//////////////////////////////////////

    // std::cout<<std::hex<< "call uc_emu_start "<< emu_state.eip<<std::endl;

    // if (log_file != NULL) {
    //     fprintf(log_file, "writting files\n");
    //     printf("Starting emu\n");
    //     err = uc_emu_start(g_uc, 
    //     emu_state.eip,
    //     g_guest_space_size,
    //     0,0);
    // }


    munmap(g_guest_space, g_guest_space_size);
    /////////////////////////////////////socket//////////////////////////////////////
    #ifdef MYSOCKET
    pthread_join(tid,&tret);
    #endif
    /////////////////////////////////////socket//////////////////////////////////////


   return 0;

}