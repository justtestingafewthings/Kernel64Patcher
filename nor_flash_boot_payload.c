/* Read one NAND Boot Block page through IOFlashController on XNU 2107.
 * Build as Thumb code with -ffixed-r9; the runtime kernel uses r9. */
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t version,selector,async_wake_port,async_reference,async_reference_count;
    const uint64_t *scalar_input; uint32_t scalar_input_count;
    const void *structure_input; uint32_t structure_input_size;
    void *structure_input_descriptor;
    uint64_t *scalar_output; uint32_t scalar_output_count;
    void *structure_output; uint32_t structure_output_size;
    void *structure_output_descriptor; uint32_t structure_output_descriptor_size;
} arguments;
typedef struct {uint32_t version,region,offset,length;} request;
typedef struct {
    uint32_t command,options,page_count,field_c;
    uint32_t *pages;
    void *descriptor;
    uint32_t field_18,field_1c,field_20;
    uint32_t *banks;
    void *spare;
    uint32_t spare_size,field_30,field_34,field_38,corrected,field_40,field_44,field_48,field_4c;
} flash_command;
typedef void *(*memory_descriptor)(void *,uint32_t,uint32_t);
typedef void *(*aligned_alloc)(uint32_t,uint32_t);
typedef void (*aligned_free)(void *,uint32_t);
typedef uint32_t (*execute_command)(void *,uint32_t,flash_command *);
typedef void (*release_descriptor)(void *);

__attribute__((used,noinline)) uint32_t nor_flash_boot_bridge(void *client,uint32_t selector,arguments *args) {
    if(selector!=11 || !args || !args->structure_input || args->structure_input_size!=sizeof(request) ||
       args->structure_input_descriptor || !args->structure_output || args->structure_output_descriptor ||
       args->structure_output_size<1536) return 0xe00002c2u;
    const request *r=(const request *)args->structure_input;
    if(r->version!=2 || r->region!=2 || r->offset>=128 || r->length!=1536) return 0xe00002c2u;
    void *controller=*(void **)((char *)client+0x78);
    if(!controller) return 0xe00002d8u;
    uintptr_t anchor;
    __asm__ volatile("mov %0, pc" : "=r"(anchor));
    memory_descriptor wrap=(memory_descriptor)(anchor+0x13579bdfu);
    aligned_alloc allocate=(aligned_alloc)(anchor+0x31415926u);
    aligned_free free_aligned=(aligned_free)(anchor+0x2468ace1u);
    void *buffer=allocate(8192,16);
    if(!buffer) return 0xe00002bdu;
    void *descriptor=wrap(buffer,8192,1);
    if(!descriptor) { free_aligned(buffer,8192);return 0xe00002bdu; }
    uint32_t ce=0,page=r->offset;
    flash_command command;
    volatile uint32_t *words=(volatile uint32_t *)&command;
    for(unsigned i=0;i<sizeof(command)/sizeof(uint32_t);i++) words[i]=0;
    command.command=9;
    command.options=1;
    command.page_count=1;
    command.pages=&page;
    command.descriptor=descriptor;
    command.banks=&ce;
    void **vtable=*(void ***)controller;
    execute_command execute=(execute_command)*(void **)((char *)vtable+0x34c);
    uint32_t result=execute(controller,0,&command);
    void **descriptor_vtable=*(void ***)descriptor;
    release_descriptor release=(release_descriptor)*(void **)((char *)descriptor_vtable+20);
    release(descriptor);
    if(!result) {
        volatile uint8_t *source=(volatile uint8_t *)buffer;
        volatile uint8_t *destination=(volatile uint8_t *)args->structure_output;
        for(uint32_t i=0;i<1536;i++) destination[i]=source[i];
    }
    free_aligned(buffer,8192);
    if(result) return result;
    args->structure_output_size=1536;
    return 0;
}
