/* Bounded Boot Block page read through the iOS 4.3/5 IOFlashPartitionScheme.
 * The client keeps the scheme at +0x7c; the scheme's nandCommand handles
 * the controller command layout and calls the same read used at startup. */
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
typedef void *(*memory_descriptor)(void *,uint32_t,uint32_t);
typedef void *(*aligned_alloc)(uint32_t,uint32_t);
typedef void (*aligned_free)(void *,uint32_t);
typedef void (*release_descriptor)(void *);
typedef uint32_t (*nand_command)(void *,uint32_t,uint32_t,uint32_t,uint32_t,void *,void *);

__attribute__((used,noinline)) uint32_t nor_flash_early_bridge(void *client,uint32_t selector,arguments *args) {
    if(selector!=11 || !args || !args->structure_input || args->structure_input_size!=sizeof(request) ||
       args->structure_input_descriptor || !args->structure_output || args->structure_output_descriptor ||
       !args->structure_output_size) return 0xe00002c2u;
    const request *r=(const request *)args->structure_input;
    uint32_t page=r->offset>>16,slice=r->offset&0xffffu;
    if(r->version!=2 || r->region!=2 || page>=128 || !r->length || r->length>256 ||
       r->length>1536u-slice || r->length>args->structure_output_size)
        return 0xe00002c2u;
    void *scheme=*(void **)((char *)client+0x7c);
    if(!scheme) return 0xe00002d8u;
    uintptr_t anchor;
    __asm__ volatile("mov %0, pc" : "=r"(anchor));
    memory_descriptor wrap=(memory_descriptor)(anchor+0x13579bdfu);
    aligned_alloc allocate=(aligned_alloc)(anchor+0x31415926u);
    aligned_free free_aligned=(aligned_free)(anchor+0x2468ace1u);
    nand_command read_page=(nand_command)(anchor+0x0badc0deu);
    void *buffer=allocate(8192,16);
    if(!buffer) return 0xe00002bdu;
    void *descriptor=wrap(buffer,8192,1);
    if(!descriptor) { free_aligned(buffer,8192);return 0xe00002bdu; }
    uint32_t result=read_page(scheme,0,page,9,1,descriptor,NULL);
    void **descriptor_vtable=*(void ***)descriptor;
    release_descriptor release=(release_descriptor)*(void **)((char *)descriptor_vtable+20);
    release(descriptor);
    if(!result) {
        volatile uint8_t *source=(volatile uint8_t *)buffer;
        volatile uint8_t *destination=(volatile uint8_t *)args->structure_output;
        for(uint32_t i=0;i<r->length;i++) destination[i]=source[slice+i];
    }
    free_aligned(buffer,8192);
    if(result) return result;
    args->structure_output_size=r->length;
    return 0;
}
