/* Compile with -ffixed-r9: iOS kernel calls may clobber r9. */
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
typedef int (*host_read)(void *,uint32_t,uint32_t,void *,uint8_t *);
typedef void *(*aligned_alloc)(uint32_t,uint32_t);
typedef void (*aligned_free)(void *,uint32_t);
__attribute__((used,noinline)) uint32_t nor_bootblock_bridge(void *client,uint32_t selector,arguments *args) {
    if(selector!=5 || !args || !args->structure_input || args->structure_input_size!=sizeof(request) ||
       args->structure_input_descriptor || !args->structure_output || args->structure_output_descriptor)
        return 0xe00002c2u;
    const request *r=(const request *)args->structure_input;
    uint32_t bank=r->offset>>16, page=r->offset&0xffffu;
    if(r->version!=2 || r->region!=2 || page>=256 || r->length!=1536 ||
       r->length>args->structure_output_size) return 0xe00002c2u;
    void *access=*(void **)((char *)client+0x7c);
    if(!access || !*(uint8_t *)((char *)access+0x58)) return 0xe00002d8u;
    void *nand=*(void **)((char *)access+0x5c);
    if(!nand) return 0xe00002d8u;
    void *partition=*(void **)((char *)nand+0x50);
    if(!partition || *(uint32_t *)((char *)partition+0x70)!=3) return 0xe00002d8u;
    void *scheme=*(void **)((char *)partition+0x58);
    if(!scheme) return 0xe00002d8u;
    uintptr_t anchor;
    __asm__ volatile("mov %0, pc" : "=r"(anchor));
    aligned_alloc allocate=(aligned_alloc)(anchor+0x13579bdfu);
    aligned_free release=(aligned_free)(anchor+0x31415926u);
    void *buffer=allocate(r->length,16);
    if(!buffer) return 0xe00002bdu;
    void *backend=*(void **)((char *)scheme+0x374);
    if(!backend) { release(buffer,r->length); return 0xe00002d8u; }
    void **device=*(void ***)((char *)backend+0x44);
    if(!device || !device[0] || bank>=*(uint32_t *)((char *)device+8)) {
        release(buffer,r->length); return 0xe00002d8u;
    }
    host_read read=(host_read)device[0xb8];
    if(!read) { release(buffer,r->length); return 0xe00002d8u; }
    uint8_t status=0;
    int ok=read(device[0],bank,page,buffer,&status);
    int result=!ok ? 0xe00002bcu : status ? 0xe00002e5u : 0;
    if(!result) {
        volatile uint8_t *source=(volatile uint8_t *)buffer;
        volatile uint8_t *destination=(volatile uint8_t *)args->structure_output;
        for(uint32_t i=0;i<r->length;i++) destination[i]=source[i];
    }
    release(buffer,r->length);
    if(result) return (uint32_t)result;
    args->structure_output_size=r->length;
    return 0;
}
