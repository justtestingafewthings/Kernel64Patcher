#include <stdint.h>
#include <stddef.h>
typedef struct {
    uint32_t version, selector, async_wake_port, async_reference, async_reference_count;
    const uint64_t *scalar_input; uint32_t scalar_input_count;
    const void *structure_input; uint32_t structure_input_size;
    void *structure_input_descriptor;
    uint64_t *scalar_output; uint32_t scalar_output_count;
    void *structure_output; uint32_t structure_output_size;
    void *structure_output_descriptor; uint32_t structure_output_descriptor_size;
} arguments;
typedef struct {uint32_t version,region,offset,length;} request;
typedef uint32_t (*size_function)(void *,uint32_t);
typedef int (*read_function)(void *,uint32_t,void *,uint32_t,uint32_t);
typedef int (*write_function)(void *,uint32_t,const void *,uint32_t,uint32_t);
typedef int (*prepare_function)(void *);
#ifdef NOR_PHYSICAL_2107
typedef struct {
    uint32_t version,region,offset,length;
    unsigned char data[4096];
} physical_write_request;
typedef void *(*map_function)(void *,uint32_t);
typedef void *(*address_function)(void *);
typedef uint32_t (*length_function)(void *);
typedef void (*release_function)(void *);
#endif
__attribute__((used,noinline)) uint32_t nor_read_bridge(void *client,uint32_t selector,arguments *args) {
#ifdef NOR_PHYSICAL_2107
    int physical_write=selector==6 && args && args->structure_input_descriptor;
    if(!physical_write && ((selector!=4 && selector!=6) || !args || !args->structure_input ||
       args->structure_input_descriptor || args->structure_input_size<sizeof(request)))
#else
    if((selector!=4 && selector!=6) || !args || !args->structure_input ||
       args->structure_input_descriptor || args->structure_input_size<sizeof(request))
#endif
        return 0xe00002c2u;
#ifdef NOR_PHYSICAL_2107
    const request *r=physical_write ? NULL : (const request *)args->structure_input;
    if(!physical_write && (r->version!=1 || r->region>1)) return 0xe00002c2u;
    if(!physical_write) {
#else
    const request *r=(const request *)args->structure_input;
    if(r->version!=1 || r->region>1) return 0xe00002c2u;
#endif
    if(selector==4) {
        if(args->structure_input_size!=sizeof(request) || !args->structure_output ||
           args->structure_output_descriptor || r->length>4096 ||
           (r->length ? r->length : 4)>args->structure_output_size)
            return 0xe00002c2u;
    } else if(r->length==0 || r->length>1024 ||
              args->structure_input_size!=sizeof(request)+r->length ||
              args->structure_output_size || args->structure_output_descriptor) {
        return 0xe00002c2u;
    }
#ifdef NOR_PHYSICAL_2107
    }
#endif
    void *provider=*(void **)((char *)client+0x7c);
    if(!provider) return 0xe00002d8u;
    if(*(uint8_t *)((char *)provider+0x58)) {
        void *nand=*(void **)((char *)provider+0x5c);
        if(!nand) return 0xe00002d8u;
        void **vtable=*(void ***)nand;
        prepare_function prepare=(prepare_function)*(void **)((char *)vtable+0x10203040u);
        int prepared=prepare(nand);
        if(prepared) return (uint32_t)prepared;
    }
    uintptr_t anchor;
    __asm__ volatile("mov %0, pc" : "=r"(anchor));
    size_function size=(size_function)(anchor+0x13579bdfu);
    read_function read=(read_function)(anchor+0x2468ace1u);
#ifdef NOR_PHYSICAL_2107
    if(physical_write) {
        if(args->scalar_input_count || args->scalar_output_count ||
           args->structure_output_size || args->structure_output_descriptor ||
           !*(uint8_t *)((char *)provider+0x50) ||
           *(uint8_t *)((char *)provider+0x58)) return 0xe00002c2u;
        void *descriptor=args->structure_input_descriptor;
        void **table=*(void ***)descriptor;
        map_function map=(map_function)*(void **)((char *)table+0x98);
        if(!map) return 0xe00002c2u;
        void *mapping=map(descriptor,0);
        if(!mapping) return 0xe00002c2u;
        table=*(void ***)mapping;
        address_function address=(address_function)*(void **)((char *)table+0x38);
        length_function length=(length_function)*(void **)((char *)table+0x40);
        const physical_write_request *w=address && length &&
            length(mapping)==sizeof(physical_write_request) ?
            (const physical_write_request *)address(mapping):NULL;
        uint32_t result=0xe00002c2u;
        if(w && w->version==2 && w->region==0 && w->length==4096 &&
           !(w->offset&4095u)) {
            uintptr_t size_anchor;
            __asm__ volatile("mov %0, pc" : "=r"(size_anchor));
            size_function physical_size=(size_function)(size_anchor+0x55667788u);
            uint32_t total=physical_size(provider,0);
            if(w->offset<=total && w->length<=total-w->offset) {
                uintptr_t write_anchor;
                __asm__ volatile("mov %0, pc" : "=r"(write_anchor));
                uintptr_t write_address=write_anchor+0xdec0addeu;
                write_function write=(write_function)write_address;
                result=(uint32_t)write(provider,0,w->data,w->length,w->offset);
            }
        }
        table=*(void ***)mapping;
        release_function release=(release_function)*(void **)((char *)table+0x14);
        if(release) release(mapping);
        return result;
    }
#endif
    uint32_t total=size(provider,r->region);
    if(selector==4 && !r->length) { *(uint32_t *)args->structure_output=total; args->structure_output_size=4; return 0; }
    if(r->offset>total || r->length>total-r->offset) return 0xe00002c2u;
    if(selector==6) {
#ifdef NOR_PHYSICAL_2107
        return 0xe00002c2u;
#else
        if(!*(uint8_t *)((char *)provider+0x58)) return 0xe00002c2u;
        uintptr_t write_address=anchor+0xdec0addeu;
        if(!write_address) return 0xe00002c2u;
        write_function write=(write_function)write_address;
        return (uint32_t)write(provider,r->region,(const char *)args->structure_input+sizeof(request),
                               r->length,r->offset);
#endif
    }
    int status=read(provider,r->region,args->structure_output,r->length,r->offset);
    if(status) return (uint32_t)status;
    args->structure_output_size=r->length;
    return 0;
}
