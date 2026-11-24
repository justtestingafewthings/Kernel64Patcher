/* ARM-state NOR access for early IMG3 user clients. NOR_MODE selects the
 * provider interface verified in that XNU generation. Modes 1, 3, and 5
 * expose bounded physical writes without an Image3 layout rewrite. This source
 * is compiled to the byte arrays in nor_read_arm_payload.h. */
#include <stdint.h>
#include <stddef.h>

#ifndef NOR_MODE
#error NOR_MODE must be selected
#endif
#if NOR_MODE == 0
#define PHYSICAL_SIZE_SLOT 0x358
#define PHYSICAL_READ_SLOT 0x35c
#elif NOR_MODE == 1
#define PHYSICAL_SIZE_SLOT 0x354
#define PHYSICAL_READ_SLOT 0x358
#define NAND_SIZE_SLOT 0x378
#define NAND_READ_SLOT 0x37c
#elif NOR_MODE == 2
#define PHYSICAL_SIZE_SLOT 0x354
#define PHYSICAL_READ_SLOT 0x358
#define NAND_SIZE_SLOT 0x37c
#define NAND_READ_SLOT 0x380
#elif NOR_MODE == 5
#define PHYSICAL_SIZE_SLOT 0x354
#define PHYSICAL_READ_SLOT 0x358
#define NAND_SIZE_SLOT 0x37c
#define NAND_READ_SLOT 0x380
#elif NOR_MODE == 3
#define PHYSICAL_SIZE_SLOT 0x354
#define PHYSICAL_READ_SLOT 0x358
#define NAND_SIZE_SLOT 0x378
#define NAND_READ_SLOT 0x37c
#else
#error Unsupported NOR_MODE
#endif

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
#if NOR_MODE == 1 || NOR_MODE == 3 || NOR_MODE == 5
typedef struct {
    uint32_t version,region,offset,length;
    unsigned char data[4096];
} physical_write_request;
#define PHYSICAL_WRITE_SLOT 0x35c
#if NOR_MODE == 3 || NOR_MODE == 5
#define DESCRIPTOR_MAP_SLOT 0xac
#else
#define DESCRIPTOR_MAP_SLOT 0xa8
#endif
typedef void *(*map_function)(void *,uint32_t);
typedef void *(*address_function)(void *);
typedef uint32_t (*length_function)(void *);
typedef void (*release_function)(void *);
#endif
typedef uint32_t (*size_function)(void *,uint32_t);
typedef int (*read_function)(void *,uint32_t,void *,uint32_t,uint32_t);

__attribute__((used,noinline)) uint32_t nor_read_arm(void *client,uint32_t selector,arguments *args) {
#if NOR_MODE == 1 || NOR_MODE == 3 || NOR_MODE == 5
    if(selector==6u) {
        if(!args || args->scalar_input_count || args->scalar_output_count)
            return 0xe00002c2u;
        uint32_t result=0xe00002c2u;
        void *mapping=NULL;
        const void *input=args->structure_input;
        uint32_t input_size=args->structure_input_size;
        if(args->structure_input_descriptor) {
            void *descriptor=args->structure_input_descriptor;
            void **table=*(void ***)descriptor;
            map_function map=(map_function)*(void **)((char *)table+DESCRIPTOR_MAP_SLOT);
            if(!map || !(mapping=map(descriptor,0))) return 0xe00002c2u;
            table=*(void ***)mapping;
            address_function address=(address_function)*(void **)((char *)table+0x4c);
            length_function length=(length_function)*(void **)((char *)table+0x54);
            if(!address || !length) goto write_done;
            input=address(mapping);
            input_size=length(mapping);
        }
        if(!input || input_size!=sizeof(physical_write_request)) goto write_done;
        const physical_write_request *w=(const physical_write_request *)input;
        if(w->version!=2 || w->region!=0 || w->length!=4096 ||
           (w->offset&4095u)) goto write_done;
        void *access=*(void **)((char *)client+0x7c);
        if(!access || !*(uint8_t *)((char *)access+0x50)) {
            result=0xe00002d8u;goto write_done;
        }
        void *provider=*(void **)((char *)access+0x54);
        if(!provider) { result=0xe00002d8u;goto write_done; }
        void **vtable=*(void ***)provider;
        size_function size=(size_function)*(void **)((char *)vtable+PHYSICAL_SIZE_SLOT);
        uint32_t total=size(provider,0);
        if(w->offset>total || w->length>total-w->offset) goto write_done;
        read_function write=(read_function)*(void **)((char *)vtable+PHYSICAL_WRITE_SLOT);
        result=(uint32_t)write(provider,0,(void *)w->data,w->length,w->offset);
write_done:
        if(mapping) {
            void **table=*(void ***)mapping;
            release_function release=(release_function)*(void **)((char *)table+0x14);
            if(release) release(mapping);
        }
        return result;
    }
#endif
    if(selector!=4u || !args || !args->structure_input ||
       args->structure_input_size!=sizeof(request) ||
       args->structure_input_descriptor || !args->structure_output || args->structure_output_descriptor)
        return 0xe00002c2u;
    const request *r=(const request *)args->structure_input;
    if(r->version!=1 || r->region>1 || r->length>(NOR_MODE==3 ? 256u:4096u) ||
       (r->length ? r->length : 4)>args->structure_output_size) return 0xe00002c2u;
    void *access=*(void **)((char *)client+0x7c);
    if(!access) return 0xe00002d8u;
    void *provider=NULL;
    uint32_t size_slot=PHYSICAL_SIZE_SLOT,read_slot=PHYSICAL_READ_SLOT;
#if NOR_MODE == 0
    provider=*(void **)((char *)access+0x50);
#else
    if(*(uint8_t *)((char *)access+0x50)) provider=*(void **)((char *)access+0x54);
    else if(*(uint8_t *)((char *)access+0x58)) {
        provider=*(void **)((char *)access+0x5c);
        size_slot=NAND_SIZE_SLOT;read_slot=NAND_READ_SLOT;
    }
#endif
    if(!provider) return 0xe00002d8u;
    void **vtable=*(void ***)provider;
    size_function size=(size_function)*(void **)((char *)vtable+size_slot);
    read_function read=(read_function)*(void **)((char *)vtable+read_slot);
    uint32_t total=size(provider,r->region);
    if(!r->length) { *(uint32_t *)args->structure_output=total; args->structure_output_size=4; return 0; }
    if(r->offset>total || r->length>total-r->offset) return 0xe00002c2u;
    int result=read(provider,r->region,args->structure_output,r->length,r->offset);
    if(result) return (uint32_t)result;
    args->structure_output_size=r->length;
    return 0;
}
