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
typedef struct {uint32_t version, region, offset, length;} request;
typedef int (*commit_function)(void *);
typedef int (*stage_function)(void *,const void *,uint32_t);
typedef void *(*map_function)(void *,uint32_t);
typedef void *(*address_function)(void *);
typedef uint32_t (*length_function)(void *);
typedef void (*release_function)(void *);

__attribute__((used,noinline)) uint32_t nor_commit_bridge(void *client,uint32_t selector,arguments *args) {
    uint32_t result=0xe00002c2u;
    void *mapping=0;
    if(selector!=7 || !args || args->structure_output_descriptor ||
       args->scalar_input_count || args->scalar_output_count) return result;
    const void *input=args->structure_input;
    uint32_t input_size=args->structure_input_size;
    if(args->structure_input_descriptor) {
        void *descriptor=args->structure_input_descriptor;
        void **table=*(void ***)descriptor;
        map_function map=(map_function)*(void **)((char *)table+0x98);
        if(!map || !(mapping=map(descriptor,0))) return result;
        table=*(void ***)mapping;
        address_function address=(address_function)*(void **)((char *)table+0x38);
        length_function length=(length_function)*(void **)((char *)table+0x40);
        if(!address || !length) goto done;
        input=address(mapping);
        input_size=length(mapping);
    }
    if(!input || input_size<sizeof(request)) goto done;
    const request *r=(const request *)input;
    if(r->region || r->offset || r->length) goto done;
    if(r->version==4 && input_size==sizeof(request) &&
       args->structure_output && args->structure_output_size>=4) {
        *(uint32_t *)args->structure_output=0x43524f4eu;
        args->structure_output_size=4;
        result=0;
        goto done;
    }
    if(r->version!=3 && r->version!=5) goto done;
    if(r->version==3 && input_size!=sizeof(request)) goto done;
    if(r->version==5) {
        uint32_t size=input_size-sizeof(request);
        const uint32_t *image=(const uint32_t *)((const char *)r+sizeof(request));
        if(size<512 || size>0x2ee00 || (size&63) || image[0]!=0x496d6733u ||
           image[1]!=size || image[4]!=0x696c6c62u ||
           image[2]>size-20 || image[3]>image[2]) goto done;
    }
    void *provider=*(void **)((char *)client+0x7c);
    if(!provider || !*(uint8_t *)((char *)provider+0x58)) {
        result=0xe00002d8u;goto done;
    }
    void *nand=*(void **)((char *)provider+0x5c);
    if(!nand) { result=0xe00002d8u;goto done; }
    void **vtable=*(void ***)nand;
    if(r->version==5) {
        stage_function stage=(stage_function)*(void **)((char *)vtable+0x380);
        const void *image=(const char *)r+sizeof(request);
        uint32_t size=input_size-sizeof(request);
        if(!stage) { result=0xe00002d8u;goto done; }
        result=stage(nand,image,size)==1 ? 0:0xe00002bcu;
        goto done;
    }
    commit_function commit=(commit_function)*(void **)((char *)vtable+0x384);
    if(!commit) { result=0xe00002d8u;goto done; }
    result=(uint32_t)commit(nand);
done:
    if(mapping) {
        void **table=*(void ***)mapping;
        release_function release=(release_function)*(void **)((char *)table+0x14);
        if(release) release(mapping);
    }
    return result;
}
