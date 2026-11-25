/* NVRAM table discovery shared by the ARM and ARM64 finders. */
#ifndef KP_NVRAM_H
#define KP_NVRAM_H
struct nv_map { size_t off, size; uint64_t address; int data; };
struct nv_image {
    unsigned char *buf;
    size_t len, pointer_size, map_count;
    struct nv_map maps[1024];
};
struct nv_table { size_t start, end, stride, count; int bits; };
static uint64_t nv_u64(const unsigned char *p) {
    return (uint64_t)read_le32(p) | (uint64_t)read_le32(p+4)<<32;
}
static uint64_t nv_va(const struct nv_image *im,size_t off) {
    for(size_t i=0;i<im->map_count;i++) {
        const struct nv_map *m=&im->maps[i];
        if(off>=m->off && off-m->off<m->size) return m->address+off-m->off;
    }
    return UINT64_MAX;
}
static size_t nv_off(const struct nv_image *im,uint64_t va) {
    for(size_t i=0;i<im->map_count;i++) {
        const struct nv_map *m=&im->maps[i];
        if(va>=m->address && va-m->address<m->size) return m->off+(size_t)(va-m->address);
    }
    return SIZE_MAX;
}
static int nv_data(const struct nv_image *im,size_t off,size_t size) {
    if(off>im->len || size>im->len-off) return 0;
    for(size_t i=0;i<im->map_count;i++) {
        const struct nv_map *m=&im->maps[i];
        if(m->data && off>=m->off && off-m->off<m->size && size<=m->size-(off-m->off)) return 1;
    }
    return 0;
}
static uint64_t nv_raw_pointer(const struct nv_image *im,size_t p) {
    return im->pointer_size==8?nv_u64(im->buf+p):read_le32(im->buf+p);
}
static size_t nv_pointer(const struct nv_image *im,uint64_t ptr) {
    if(!ptr) return SIZE_MAX;
    size_t found=nv_off(im,ptr);
    if(found!=SIZE_MAX || im->pointer_size!=8) return found;
    found=nv_off(im,(ptr&UINT64_C(0xffffffffffff))|UINT64_C(0xffff000000000000));
    if(found!=SIZE_MAX) return found;
    uint64_t base=nv_va(im,0);
    if(base==UINT64_MAX || (uint32_t)ptr>UINT64_MAX-base) return SIZE_MAX;
    found=nv_off(im,base+(uint32_t)ptr);
    return found;
}
static const char *nv_name(const struct nv_image *im,size_t p) {
    if(p>im->len || im->pointer_size>im->len-p) return NULL;
    size_t s=nv_pointer(im,nv_raw_pointer(im,p));
    if(s==SIZE_MAX || s>=im->len) return NULL;
    for(size_t n=0;n<128 && n<im->len-s;n++) {
        unsigned char ch=im->buf[s+n];
        if(!ch) return n?(const char *)im->buf+s:NULL;
        if(ch<33 || ch>126 || nv_va(im,s+n)==UINT64_MAX) return NULL;
    }
    return NULL;
}
static int nv_validate(const struct nv_image *im,size_t start,size_t stride,int bits,struct nv_table *out) {
    static const char *legacy[]={"little-endian?","real-mode?","auto-boot?"};
    static const char *modern[]={"aapl,pci","battery-health","boot-image"};
    size_t n;
    for(n=0;n<128;n++) {
        size_t p=start+n*stride;
        if(!nv_data(im,p,stride)) return 0;
        const char *name=nv_name(im,p);
        size_t field=p+im->pointer_size;
        if(!nv_raw_pointer(im,p)) {
            if(n<8) return 0;
            if(bits) {
                if(nv_u64(im->buf+field)!=64 || (stride==24 && nv_u64(im->buf+field+8))) return 0;
            } else if(read_le32(im->buf+field)!=4 || read_le32(im->buf+field+4)!=1 ||
                      read_le32(im->buf+field+8)!=UINT32_MAX) return 0;
            *out=(struct nv_table){start,p,stride,n,bits};return 1;
        }
        if(!name || (n<3 && strcmp(name,(bits?modern:legacy)[n]))) return 0;
        if(bits) {
            uint64_t perm=nv_u64(im->buf+field);
            if(!perm || (perm&~UINT64_C(1023)) || (stride==24 && nv_u64(im->buf+field+8))) return 0;
            if(n==0 && perm!=2) return 0;
        } else {
            uint32_t type=read_le32(im->buf+field),perm=read_le32(im->buf+field+4);
            uint32_t ofoff=read_le32(im->buf+field+8);
            if(type<1 || type>4 || perm>3 || (ofoff!=UINT32_MAX && ofoff>64)) return 0;
            if(n<3 && (type!=1 || perm!=1 || ofoff!=n)) return 0;
        }
        /* A duplicate name indicates a false table or corrupt metadata. */
        for(size_t j=0;j<n;j++) if(!strcmp(name,nv_name(im,start+j*stride))) return 0;
    }
    return 0;
}
static int nv_find(const struct nv_image *im,int bits,struct nv_table *out) {
    const char *anchor=bits?"aapl,pci":"little-endian?";
    size_t found=0;
    for(size_t i=0;i<im->map_count;i++) {
        const struct nv_map *m=&im->maps[i];
        if(!m->data) continue;
        size_t end=m->off+m->size;
        for(size_t p=(m->off+im->pointer_size-1)&~(im->pointer_size-1);p<end && end-p>=im->pointer_size;p+=im->pointer_size) {
            const char *name=nv_name(im,p);
            if(!name || strcmp(name,anchor)) continue;
            size_t first=bits?16:(im->pointer_size+12+im->pointer_size-1)&~(im->pointer_size-1);
            size_t last=bits?24:first;
            for(size_t stride=first;stride<=last;stride+=8) {
                struct nv_table t;
                if(!nv_validate(im,p,stride,bits,&t)) continue;
                if(found && (out->start!=t.start || out->stride!=t.stride)) return -1;
                *out=t;found=1;
            }
        }
    }
    if(!found) fprintf(stderr,"Cannot validate a unique NVRAM variable table.\n");
    return found?0:-1;
}
static int nv_legacy(struct nv_image *im,const struct nv_table *t) {
    static const unsigned char user_write[4]={2,0,0,0};
    size_t protected=0,known=0;
    for(size_t i=0;i<t->count;i++) {
        size_t p=t->start+i*t->stride,field=p+im->pointer_size+4;
        const char *name=nv_name(im,p);
        uint32_t perm=read_le32(im->buf+field);
        if(perm==3) {
            if(kp_add(field,nv_va(im,field),user_write,4,"NVRAM KernelOnly to UserWrite",1)) return -1;
            protected++;
        } else if(perm==2 && (!strcmp(name,"com.apple.System.fp-state") ||
                  !strcmp(name,"com.apple.System.sep.art") || !strcmp(name,"com.apple.System.boot-nonce"))) known++;
    }
    if(!protected) {
        if(known) {
            kp.results[kp.active].status=KP_ALREADY;
            kp.results[kp.active].reason="NVRAM KernelOnly entries already permit user writes";
        } else kp_absent("Validated NVRAM table has no KernelOnly entries");
    }
    return 0;
}
#endif
