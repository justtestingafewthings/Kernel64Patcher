/* ARM64 NVRAM permission gate. Keep table flags intact, including krn.* policy. */
static int nv_returns(const struct kd_ctx *c,size_t p,unsigned result) {
    uint32_t aliases=UINT32_C(1)<<result;
    for(unsigned n=0;n<40;n++,p+=4) {
        if(!kd_executable(c,p)) return 0;
        uint32_t w=kd_word(c,p);unsigned rd=w&31,rn=(w>>5)&31;
        if(da_ret(w)) return (aliases&1)!=0;
        if(da_b(w)) { p=kd_branch(c,p);if(p==KD_NONE)return 0;p-=4;continue; }
        if(da_bl(w)) return 0;
        /* Only the not-taken stack-canary failure edge is on this return path. */
        if((w&0xff00001f)==0x54000001 && (kd_word(c,p-4)&0xffe0fc1f)==0xeb00001f) continue;
        if((w&0xffe0ffe0)==0xaa0003e0 || (w&0xffe0ffe0)==0x2a0003e0) {
            unsigned source=(w>>16)&31;
            aliases=(aliases&~(UINT32_C(1)<<rd))|((aliases>>source&1)<<rd);
        } else if((w&0xfffffc00)==0x12000000) {
            aliases=(aliases&~(UINT32_C(1)<<rd))|((aliases>>rn&1)<<rd);
        } else if((w&0xffc00000)==0xa9400000 || (w&0xffc00000)==0xa8c00000) {
            aliases&=~((UINT32_C(1)<<rd)|(UINT32_C(1)<<((w>>10)&31)));
        } else if((w&0xffc00000)==0xf9400000 || (w&0x9f000000)==0x90000000 ||
                  (w&0xff000000)==0x91000000) aliases&=~(UINT32_C(1)<<rd);
        else if((w&0xffe0fc1f)!=0xeb00001f) return 0;
    }
    return 0;
}
static int nv_modern(struct kd_ctx *c,const struct nv_table *t) {
    size_t selected=KD_NONE;unsigned selected_reg=0;
    for(size_t i=0;i<c->region_count;i++) {
        const struct kd_region *r=&c->regions[i];
        if(!r->executable) continue;
        size_t end=r->off+r->size;
        for(size_t p=r->off+4;p+8<=end;p+=4) {
            uint32_t set=kd_word(c,p),bit=kd_word(c,p+4);
            if((set&0xffffffe0)!=0x1a9f17e0 && (set&0xffffffe0)!=0x52800020) continue;
            if((bit&0xfff80000)!=0x37100000 ||
               (kd_word(c,p-4)&0xffe0fc1f)!=0xeb00001f) continue;
            unsigned permission=bit&31;
            size_t fn=kd_function(c,p),field=KD_NONE;
            if(fn==KD_NONE || p-fn>0x4000) continue;
            for(size_t q=p>40?p-40:0;q<p-4;q+=4)
                if((kd_word(c,q)&0xfffffc1f)==(0xf9400400|permission)) {
                    if(field!=KD_NONE) { field=KD_NONE;break; }
                    field=q;
                }
            if(field==KD_NONE) continue;
            int table_ref=0;
            for(size_t q=fn;q<field;q+=4) {
                size_t target;
                if(kd_address(c,q,NULL,&target) && target>=t->start && target<=t->end &&
                   !((target-t->start)%t->stride)) table_ref=1;
            }
            size_t target=kd_branch(c,p+4);unsigned result=set&31;
            if(!table_ref || target==KD_NONE || !nv_returns(c,target,result)) continue;
            if(selected!=KD_NONE && selected!=p) return da_fail("unique NVRAM KernelOnly gate");
            selected=p;selected_reg=result;
        }
    }
    if(selected==KD_NONE) return da_fail("NVRAM KernelOnly permission result and return path");
    return kd_add_word(c,selected,0x52800020|selected_reg,"Allow NVRAM KernelOnly access");
}
static int kd_nvram(struct kd_ctx *c) {
    struct nv_image *im=calloc(1,sizeof(*im));
    if(!im) return -1;
    im->buf=c->buf;im->len=c->len;im->pointer_size=8;
    for(size_t i=0;i<c->region_count;i++) {
        const struct kd_region *r=&c->regions[i];
        im->maps[im->map_count++]=(struct nv_map){r->off,r->size,r->address,
            !r->executable && !strncmp(r->name,"__DATA",6)};
    }
    struct nv_table table;
    int bits=c->xnu>=8019,rc=nv_find(im,bits,&table);
    if(!rc) rc=bits?nv_modern(c,&table):nv_legacy(im,&table);
    free(im);return rc;
}
