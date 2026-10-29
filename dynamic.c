/* Discover instructions in the supplied Mach-O, without firmware profiles. */
#include "dynamic.h"
static uint64_t kd_u64(const unsigned char *p) {
    return (uint64_t)read_le32(p) | (uint64_t)read_le32(p+4)<<32;
}
static uint32_t kd_word(const struct kd_ctx *c,size_t p) {
    return p<=c->len && c->len-p>=4 ? read_le32(c->buf+p) : 0;
}
static uint64_t kd_va(const struct kd_ctx *c,size_t p) {
    for(size_t i=0;i<c->region_count;++i) {
        const struct kd_region *r=&c->regions[i];
        if(p>=r->off && p-r->off<r->size) return r->address+p-r->off;
    }
    return UINT64_MAX;
}
static size_t kd_offset(const struct kd_ctx *c,uint64_t a) {
    for(size_t i=0;i<c->region_count;++i) {
        const struct kd_region *r=&c->regions[i];
        if(a>=r->address && a-r->address<r->size) return r->off+(size_t)(a-r->address);
    }
    return KD_NONE;
}
static int kd_exec_bounds(const struct kd_ctx *c,size_t p,size_t *start,size_t *end) {
    for(size_t i=0;i<c->region_count;++i) {
        const struct kd_region *r=&c->regions[i];
        if(r->executable && p>=r->off && p-r->off<r->size) {
            if(start) *start=r->off;
            if(end) *end=r->off+r->size;
            return 1;
        }
    }
    return 0;
}
static int kd_executable(const struct kd_ctx *c,size_t p) {
    size_t end;
    return !(p&3) && p<=c->len && c->len-p>=4 &&
           kd_exec_bounds(c,p,NULL,&end) && end-p>=4;
}
static int64_t kd_signed(uint64_t v,unsigned bits) {
    return (int64_t)(v<<(64-bits))>>(64-bits);
}
static int kd_address(const struct kd_ctx *c,size_t p,unsigned *reg,size_t *target) {
    uint32_t op=kd_word(c,p);unsigned rd=op&31;
    uint64_t pc=kd_va(c,p),address;
    if(pc==UINT64_MAX) return 0;
    uint64_t imm=((uint64_t)(op>>5)&0x7ffff)<<2 | ((op>>29)&3);
    if((op&0x9f000000)==0x10000000) address=pc+kd_signed(imm,21);
    else if((op&0x9f000000)==0x90000000) {
        address=(pc&~UINT64_C(4095))+kd_signed(imm,21)*4096;
        uint32_t next=kd_word(c,p+4);
        if((next&0xffc00000)!=0x91000000 || ((next>>5)&31)!=rd) return 0;
        address+=(next>>10)&4095;rd=next&31;
    } else return 0;
    size_t off=kd_offset(c,address);
    if(off==KD_NONE) return 0;
    if(reg) *reg=rd;
    if(target) *target=off;
    return 1;
}
static size_t kd_branch(const struct kd_ctx *c,size_t p) {
    uint32_t w=kd_word(c,p);int64_t delta;
    if((w&0x7c000000)==0x14000000) delta=kd_signed(w&0x03ffffff,26)*4;
    else if((w&0x7e000000)==0x34000000 || (w&0xff000010)==0x54000000)
        delta=kd_signed((w>>5)&0x7ffff,19)*4;
    else if((w&0x7e000000)==0x36000000) delta=kd_signed((w>>5)&0x3fff,14)*4;
    else return KD_NONE;
    uint64_t pc=kd_va(c,p);
    return pc==UINT64_MAX?KD_NONE:kd_offset(c,pc+delta);
}
static int kd_prologue(uint32_t w) {
    return (w&0xffc003e0)==0xa98003e0 || w==0xd503237f || w==0xd503233f;
}
static size_t kd_function(const struct kd_ctx *c,size_t p) {
    size_t begin,end;
    if(!kd_exec_bounds(c,p,&begin,&end)) return KD_NONE;
    size_t lo=0,hi=c->function_count;
    while(lo<hi) {
        size_t mid=lo+(hi-lo)/2;
        if(c->functions[mid]<=p) lo=mid+1;else hi=mid;
    }
    if(lo && c->functions[lo-1]>=begin) return c->functions[lo-1];
    for(size_t q=p&~(size_t)3;;q-=4) {
        uint32_t w=kd_word(c,q);
        if((w&0xffc07fff)==0xa9007bfd) {
            size_t a=q;
            while(a>=begin+4 && q-a<64 &&
                  (kd_word(c,a-4)&0xffc003e0)==0xa90003e0) a-=4;
            if(a>=begin+4 && (kd_word(c,a-4)&0xffc003ff)==0xd10003ff) {
                a-=4;
                if(a>=begin+4 && (kd_word(c,a-4)==0xd503237f || kd_word(c,a-4)==0xd503233f)) a-=4;
                return a;
            }
        }
        if((w&0xffc003ff)==0xd10003ff) {
            for(size_t a=q+4;a<end && a-q<=64;a+=4) {
                uint32_t save=kd_word(c,a);
                if((save&0xffc07fff)==0xa9007bfd) {
                    if(q>=begin+4 && (kd_word(c,q-4)==0xd503237f || kd_word(c,q-4)==0xd503233f))
                        return q-4;
                    return q;
                }
                if((save&0xffc003e0)!=0xa90003e0) break;
            }
        }
        if(kd_prologue(w)) {
            if(q>=begin+4 && (kd_word(c,q-4)&0xffc003ff)==0xd10003ff) q-=4;
            if(q>=begin+4 && (kd_word(c,q-4)==0xd503237f || kd_word(c,q-4)==0xd503233f)) q-=4;
            return q;
        }
        if((w&0xffc07fff)==0xa9007bfd && q>=begin+4 &&
           (kd_word(c,q-4)&0xffc003ff)==0xd10003ff) return q-4;
        if(q<begin+4 || p-q>=0x4000) break;
    }
    return KD_NONE;
}
static size_t kd_string(const struct kd_ctx *c,const char *s) {
    const unsigned char *p=memmem(c->buf,c->len,s,strlen(s));
    return p?(size_t)(p-c->buf):KD_NONE;
}
static size_t kd_xref(const struct kd_ctx *c,size_t start,size_t end,size_t target) {
    if(end>c->len) end=c->len;
    for(size_t i=0;i<c->region_count;++i) {
        const struct kd_region *r=&c->regions[i];
        if(!r->executable) continue;
        size_t a=start>r->off?start:r->off,z=end<r->off+r->size?end:r->off+r->size;
        a=(a+3)&~(size_t)3;
        for(size_t p=a;p<z && z-p>=4;p+=4) {
            size_t t;
            if(kd_address(c,p,NULL,&t) && t==target) return p;
        }
    }
    return KD_NONE;
}
static int kd_add(struct kd_ctx *c,size_t p,const void *bytes,size_t n,const char *name) {
    size_t code_end;
    if(!n || n>sizeof(kp.edits[0].after) || p>c->len || n>c->len-p || !kd_executable(c,p) ||
       !kd_exec_bounds(c,p,NULL,&code_end) || n>code_end-p) {
        fprintf(stderr,"Invalid dynamic patch extent for %s.\n",name);return -1;
    }
    return kp_add(p,kd_va(c,p),bytes,n,name,0);
}
static int kd_add_word(struct kd_ctx *c,size_t p,uint32_t w,const char *name) {
    unsigned char b[4]={(unsigned char)w,(unsigned char)(w>>8),(unsigned char)(w>>16),(unsigned char)(w>>24)};
    return kd_add(c,p,b,4,name);
}
/* Legacy prelinked kernels map their container as data. Execution permissions
 * belong to each embedded kext's validated instruction sections. */
static int kd_prelinked_code(struct kd_ctx *c) {
    size_t original=c->region_count;
    for(size_t ri=0;ri<original;ri++) {
        struct kd_region container=c->regions[ri];
        if(strcmp(container.name,"__PRELINK_TEXT")) continue;
        size_t end=container.off+container.size;
        for(size_t head=container.off;head<end && end-head>=32;head+=4) {
            if(kd_word(c,head)!=0xfeedfacf || kd_word(c,head+4)!=0x0100000c || kd_word(c,head+12)!=11) continue;
            uint32_t count=kd_word(c,head+16),bytes=kd_word(c,head+20);
            if(!count || count>128 || bytes>end-head-32 || count>bytes/8) continue;
            size_t p=head+32,stop=p+bytes,save=c->region_count;
            int valid=1,identity=0;
            for(uint32_t j=0;j<count;j++) {
                if(stop-p<8) { valid=0;break; }
                uint32_t cmd=kd_word(c,p),size=kd_word(c,p+4);
                if(size<8 || size>stop-p) { valid=0;break; }
                if(cmd==0x19) {
                    if(size<72 || kd_word(c,p+64)>(size-72)/80) { valid=0;break; }
                    uint64_t va=kd_u64(c->buf+p+24),fs=kd_u64(c->buf+p+48);
                    uint64_t fo=kd_u64(c->buf+p+40);
                    if(!fo && kd_offset(c,va)==head) identity=1;
                    for(uint32_t k=0;k<kd_word(c,p+64);k++) {
                        size_t s=p+72+(size_t)k*80;
                        if(!(kd_word(c,s+64)&0x80000400u)) continue;
                        uint64_t a=kd_u64(c->buf+s+32),n=kd_u64(c->buf+s+40);
                        size_t off=kd_offset(c,a);
                        if(!n) continue;
                        if(a<va || a-va>fs || n>fs-(a-va) || off==KD_NONE ||
                           off<container.off || off>end || n>end-off || (off&3)) { valid=0;break; }
                        if(c->region_count>=sizeof(c->regions)/sizeof(*c->regions)) return -1;
                        struct kd_region *r=&c->regions[c->region_count++];
                        r->off=off;r->size=(size_t)n;r->address=a;r->executable=1;
                        memcpy(r->name,c->buf+s,16);r->name[16]=0;
                    }
                    if(!valid) break;
                }
                p+=size;
            }
            if(!valid || !identity || p!=stop) c->region_count=save;
        }
    }
    return 0;
}
static int kd_init(struct kd_ctx *c,unsigned char *buf,size_t len) {
    if(!c || !buf) return -1;
    memset(c,0,sizeof(*c));c->buf=buf;c->len=len;
    if(len<32) return -1;
    uint32_t commands=read_le32(buf+16),command_bytes=read_le32(buf+20);
    if(!commands || command_bytes>len-32 || commands>command_bytes/8) return -1;
    size_t pos=32,starts=0,start_size=0;uint64_t text=UINT64_MAX;
    size_t command_end=32+(size_t)command_bytes;
    for(uint32_t i=0;i<commands;++i) {
        if(pos>command_end || command_end-pos<8) return -1;
        uint32_t cmd=read_le32(buf+pos),size=read_le32(buf+pos+4);
        if(size<8 || size>command_end-pos) return -1;
        if(cmd==0x19) {
            if(size<72 || c->region_count>=sizeof(c->regions)/sizeof(*c->regions) || read_le32(buf+pos+64)>(size-72)/80) return -1;
            uint64_t va=kd_u64(buf+pos+24),off=kd_u64(buf+pos+40),extent=kd_u64(buf+pos+48);
            if(off>len || extent>len-off || extent>UINT64_MAX-va) return -1;
            if(extent) {
                struct kd_region *r=&c->regions[c->region_count++];
                r->off=(size_t)off;r->size=(size_t)extent;r->address=va;
                r->executable=(read_le32(buf+pos+60)&4)!=0;
                memcpy(r->name,buf+pos+8,16);r->name[16]=0;
            }
            if(!(read_le32(buf+pos+60)&4)) {
                for(uint32_t j=0;j<read_le32(buf+pos+64);++j) {
                    size_t section=pos+72+(size_t)j*80;
                    if(!(read_le32(buf+section+64)&0x80000400u)) continue;
                    uint64_t address=kd_u64(buf+section+32),length=kd_u64(buf+section+40);
                    size_t file=read_le32(buf+section+48);
                    if(!length) continue;
                    if(c->region_count>=sizeof(c->regions)/sizeof(*c->regions) || file<off || file-off>extent || length>extent-(file-off) ||
                       address<va || address-va!=file-off) return -1;
                    struct kd_region *r=&c->regions[c->region_count++];
                    r->off=file;r->size=(size_t)length;r->address=address;r->executable=1;
                    memcpy(r->name,buf+section,16);r->name[16]=0;
                }
            }
            if(!memcmp(buf+pos+8,"__TEXT\0",7)) text=va;
        } else if(cmd==2) {
            if(size<24) return -1;
            c->symoff=read_le32(buf+pos+8);c->nsyms=read_le32(buf+pos+12);
            c->stroff=read_le32(buf+pos+16);c->strsize=read_le32(buf+pos+20);
            if(c->symoff>len || c->nsyms>(len-c->symoff)/16 ||
               c->stroff>len || c->strsize>len-c->stroff) return -1;
        } else if(cmd==0x26 && size>=16) {
            starts=read_le32(buf+pos+8);start_size=read_le32(buf+pos+12);
        } else if(cmd==0x32 && size>=24) {
            c->platform=read_le32(buf+pos+8);c->minos=read_le32(buf+pos+12);
        }
        pos+=size;
    }
    if(pos!=command_end) return -1;
    const unsigned char *v=memmem(buf,len,"root:xnu-",9);
    size_t version_prefix=9;
    if(!v) { v=memmem(buf,len,"root:xnu_development-",21);version_prefix=21; }
    if(v) {
        size_t p=(size_t)(v-buf)+version_prefix;
        while(p<len && buf[p]>='0' && buf[p]<='9') {
            if(c->xnu>(UINT_MAX-9)/10) return -1;
            c->xnu=c->xnu*10+buf[p++]-'0';
        }
    }
    if(!c->region_count || !c->xnu || kd_prelinked_code(c)) return -1;
    if(start_size) {
        if(starts>len || start_size>len-starts || text==UINT64_MAX) return -1;
        c->functions=calloc(start_size,sizeof(size_t));
        if(!c->functions) return -1;
        uint64_t va=text;size_t p=starts,z=starts+start_size;
        while(p<z) {
            uint64_t delta=0;unsigned shift=0;unsigned char b;
            do {
                b=buf[p++];if(shift>=64 || (shift==63 && (b&0x7e))) return -1;
                delta|=(uint64_t)(b&127)<<shift;shift+=7;
            } while((b&128) && p<z);
            if(b&128) return -1;
            if(!delta) break;
            if(delta>UINT64_MAX-va) return -1;
            va+=delta;size_t off=kd_offset(c,va);
            if(off==KD_NONE || !kd_executable(c,off) ||
                (c->function_count && off<=c->functions[c->function_count-1])) return -1;
            c->functions[c->function_count++]=off;
        }
    }
    return 0;
}

#include "dynamic_amfi.c"
#include "dynamic_aux.c"

static int patch_dynamic_kernel(unsigned char *buf,size_t len,uint64_t selection) {
    struct kd_ctx *c=calloc(1,sizeof(*c));
    if(!c) return -1;
    int result=-1;
    if(kd_init(c,buf,len)) { fprintf(stderr,"Cannot map ARM64 kernel code.\n");goto done; }
    result=0;
    for(unsigned id=0;id<KP_COUNT;id++) if(selection&KP_BIT(id)) {
        kp_begin((enum kp_id)id);
        int rc;
        if(id<=KP_DEVELOPER_MODE) rc=kd_amfi_patch(c,(enum kp_id)id);
        else if(id<=KP_UNENCRYPTED) rc=kd_aux(c,1<<(id-KP_FIRMWARE+1));
        else if(id==KP_APFS_MOUNT_AUTH) rc=da_apfs_mount_auth(c);
        else if(id==KP_APFS_REMOUNT) rc=da_apfs_remount(c);
        else if(id==KP_FAIRPLAY_VALIDATION) {
            kp_absent("This legacy FairPlay policy applies to ARM iPhone OS kernels");rc=0;
        }
        else if(id==KP_VM_MAP_PROTECTION) { kp_absent("This legacy vm_map guard applies to ARM iPhone OS 2.0 kernels");rc=0; }
        else if(id==KP_AMFI_VNODE_VALIDATION || id==KP_LEGACY_CS_VALIDATION) {
            kp_absent("This legacy iPhone OS 2.0 policy applies to ARM kernels");rc=0;
        }
        else rc=kp_unsupported("This policy finder currently supports ARM32 kernels only");
        if(kp_finish(rc)) result=-1;
    }
done:
    free(c->functions);free(c);return result;
}
