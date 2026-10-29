#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static uint32_t read_le32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint32_t read_be32(const unsigned char *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | p[3];
}

/* Discover Thumb kernel policy and kext paths from Mach-O metadata and code. */
#define WK_MAX_MAPS 32
#define WK_MAX_MODULES 256
struct wk_range { size_t start, end; };
struct wk_map { uint32_t va, size; size_t off; };
struct wk_module { struct wk_range text, strings; size_t header; };
struct wk_image {
    unsigned char *b; size_t len;
    struct wk_map maps[WK_MAX_MAPS]; size_t nmaps;
    struct wk_module modules[WK_MAX_MODULES]; size_t nmodules;
    struct wk_range prelink;
    uint32_t symoff, nsyms, stroff, strsize;
    unsigned xnu, subtype;
};
static uint16_t wk_u16(const struct wk_image *im, size_t off) {
    return (uint16_t)(im->b[off] | (unsigned)im->b[off+1] << 8);
}
static size_t wk_off(const struct wk_image *im, uint32_t va) {
    for (size_t i=0;i<im->nmaps;i++)
        if (va>=im->maps[i].va && (uint64_t)va-im->maps[i].va<im->maps[i].size)
            return im->maps[i].off+(va-im->maps[i].va);
    return SIZE_MAX;
}
static uint32_t wk_va(const struct wk_image *im, size_t off) {
    for (size_t i=0;i<im->nmaps;i++)
        if (off>=im->maps[i].off && off-im->maps[i].off<im->maps[i].size)
            return im->maps[i].va+(uint32_t)(off-im->maps[i].off);
    return 0;
}
static int wk_in(struct wk_range r,size_t off,size_t size) {
    return off>=r.start && off<r.end && size<=r.end-off;
}
static size_t wk_width(const struct wk_image *im,size_t off) {
    return (wk_u16(im,off)&0xf800)>=0xe800 ? 4 : 2;
}
static int32_t wk_signed(uint32_t n,unsigned bits) {
    return (int32_t)(n | ((n & (UINT32_C(1)<<(bits-1))) ? ~((UINT32_C(1)<<bits)-1) : 0));
}
/* kind: 1 conditional, 2 unconditional, 3 call. */
static size_t wk_branch(const struct wk_image *im,size_t p,int *kind) {
    *kind=0;
    if (p>im->len || im->len-p<2) return SIZE_MAX;
    uint16_t a=wk_u16(im,p); uint32_t pc=wk_va(im,p)+4; int32_t d=0;
    if ((a&0xf800)==0xe000) { *kind=2; d=wk_signed((a&0x7ff)<<1,12); }
    else if ((a&0xf000)==0xd000 && (a&0xf00)<0xe00) {
        *kind=1; d=wk_signed((a&255)<<1,9);
    } else if ((a&0xf500)==0xb100) {
        *kind=1; d=(int32_t)(((a>>3)&31)*2+((a>>9)&1)*64);
    } else if ((a&0xf800)==0xf000 && im->len-p>=4) {
        uint16_t b=wk_u16(im,p+2); unsigned s=(a>>10)&1,j1=(b>>13)&1,j2=(b>>11)&1;
        if ((b&0xd000)==0xd000 || (b&0xd000)==0x9000) {
            *kind=(b&0xd000)==0xd000 ? 3 : 2;
            d=wk_signed(s<<24|(!(j1^s))<<23|(!(j2^s))<<22|(a&1023)<<12|(b&2047)<<1,25);
        } else if ((b&0xd000)==0x8000 && ((a>>6)&15)<14) {
            *kind=1; d=wk_signed(s<<20|j2<<19|j1<<18|(a&63)<<12|(b&2047)<<1,21);
        }
    }
    return *kind ? wk_off(im,pc+(uint32_t)d) : SIZE_MAX;
}
static int wk_header(struct wk_image *im,size_t off,int top) {
    if (off>im->len || im->len-off<28 || read_le32(im->b+off)!=0xfeedface ||
        read_le32(im->b+off+4)!=12) return 0;
    unsigned subtype=read_le32(im->b+off+8)&0xffffff;
    if(top && subtype!=6 && subtype!=9 && subtype!=11 && subtype!=12) return 0;
    uint32_t n=read_le32(im->b+off+16),z=read_le32(im->b+off+20);
    if (!n || n>128 || z>im->len-off-28 || n>z/8) return 0;
    size_t p=off+28,end=p+z;
    struct wk_module module={{0,0},{0,0},off};
    for (uint32_t i=0;i<n;i++) {
        if (end-p<8) return 0;
        uint32_t cmd=read_le32(im->b+p),size=read_le32(im->b+p+4);
        if (size<8 || size>end-p) return 0;
        if (cmd==1) {
            if (size<56) return 0;
            uint32_t va=read_le32(im->b+p+24),fo=read_le32(im->b+p+32),fs=read_le32(im->b+p+36);
            uint32_t ns=read_le32(im->b+p+48);
            if (ns>(size-56)/68) return 0;
            if (top && fs) {
                if (fo>im->len || fs>im->len-fo || im->nmaps==WK_MAX_MAPS || (uint64_t)va+fs>UINT64_C(0x100000000)) return 0;
                im->maps[im->nmaps++]=(struct wk_map){va,fs,fo};
            }
        } else if (top && cmd==2) {
            if (size<24) return 0;
            im->symoff=read_le32(im->b+p+8); im->nsyms=read_le32(im->b+p+12);
            im->stroff=read_le32(im->b+p+16); im->strsize=read_le32(im->b+p+20);
            if (im->symoff>im->len || im->nsyms>(im->len-im->symoff)/12 ||
                im->stroff>im->len || im->strsize>im->len-im->stroff) return 0;
        }
        p+=size;
    }
    if (p!=end) return 0;
    p=off+28;
    for (uint32_t i=0;i<n;i++) {
        uint32_t cmd=read_le32(im->b+p),size=read_le32(im->b+p+4);
        if (cmd==1) for (uint32_t j=0;j<read_le32(im->b+p+48);j++) {
            size_t q=p+56+j*68; uint32_t va=read_le32(im->b+q+32),length=read_le32(im->b+q+36);
            size_t at=wk_off(im,va);
            if (!length || at==SIZE_MAX || length>im->len-at) continue;
            size_t last=wk_off(im,va+length-1);
            /* Overlapping VM maps can make a section's backing range ambiguous. */
            if((uint64_t)va+length>UINT64_C(0x100000000) || last!=at+length-1) continue;
            if (!memcmp(im->b+q,"__text\0",7) && !memcmp(im->b+q+16,"__TEXT\0",7)) module.text=(struct wk_range){at,at+length};
            if (top && !memcmp(im->b+q,"__text\0",7) && !memcmp(im->b+q+16,"__PRELINK",9))
                im->prelink=(struct wk_range){at,at+length};
            if (!memcmp(im->b+q,"__cstring\0",10)) module.strings=(struct wk_range){at,at+length};
        }
        p+=size;
    }
    if (module.text.end && im->nmodules<WK_MAX_MODULES) im->modules[im->nmodules++]=module;
    return 1;
}
static int wk_open(struct wk_image *im,unsigned char *b,size_t len) {
    if(!im || !b) return -1;
    memset(im,0,sizeof(*im)); im->b=b; im->len=len;
    if (len<28 || read_le32(b+12)!=2 || !wk_header(im,0,1) || !im->nmodules) return -1;
    im->subtype=read_le32(b+8)&0xffffff;
    const unsigned char *v=memmem(b,len,"root:xnu-",9);size_t prefix=9;
    if(!v) { v=memmem(b,len,"root:xnu_development-",21);prefix=21; }
    if(v) for(size_t p=(size_t)(v-b)+prefix;p<len && b[p]>='0' && b[p]<='9';p++) {
        if(im->xnu>(UINT32_MAX-9)/10) return -1;
        im->xnu=im->xnu*10+b[p]-'0';
    }
    if(!im->xnu) return -1;
    for (size_t p=28;p+28<=len;p+=4)
        if (read_le32(b+p)==0xfeedface && (read_le32(b+p+12)==11 || read_le32(b+p+12)==1))
            (void)wk_header(im,p,0);
    return 0;
}
static size_t wk_symbol(const struct wk_image *im,const char *name) {
    if(kp_ignore_symbols) return SIZE_MAX;
    size_t found=SIZE_MAX;
    for (uint32_t i=0;i<im->nsyms;i++) {
        const unsigned char *s=im->b+im->symoff+(size_t)i*12;
        uint32_t idx=read_le32(s); unsigned type=s[4];
        if ((type&0xe0) || (type&0xe)!=0xe || idx>=im->strsize) continue;
        const char *n=(const char *)im->b+im->stroff+idx;
        size_t left=im->strsize-idx;
        if (!memchr(n,0,left) || strlen(name)>=left || strcmp(n,name)) continue;
        size_t p=wk_off(im,read_le32(s+8)&~1u);
        if (p==SIZE_MAX) return SIZE_MAX;
        if (found!=SIZE_MAX && found!=p) return SIZE_MAX;
        found=p;
    }
    return found;
}
static int wk_mov(uint16_t a,uint16_t b,unsigned *rd,uint32_t *imm,int *high) {
    unsigned k=a&0xfbf0;
    if (k!=0xf240 && k!=0xf2c0) return 0;
    *rd=(b>>8)&15; *high=k==0xf2c0;
    *imm=(a&15)<<12|(a&0x400)<<1|(b&0x7000)>>4|(b&255);
    return 1;
}
static size_t wk_resolve(const struct wk_image *im,size_t p) {
    if (p==SIZE_MAX || p>im->len || im->len-p<16) return p;
    unsigned r1,r2; uint32_t lo,hi; int h1,h2;
    if (wk_mov(wk_u16(im,p),wk_u16(im,p+2),&r1,&lo,&h1) && !h1 &&
        wk_mov(wk_u16(im,p+4),wk_u16(im,p+6),&r2,&hi,&h2) && h2 && r1==12 && r2==12 &&
        wk_u16(im,p+8)==0x44fc && wk_u16(im,p+10)==0xf8dc &&
        wk_u16(im,p+12)==0xc000 && wk_u16(im,p+14)==0x4760) {
        size_t slot=wk_off(im,(lo|hi<<16)+wk_va(im,p+8)+4);
        if (slot!=SIZE_MAX && im->len-slot>=4) return wk_off(im,read_le32(im->b+slot)&~1u);
    }
    return p;
}
static struct wk_range wk_code(const struct wk_image *im,size_t p) {
    for (size_t i=0;i<im->nmodules;i++) if (wk_in(im->modules[i].text,p,2)) return im->modules[i].text;
    return (struct wk_range){0,0};
}
static int wk_called(const struct wk_image *im,struct wk_range code,size_t target) {
    for (size_t p=code.start;p+4<=code.end;p+=wk_width(im,p)) {
        int kind; size_t to=wk_branch(im,p,&kind);
        if (kind==3 && to==target) return 1;
    }
    return 0;
}
static size_t wk_function(const struct wk_image *im,size_t ref) {
    if(ref>im->len || im->len-ref<4) return SIZE_MAX;
    struct wk_range code=wk_code(im,ref);
    if (!code.end) return SIZE_MAX;
    size_t min=ref-code.start>4096 ? ref-4096 : code.start;
    for (size_t p=ref;;p-=2) {
        uint16_t a=wk_u16(im,p),b=wk_u16(im,p+2);
        if ((a&0xff00)==0xb500 && (b==0x466f || (b&0xff80)==0xaf00)) return p;
        if ((a==0x2000 || a==0x2001) && b==0x4770 && wk_called(im,code,p)) return p;
        if (p<min+2) break;
    }
    return SIZE_MAX;
}
static int wk_add(const struct wk_image *im,const char *name,size_t p,const unsigned char *bytes,size_t n) {
    if (p==SIZE_MAX || p>im->len || n>im->len-p || !n || n>4 || (p&1)) return -1;
    int executable=0;
    for(size_t i=0;i<im->nmodules;i++) if(wk_in(im->modules[i].text,p,n)) executable=1;
    if(!executable) return -1;
    return kp_add(p,wk_va(im,p),bytes,n,name,0);
}
static int wk_data_u32(const struct wk_image *im,const char *name,size_t p,uint32_t value) {
    if(p==SIZE_MAX || p>im->len || im->len-p<4 || wk_va(im,p)==0) return -1;
    for(size_t i=0;i<im->nmodules;i++) if(wk_in(im->modules[i].text,p,4)) return -1;
    uint32_t old=read_le32(im->b+p);
    if(old!=0 && old!=value) return -1;
    unsigned char bytes[4]={(unsigned char)value,(unsigned char)(value>>8),
                            (unsigned char)(value>>16),(unsigned char)(value>>24)};
    return kp_add(p,wk_va(im,p),bytes,4,name,1);
}
static int wk_b(const struct wk_image *im,const char *name,size_t from,size_t to) {
    int64_t d=(int64_t)wk_va(im,to)-(int64_t)wk_va(im,from)-4;
    if ((d&1) || d < -2048 || d>2046) return -1;
    uint16_t h=(uint16_t)(0xe000|((uint32_t)(d/2)&0x7ff));
    unsigned char b[2]={(unsigned char)h,(unsigned char)(h>>8)};
    return wk_add(im,name,from,b,2);
}
struct wk_refs { size_t positions[16]; size_t count; int overflow; };
static void wk_reference(struct wk_refs *out,size_t p) {
    for (size_t i=0;i<out->count;i++) if (out->positions[i]==p) return;
    if (out->count==16) { out->overflow=1; return; }
    out->positions[out->count++]=p;
}
/* Constant propagation for literal loads, MOVW/MOVT and PC-relative ADD/ADR. */
static struct wk_refs wk_refs_to(const struct wk_image *im,uint32_t target) {
    struct wk_refs out={{0},0,0};
    for (size_t m=0;m<im->nmodules;m++) {
        uint32_t value[16]={0}; size_t age[16]={0}; unsigned valid=0;
        struct wk_range code=im->modules[m].text;
        for (size_t p=code.start;p+4<=code.end;p+=wk_width(im,p)) {
            uint16_t a=wk_u16(im,p),b=wk_u16(im,p+2); unsigned rd=0; uint32_t v=0; int set=0,high=0;
            if ((a&0xff00)==0xb500) valid=0;
            if ((a&0xf800)==0x4800) {
                rd=(a>>8)&7; size_t q=wk_off(im,((wk_va(im,p)+4)&~3u)+(a&255)*4);
                if (q!=SIZE_MAX && im->len-q>=4) { v=read_le32(im->b+q); set=1; }
            } else if (a==0xf8df || a==0xf85f) {
                rd=b>>12; uint32_t pc=(wk_va(im,p)+4)&~3u;
                size_t q=wk_off(im,a==0xf8df ? pc+(b&0xfff) : pc-(b&0xfff));
                if (q!=SIZE_MAX && im->len-q>=4) { v=read_le32(im->b+q); set=1; }
            } else if (wk_mov(a,b,&rd,&v,&high)) {
                if (high) { if ((valid&(1u<<rd)) && p-age[rd]<64) v=(value[rd]&65535)|(v<<16); else continue; }
                set=1;
            } else if ((a&0xff78)==0x4478) {
                rd=(a&7)|((a>>4)&8);
                if ((valid&(1u<<rd)) && p-age[rd]<64) { v=value[rd]+wk_va(im,p)+4; set=1; }
            } else if ((a&0xf800)==0xa000) { rd=(a>>8)&7; v=((wk_va(im,p)+4)&~3u)+(a&255)*4; set=1; }
            if (set) { value[rd]=v; age[rd]=p; valid|=1u<<rd; if (v==target) wk_reference(&out,p); }
            int kind; (void)wk_branch(im,p,&kind); if (kind==3) valid&=~15u;
        }
    }
    return out;
}
static size_t wk_string(const struct wk_image *im,const char *needle,int containing) {
    size_t n=strlen(needle),found=SIZE_MAX;
    for (size_t p=0;p+n<=im->len;p++) if (!memcmp(im->b+p,needle,n)) {
        if (!containing && (p+n==im->len || im->b[p+n])) continue;
        size_t start=p;
        if (containing) while (start && p-start<512 && im->b[start-1]) start--;
        if (found!=SIZE_MAX && found!=start) return SIZE_MAX;
        found=start;
    }
    return found;
}
static int wk_unique(struct wk_refs r,size_t *p) {
    if (r.overflow || r.count!=1) return -1;
    *p=r.positions[0]; return 0;
}
static int wk_policy(struct wk_image *im,enum kp_id id) {
    static const char *const names[]={"_cs_enforcement","_cs_process_enforcement","_cs_process_global_enforcement","_cs_system_enforcement","_cs_require_lv","_cs_system_require_lv"};
    const unsigned char no[4]={0,0x20,0x70,0x47};
    unsigned found=0;
    if(id==KP_CS_ENFORCEMENT) {
        size_t global=wk_symbol(im,"_cs_enforcement_disable");
        if(global!=SIZE_MAX && !wk_data_u32(im,"_cs_enforcement_disable",global,1)) return 0;
    }
    size_t start=id==KP_CS_ENFORCEMENT?0:4,end=id==KP_CS_ENFORCEMENT?4:6;
    for(size_t i=start;i<end;i++) {
        size_t p=wk_symbol(im,names[i]);
        if(p==SIZE_MAX) continue;
        int thumb=0;
        for(uint32_t j=0;j<im->nsyms;j++) {
            const unsigned char *sym=im->b+im->symoff+(size_t)j*12;
            uint32_t value=read_le32(sym+8);
            if(wk_off(im,value&~1u)==p && ((value&1u) || (sym[6]&8u))) thumb=1;
        }
        if(!thumb) return kp_unsupported("Policy entry is not a validated Thumb function");
        if(!wk_in(im->modules[0].text,p,4) || wk_add(im,names[i],p,no,4)) return -1;
        found++;
    }
    if(!found) return kp_unsupported("No validated code-signing policy entry; stripped fallback is unavailable");
    return 0;
}
static int wk_amfi(struct wk_image *im) {
    const unsigned char yes[4]={1,0x20,0x70,0x47};
    struct wk_range code={0,0};
    const char bundle[]="com.apple.driver.AppleMobileFileIntegrity";
    for(size_t at=12;at+sizeof(bundle)+140<im->len;at+=4) {
        if(memcmp(im->b+at,bundle,sizeof(bundle)) || read_le32(im->b+at-8)!=1) continue;
        size_t header=wk_off(im,read_le32(im->b+at+136));
        /* Legacy kmod_info can occupy a separate region. Recover its header
         * by file offset and require a module parsed from that header. */
        if(header==SIZE_MAX) {
            size_t floor=at>UINT32_C(0x40000)?at-UINT32_C(0x40000):0;
            for(size_t q=at&~(size_t)3;q>=floor;q-=4) {
                if(read_le32(im->b+q)==0xfeedface) { header=q;break; }
                if(q<floor+4) break;
            }
        }
        for(size_t m=1;m<im->nmodules;m++) if(im->modules[m].header==header) {
            if(code.end && code.start!=im->modules[m].text.start)
                return kp_unsupported("AMFI module identification is ambiguous");
            code=im->modules[m].text;
        }
    }
    for (size_t i=1;i<im->nmodules;i++) {
        struct wk_range s=im->modules[i].strings;
        if (!s.end) continue;
        if (memmem(im->b+s.start,s.end-s.start,"entitlements too small",22) ||
            memmem(im->b+s.start,s.end-s.start,"Internal Error: No cdhash found.",31)) {
            if (code.end && code.start!=im->modules[i].text.start)
                return kp_unsupported("AMFI module identification is ambiguous");
            code=im->modules[i].text;
        }
    }
    if (!code.end) {
        if(!memmem(im->b,im->len,"AppleMobileFileIntegrity",25)) {
            kp_absent("This kernel has no AppleMobileFileIntegrity component");
            return 0;
        }
        return kp_unsupported("Cannot identify the ARM AMFI text section");
    }
    size_t pmap=wk_symbol(im,"_pmap_lookup_in_static_trust_cache"),memcmp_fn=wk_symbol(im,"_memcmp"),selected=SIZE_MAX;
    for (size_t p=code.start;p+8<=code.end;p+=wk_width(im,p)) {
        int kind; size_t to=wk_branch(im,p,&kind);
        if (kind!=3) continue;
        size_t resolved=wk_resolve(im,to),function=SIZE_MAX;
        if (pmap!=SIZE_MAX && resolved==pmap && wk_u16(im,p+4)==0xf000 && wk_u16(im,p+6)==1) {
            function=wk_function(im,p);
            if (function==SIZE_MAX || p-function>32) continue;
        } else if (memcmp_fn!=SIZE_MAX && resolved==memcmp_fn && p>=code.start+2 && wk_u16(im,p-2)==0x2213) {
            function=wk_function(im,p);
            if (function==SIZE_MAX || p-function>192) continue;
            unsigned nineteen=0,back=0;
            for (size_t q=function;q<p+48 && q+4<=code.end;q+=wk_width(im,q)) {
                uint16_t h=wk_u16(im,q); if ((h&0xf8ff)==0x2013) nineteen++;
                int k; size_t t=wk_branch(im,q,&k); if (k==1 && t>=function && t<q) back++;
            }
            if (nineteen<2 || !back) continue;
        }
        if (function!=SIZE_MAX) {
            if (selected!=SIZE_MAX && selected!=function)
                return kp_unsupported("AMFI static CDHash lookup is ambiguous");
            selected=function;
        }
    }
    if (selected==SIZE_MAX)
        return kp_unsupported("Cannot resolve the ARM AMFI static CDHash lookup");
    return wk_add(im,"AMFI static trust-cache lookup",selected,yes,4);
}
static int wk_straight(const struct wk_image *im,size_t start,size_t end) {
    if (start>end || end-start>256) return 0;
    size_t panic=wk_symbol(im,"_panic");
    for (size_t p=start;p<end;p+=wk_width(im,p)) {
        int k; size_t to=wk_branch(im,p,&k);
        if (k==1 || k==2 || (k==3 && panic!=SIZE_MAX && wk_resolve(im,to)==panic) ||
            wk_u16(im,p)==0x4770 || (wk_u16(im,p)&0xff00)==0xbd00) return 0;
    }
    return 1;
}
static int wk_firmware(struct wk_image *im) {
    size_t key=wk_string(im,"skipFWValidation",0);
    if (key==SIZE_MAX) {
        if (memmem(im->b,im->len,"skipFWValidation",16)) return -1;
        kp_absent("AppleFirmwareUpdate validation bypass"); return 0;
    }
    size_t keyref,logref=SIZE_MAX,log=wk_string(im,"Boot-arg present, skipping firmware validation",1);
    if (wk_unique(wk_refs_to(im,wk_va(im,key)),&keyref)) return -1;
    size_t function=wk_function(im,keyref),call=SIZE_MAX;
    if (function==SIZE_MAX) return -1;
    for (size_t p=keyref;p<keyref+32 && p+4<=im->len;p+=wk_width(im,p)) { int k; (void)wk_branch(im,p,&k); if (k==3) { call=p; break; } }
    if (call==SIZE_MAX) return -1;
    if (log==SIZE_MAX) {
        /* Development builds omit the skip message, but retain the mode/boot-arg
         * guards followed by the two success-state byte stores. */
        size_t destination=SIZE_MAX,last=SIZE_MAX; unsigned guards=0;
        for (size_t p=call+4;p<call+16;p+=wk_width(im,p)) {
            int k; size_t to=wk_branch(im,p,&k);
            if (k==1) {
                if (destination!=SIZE_MAX && destination!=to) return -1;
                destination=to; last=p+wk_width(im,p); guards++;
            }
        }
        if (guards!=2 || last==SIZE_MAX || destination<=last || destination-last>64) return -1;
        unsigned stores=0,zero=0,one=0; int object=-1;
        for (size_t p=last;p<destination;p+=wk_width(im,p)) {
            uint16_t a=wk_u16(im,p); if ((a&0xf8ff)==0x2000) zero++; if ((a&0xf8ff)==0x2001) one++;
            if ((a&0xfff0)==0xf880) { if (object>=0 && object!=(a&15)) return -1; object=a&15; stores++; }
        }
        if (stores!=2 || !zero || !one) return -1;
        return wk_b(im,"AppleFirmwareUpdate native validation bypass",call+4,last);
    }
    if (wk_unique(wk_refs_to(im,wk_va(im,log)),&logref) || wk_function(im,logref)!=function ||
        call+4>=logref || logref-call>256) return -1;
    size_t target=SIZE_MAX;
    for (size_t p=call+4;p<logref;p+=wk_width(im,p)) {
        int k; size_t to=wk_branch(im,p,&k);
        if (k==1 && to>p && to<=logref && wk_straight(im,to,logref)) {
            if (target!=SIZE_MAX && target!=to) return -1;
            target=to;
        }
    }
    if (target==SIZE_MAX) for (size_t p=call+4;p<logref;p+=wk_width(im,p)) {
        int k; size_t to=wk_branch(im,p,&k);
        if (k==1 && to>logref && wk_straight(im,p+wk_width(im,p),logref)) target=p+wk_width(im,p);
    }
    if (target==SIZE_MAX) return -1;
    return wk_b(im,"AppleFirmwareUpdate native validation bypass",call+4,target);
}
/* Find the branch entering an inline or outlined panic block. */
static int wk_failure(struct wk_image *im,const char *anchor,const char *name,int flag) {
    size_t string=wk_string(im,anchor,1),ref;
    if (string==SIZE_MAX) {
        if (memmem(im->b,im->len,anchor,strlen(anchor))) return -1;
        kp_absent(flag==4 ? "SPU firmware-validation failure guard" : "rootvp authentication panic"); return 0;
    }
    if (wk_unique(wk_refs_to(im,wk_va(im,string)),&ref)) return -1;
    struct wk_range code=wk_code(im,ref);
    size_t guard=SIZE_MAX,helper=wk_function(im,ref),block=SIZE_MAX;
    /* Direct branches to a straight-line panic block, including wide BNE. */
    for (size_t p=code.start;p+4<=code.end;p+=wk_width(im,p)) {
        int k; size_t to=wk_branch(im,p,&k);
        if (k==1 && to<=ref && ref-to<=64 && wk_straight(im,to,ref)) {
            if (guard!=SIZE_MAX && guard!=p) return -1;
            guard=p; block=to;
        }
    }
    if (guard==SIZE_MAX && flag==4) {
        for (size_t p=ref-code.start>128 ? ref-128 : code.start;p<ref;p+=2) {
            int k; size_t to=wk_branch(im,p,&k);
            uint16_t h=wk_u16(im,p);
            if ((k==1 || k==2) && to>ref && to-ref<=64 &&
                wk_straight(im,p+wk_width(im,p),ref) &&
                ((h&0xfd00)==0xb100 || (h&0xf800)==0xe000)) {
                if (guard!=SIZE_MAX && guard!=p) return -1;
                guard=p; block=to;
            }
        }
    }
    if (guard==SIZE_MAX && flag==4 && helper!=SIZE_MAX) {
        /* Early SPU handles validation statuses in a switch before logging.
         * Its zero-status edge enters the normal bundle-processing path. */
        for (size_t p=helper;p<ref && p<helper+64;p+=wk_width(im,p)) {
            int k; size_t to=wk_branch(im,p,&k); uint16_t h=wk_u16(im,p);
            if (to>ref && to-ref<=32 &&
                (((h&0xfd07)==0xb101 && !(h&0x800)) ||
                 ((h&0xf800)==0xe000 && wk_u16(im,p+2)==0x2901))) {
                if (guard!=SIZE_MAX && guard!=p) return -1;
                guard=p; block=to;
            }
        }
    }
    if (guard==SIZE_MAX && helper!=SIZE_MAX) {
        /* Later SPU builds outline the fatal logging code into a cold helper. */
        for (size_t m=0;m<im->nmodules;m++) {
            struct wk_range r=im->modules[m].text;
            for (size_t p=r.start;p+4<=r.end;p+=wk_width(im,p)) {
                int k; size_t to=wk_branch(im,p,&k);
                if (k!=3 || to!=helper) continue;
                size_t from=wk_function(im,p);
                if (from==SIZE_MAX || p-from>2048) continue;
                for (size_t q=from;q<p;q+=wk_width(im,q)) {
                    if (flag==4 && q>=from+2 && q<from+48 && wk_u16(im,q)==0xbf00 &&
                        (wk_u16(im,q-2)&0xfd07)==0xb100 && wk_u16(im,q+2)==0x4618) {
                        int next; (void)wk_branch(im,q+4,&next);
                        if (next==3) {
                            if (guard!=SIZE_MAX && guard!=q) return -1;
                            guard=q; block=p;
                        }
                    }
                    int branch; size_t dest=wk_branch(im,q,&branch);
                    if (branch==1 && dest<=p && p-dest<=16 && wk_straight(im,dest,p)) {
                        if (guard!=SIZE_MAX && guard!=q) return -1;
                        guard=q; block=dest;
                    }
                }
            }
        }
    }
    if (guard==SIZE_MAX && flag==8 && helper!=SIZE_MAX) {
        /* Recognize our removed wide guard between the authentication callback's
         * zero comparison and the next call, within this panic's owner. */
        for (size_t p=helper+4;p+8<ref;p+=2) {
            int k; (void)wk_branch(im,p+4,&k);
            if (wk_u16(im,p)==0xbf00 && wk_u16(im,p+2)==0xbf00 &&
                wk_u16(im,p-2)==0x2800 && (wk_u16(im,p-4)&0xff87)==0x4780 && k==3) {
                if (guard!=SIZE_MAX && guard!=p) return -1;
                guard=p; block=ref;
            }
        }
    }
    const unsigned char nop[4]={0,0xbf,0,0xbf};
    if (guard==SIZE_MAX) { fprintf(stderr,"Cannot resolve the ARM %s.\n",name); return -1; }
    if (flag==4 && block>guard && guard<ref && ref-guard<128) {
        /* Inline SPU: the zero-result branch skips the panic. Force that path. */
        uint16_t h=wk_u16(im,guard);
        if (((h&0xfd00)==0xb100 && !(h&0x800)) || (h&0xf800)==0xe000) {
            int k; size_t skip=wk_branch(im,guard,&k);
            return wk_b(im,name,guard,skip);
        }
    }
    return wk_add(im,name,guard,nop,wk_width(im,guard));
}

static int patch_arm32_kernel(unsigned char *buf,size_t len,uint64_t selection) {
    struct wk_image im;
    if(wk_open(&im,buf,len)) { fprintf(stderr,"Invalid or unsupported ARM Mach-O kernel metadata.\n");return -1; }
    int failed=0;
    for(unsigned id=0;id<KP_COUNT;id++) if(selection&KP_BIT(id)) {
        kp_begin((enum kp_id)id);
        int rc=0;
        switch(id) {
        case KP_AMFI_TRUST:rc=wk_amfi(&im);break;
        case KP_CS_ENFORCEMENT:case KP_LIBRARY_VALIDATION:rc=wk_policy(&im,(enum kp_id)id);break;
        case KP_AMFI_SHA1:
            if(im.xnu<8019) kp_absent("This XNU generation predates the targeted SHA-1 policy");
            else rc=kp_unsupported("ARM SHA-1 policy finder unavailable");
            break;
        case KP_LAUNCH_CONSTRAINTS:case KP_DEVELOPER_MODE:
            if(im.xnu<8792) kp_absent("This XNU generation predates this AMFI feature");
            else rc=kp_unsupported("ARM AMFI feature finder unavailable");
            break;
        case KP_FIRMWARE:rc=wk_firmware(&im);break;
        case KP_SPU:rc=wk_failure(&im,"firmware validation failed","SPU firmware-validation failure guard",4);break;
        case KP_ROOTVP:rc=wk_failure(&im,"rootvp not authenticated after mounting","rootvp authentication panic guard",8);break;
        case KP_ROOT_HASH:case KP_LOCAL_SIGNING:case KP_UNENCRYPTED:
            /* ARMv7k watchOS lacks these iOS filesystem/signing guards. */
            if(im.subtype==12) kp_absent("This watchOS kernel has no targeted filesystem/signing guard");
            else if(im.xnu<8019) kp_absent("This XNU generation predates the targeted filesystem/signing guard");
            else rc=kp_unsupported("No validated ARM finder for this guard");
            break;
        case KP_APFS_MOUNT_AUTH:case KP_APFS_REMOUNT:
            rc=kp_unsupported("No validated ARM APFS finder for this guard");
            break;
        default:rc=-1;break;
        }
        if(kp_finish(rc)) failed=1;
    }
    return failed?-1:0;
}
