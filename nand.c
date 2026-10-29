/* Reject NAND migrations, formats and signature writes through the
 * initializer's existing error paths. Included by watchos32.c. */
struct np_function { struct wk_range code; size_t start, end; int arm; };
struct np_call { size_t off, width, target; unsigned base, slot; int indirect; };

static size_t np_width(const struct wk_image *im, size_t p, int arm) {
    return arm ? 4 : wk_width(im,p);
}
static int np_call_at(const struct wk_image *im, size_t p, int arm, struct np_call *out) {
    if(p>im->len || im->len-p<4) return 0;
    memset(out,0,sizeof(*out));out->off=p;out->target=SIZE_MAX;
    out->width=np_width(im,p,arm);out->base=16;out->slot=UINT32_MAX;
    if(arm) {
        uint32_t w=read_le32(im->b+p);
        if((w&0xff000000)==0xeb000000) {
            out->target=wk_off(im,wk_va(im,p)+8+(uint32_t)wk_signed((w&0xffffff)<<2,26));
            return out->target!=SIZE_MAX;
        }
        if((w&0xfffffff0)==0xe12fff30) { out->indirect=1;out->base=w&15;return 1; }
        /* Old ARM GCC emits MOV lr,pc; LDR pc,[table,#offset]. */
        if(p>=4 && read_le32(im->b+p-4)==0xe1a0e00f &&
           (w&0xfff0f000)==0xe590f000) {
            out->indirect=2;out->base=(w>>16)&15;out->slot=w&0xfff;return 1;
        }
    } else {
        uint16_t a=wk_u16(im,p);
        if((a&0xff87)==0x4780) {out->indirect=1;out->base=(a>>3)&15;return 1;}
        int kind;size_t to=wk_branch(im,p,&kind);
        if(kind==3 && to!=SIZE_MAX) {out->target=to;return 1;}
    }
    return 0;
}
static int np_prologue(const struct wk_image *im,size_t p,int arm) {
    if(p>im->len || im->len-p<12) return 0;
    if(arm) {
        uint32_t a=read_le32(im->b+p),b=read_le32(im->b+p+4);
        return !(p&3) && (a&0xffffc000)==0xe92d4000 &&
               (a&0x80) && (b&0xfffff000)==0xe28d7000;
    }
    uint16_t a=wk_u16(im,p),b=wk_u16(im,p+2);
    return (a&0xff80)==0xb580 && (b&0xff80)==0xaf00;
}
static int np_owner(const struct wk_image *im,size_t ref,int arm,struct np_function *f) {
    struct wk_range r=wk_code(im,ref);
    if(!r.end) return -1;
    size_t step=arm?4:2,lo=ref-r.start>32768?ref-32768:r.start;
    size_t p=ref&~(step-1),start=SIZE_MAX;
    for(;;) {
        if(np_prologue(im,p,arm)) {start=p;break;}
        if(p<lo+step) break;
        p-=step;
    }
    if(start==SIZE_MAX) return -1;
    /* Bound the owner at its return or the next function's prologue. */
    size_t end=r.end;
    for(p=ref+step;p+4<=r.end;p+=np_width(im,p,arm)) {
        uint32_t w=read_le32(im->b+p);uint16_t h=wk_u16(im,p);
        int ret=arm?((w&0xffff8080)==0xe8bd8080):
            ((h&0xff80)==0xbd80 || (h==0xe8bd && (wk_u16(im,p+2)&0x8080)==0x8080));
        if(ret) {end=p+np_width(im,p,arm);break;}
        if(np_prologue(im,p,arm)) {end=p;break;}
    }
    if(end-start>65536) return -1;
    *f=(struct np_function){r,start,end,arm};return 0;
}
static int np_reference(const struct wk_image *im,const char *text,
                        struct np_function *f,size_t *ref,int optional) {
    size_t s=wk_string(im,text,0);
    if(s==SIZE_MAX) {
        /* Match a complete diagnostic prefix without backing up through a
         * preceding literal pool when the string is not NUL-aligned. */
        const unsigned char *p=memmem(im->b,im->len,text,strlen(text));
        if(!p) return optional?1:-1;
        s=(size_t)(p-im->b);
        if(memmem(p+strlen(text),im->len-s-strlen(text),text,strlen(text))) return -1;
    }
    struct wk_refs refs=wk_refs_to(im,wk_va(im,s)),ar={{0},0,0};
    wk_arm_references(&ar,im,wk_va(im,s));
    size_t found=SIZE_MAX;struct np_function chosen={0};
    if(refs.overflow || ar.overflow) return -1;
    for(unsigned mode=0;mode<2;mode++) {
        struct wk_refs *r=mode?&ar:&refs;
        for(size_t j=0;j<r->count;j++) {
            struct np_function owner;
            if(np_owner(im,r->positions[j],mode,&owner)) continue;
            if(f->end && (owner.start!=f->start || (int)mode!=f->arm ||
                          r->positions[j]<f->start || r->positions[j]>=f->end)) continue;
            if(found!=SIZE_MAX && (found!=r->positions[j] || chosen.arm!=(int)mode)) return -1;
            found=r->positions[j];chosen=owner;
        }
    }
    if(found==SIZE_MAX) return -1;
    if(!f->end) *f=chosen;
    *ref=found;return 0;
}
static int np_previous_call(const struct wk_image *im,const struct np_function *f,
                             size_t ref,size_t distance,struct np_call *call) {
    size_t last=SIZE_MAX;
    for(size_t p=f->start;p<ref;p+=np_width(im,p,f->arm)) {
        struct np_call c;
        if(np_call_at(im,p,f->arm,&c)) {last=p;*call=c;}
    }
    return last!=SIZE_MAX && ref-last<=distance ? 0:-1;
}
static size_t np_conditional(const struct wk_image *im,size_t p,int arm) {
    if(arm) {
        uint32_t w=read_le32(im->b+p);
        if((w&0x0f000000)!=0x0a000000 || (w>>28)>=14) return SIZE_MAX;
        return wk_off(im,wk_va(im,p)+8+(uint32_t)wk_signed((w&0xffffff)<<2,26));
    }
    int kind;size_t to=wk_branch(im,p,&kind);return kind==1?to:SIZE_MAX;
}
static int np_straight(const struct wk_image *im,const struct np_function *f,size_t from,size_t end) {
    if(from>end || from<f->start || end>=f->end) return 0;
    for(size_t p=from;p<end;p+=np_width(im,p,f->arm)) {
        struct np_call c;if(np_call_at(im,p,f->arm,&c)) return 0;
        if(f->arm) {
            if((read_le32(im->b+p)&0x0e000000)==0x0a000000) return 0;
        } else {int kind;(void)wk_branch(im,p,&kind);if(kind) return 0;}
    }
    return 1;
}
static int np_checked_call(const struct wk_image *im,const struct np_function *f,
                            size_t ref,struct np_call *call) {
    /* Require a result check to distinguish the formatter from a logging call. */
    int found=0;
    for(size_t at=f->start;at<ref;at+=np_width(im,at,f->arm)) {
        struct np_call candidate;
        if(ref-at>112 || !np_call_at(im,at,f->arm,&candidate)) continue;
        int zero=0;unsigned result_regs=1;
        for(size_t p=at+candidate.width;p<ref;p+=np_width(im,p,f->arm)) {
            struct np_call next;if(np_call_at(im,p,f->arm,&next)) break;
            if(f->arm) {
                uint32_t w=read_le32(im->b+p);
                unsigned rd=(w>>12)&15,rn=(w>>16)&15;
                if((w&0xfff0ffff)==0xe3500000 && (result_regs&(1u<<rn))) zero=1;
                if((w&0xfff00fff)==0xe2500000 && (result_regs&(1u<<rn))) {
                    zero=1;result_regs|=1u<<rd;
                }
                if((w&0x0fe0fff0)==0x01a00000) {
                    if(result_regs&(1u<<(w&15))) result_regs|=1u<<rd;
                    else result_regs&=~(1u<<rd);
                } else if((w&0x0c100000)==0x04100000 || (w&0x0fe00000)==0x03a00000)
                    result_regs&=~(1u<<rd);
            } else {
                uint16_t a=wk_u16(im,p);
                if((a&0xf8ff)==0x2800 && (result_regs&(1u<<((a>>8)&7)))) zero=1;
                if((a&0xf500)==0xb100 && (result_regs&(1u<<(a&7)))) zero=1;
                if((a&0xff00)==0x4600) {
                    unsigned rd=(a&7)|((a>>4)&8),rn=(a>>3)&15;
                    if(result_regs&(1u<<rn)) result_regs|=1u<<rd;
                    else result_regs&=~(1u<<rd);
                } else if((a&0xf800)==0x2000) result_regs&=~(1u<<((a>>8)&7));
                else if((a&0xf800)==0x4800) result_regs&=~(1u<<((a>>8)&7));
                else if(a==0xf8df || a==0xf85f) result_regs&=~(1u<<(wk_u16(im,p+2)>>12));
            }
            size_t to=np_conditional(im,p,f->arm);
            size_t success=(to<=ref && to>p)?to:p+np_width(im,p,f->arm);
            if(zero && to>=f->start && to<f->end &&
               (to>ref || to<at || (to<=ref && ref-to<=8)) &&
               np_straight(im,f,success,ref)) {
                if(found) return -1;
                *call=candidate;found=1;break;
            }
        }
    }
    return found?0:-1;
}
static int np_result(const struct wk_image *im,const struct np_function *f,
                      struct np_call call,unsigned value,const char *name) {
    unsigned char bytes[4];
    if(f->arm) {
        uint32_t w=0xe3a00000|value;memcpy(bytes,&w,4);
    } else {
        bytes[0]=(unsigned char)value;bytes[1]=0x20;bytes[2]=0xc0;bytes[3]=0x46;
    }
    return kp_add(call.off,wk_va(im,call.off),bytes,call.width,name,0);
}
static int np_jump(const struct wk_image *im,const struct np_function *f,
                    size_t from,size_t to,const char *name) {
    if(from<f->start || from>=f->end || to<f->start || to>=f->end) return -1;
    unsigned char bytes[4];size_t length;
    int64_t d=(int64_t)wk_va(im,to)-wk_va(im,from)-(f->arm?8:4);
    if(f->arm) {
        if((d&3) || d<-(INT64_C(1)<<25) || d>=(INT64_C(1)<<25)) return -1;
        uint32_t w=0xea000000|((uint32_t)(d/4)&0xffffff);memcpy(bytes,&w,4);length=4;
    } else if(!(d&1) && d>=-2048 && d<=2046) {
        uint16_t h=0xe000|((uint32_t)(d/2)&0x7ff);
        bytes[0]=h;bytes[1]=h>>8;length=2;
    } else {
        if((d&1) || im->subtype==6 || d<-(INT64_C(1)<<24) || d>=(INT64_C(1)<<24)) return -1;
        unsigned u=(unsigned)d,s=(u>>24)&1,i1=(u>>23)&1,i2=(u>>22)&1;
        uint16_t a=0xf000|(s<<10)|((u>>12)&1023);
        uint16_t b=0x9000|((!(i1^s))<<13)|((!(i2^s))<<11)|((u>>1)&2047);
        bytes[0]=a;bytes[1]=a>>8;bytes[2]=b;bytes[3]=b>>8;length=4;
        if(np_width(im,from,0)!=4) return -1;
    }
    return kp_add(from,wk_va(im,from),bytes,length,name,0);
}

/* Resolve callback table addresses, including literal and PIC aliases. */
static int np_value(const struct wk_image *im,const struct np_function *f,
                      size_t before,unsigned reg,unsigned depth,uint32_t *value) {
    if(depth>16 || reg>15 || before<f->start || before>f->end || f->end>im->len) return 0;
    size_t step=f->arm?4:2;
    for(size_t p=before;p>=f->start+step;) {
        p-=step;
        if(f->end-p<2 || np_width(im,p,f->arm)>f->end-p) return 0;
        if(f->arm) {
            uint32_t w=read_le32(im->b+p);unsigned rd=(w>>12)&15,rn=(w>>16)&15;
            struct np_call call;
            if(np_call_at(im,p,1,&call) && (reg<4 || reg==12)) return 0;
            if((w&0xfffff000)==(0xe59f0000|(reg<<12)) ||
               (w&0xfffff000)==(0xe51f0000|(reg<<12))) {
                uint32_t pc=wk_va(im,p)+8;
                size_t at=wk_off(im,(w&0x800000)?pc+(w&4095):pc-(w&4095));
                if(at==SIZE_MAX || im->len-at<4) return 0;
                *value=read_le32(im->b+at);return 1;
            }
            if((w&0x0fe0fff0)==0x01a00000 && rd==reg)
                return np_value(im,f,p,w&15,depth+1,value);
            if((w&0x0e000000)==0x02000000 && rd==reg) {
                unsigned rot=((w>>8)&15)*2;uint32_t v=w&255;
                if(rot) v=(v>>rot)|(v<<(32-rot));
                unsigned op=(w>>21)&15;
                if(op==13) {*value=v;return 1;}
                uint32_t base;
                if(rn==15) base=wk_va(im,p)+8;
                else if(!np_value(im,f,p,rn,depth+1,&base)) return 0;
                if(op==4) {*value=base+v;return 1;}
                if(op==2) {*value=base-v;return 1;}
                return 0;
            }
            if(rd==reg && (((w&0x0c100000)==0x04100000) ||
               ((w&0x0c000000)==0 && ((w>>21)&15)<8))) return 0;
        } else {
            uint16_t a=wk_u16(im,p),b=f->end-p>=4?wk_u16(im,p+2):0;
            struct np_call call;
            if(np_call_at(im,p,0,&call) && (reg<4 || reg==12)) return 0;
            unsigned rd;uint32_t v;int high;
            if((a&0xf800)==0x4800 && ((a>>8)&7)==reg) {
                size_t at=wk_off(im,((wk_va(im,p)+4)&~3u)+(a&255)*4);
                if(at==SIZE_MAX || im->len-at<4) return 0;
                *value=read_le32(im->b+at);return 1;
            }
            if((a==0xf8df || a==0xf85f) && (b>>12)==reg) {
                uint32_t pc=(wk_va(im,p)+4)&~3u;
                size_t at=wk_off(im,a==0xf8df?pc+(b&4095):pc-(b&4095));
                if(at==SIZE_MAX || im->len-at<4) return 0;
                *value=read_le32(im->b+at);return 1;
            }
            if(wk_mov(a,b,&rd,&v,&high) && rd==reg) {
                uint32_t low=0;
                if(high && !np_value(im,f,p,reg,depth+1,&low)) return 0;
                *value=high?(low&65535)|(v<<16):v;return 1;
            }
            if((a&0xff78)==0x4478 && ((a&7)|((a>>4)&8))==reg) {
                if(!np_value(im,f,p,reg,depth+1,value)) return 0;
                *value+=wk_va(im,p)+4;return 1;
            }
            if((a&0xff00)==0x4600 && ((a&7)|((a>>4)&8))==reg)
                return np_value(im,f,p,(a>>3)&15,depth+1,value);
            if((a&0xf800)==0x2000 && ((a>>8)&7)==reg) {*value=a&255;return 1;}
            if((a&0xf800)==0xa000 && ((a>>8)&7)==reg) {
                *value=((wk_va(im,p)+4)&~3u)+(a&255)*4;return 1;
            }
            if(((a&0xf800)==0x3000 || (a&0xf800)==0x3800) && ((a>>8)&7)==reg) {
                if(!np_value(im,f,p,reg,depth+1,value)) return 0;
                *value+=(a&0x800)?-(uint32_t)(a&255):(uint32_t)(a&255);return 1;
            }
            if(((a&0xf800)==0x6800 || (a&0xf800)==0x7800 || (a&0xf800)==0x8800) &&
               (a&7)==reg) return 0;
            if((a&0xfff0)==0xf8d0 && (b>>12)==reg) return 0;
            if((a&0xf800)==0x9800 && ((a>>8)&7)==reg) {
                unsigned offset=(a&255)*4;
                for(size_t q=p;q>=f->start+2;) {
                    q-=2;uint16_t s=wk_u16(im,q),t=wk_u16(im,q+2);
                    if((s&0xf800)==0x9000 && (s&255)*4==offset)
                        return np_value(im,f,q,(s>>8)&7,depth+1,value);
                    if(s==0xf8cd && (t&4095)==offset)
                        return np_value(im,f,q,t>>12,depth+1,value);
                    /* Stack displacements are valid only within the same
                     * fixed-size frame. Do not trace through another SP move. */
                    if((s&0xff00)==0xb000 || (s&0xfe00)==0xbc00) return 0;
                }
                return 0;
            }
        }
    }
    return 0;
}
struct np_expression { int table; size_t target; uint32_t base,slot; };
/* Merge constants across the CFG to resolve spills separated by error blocks. */
#define NP_VALUES 80
struct np_state { uint32_t value[NP_VALUES]; unsigned char known[NP_VALUES]; int reached; };
struct np_node { size_t off; struct np_state in; };
static struct { struct np_node *nodes; size_t count,start; } np_cfg;
static void np_unknown(struct np_state *s,unsigned r) {if(r<NP_VALUES) s->known[r]=0;}
static void np_constant(struct np_state *s,unsigned r,uint32_t v) {
    if(r<NP_VALUES) {s->known[r]=1;s->value[r]=v;}
}
static void np_copy(struct np_state *s,unsigned rd,unsigned rn) {
    if(rd>=NP_VALUES || rn>=NP_VALUES) return;
    s->known[rd]=s->known[rn];s->value[rd]=s->value[rn];
}
static size_t np_node_at(size_t off) {
    size_t lo=0,hi=np_cfg.count;
    while(lo<hi) {size_t m=lo+(hi-lo)/2;if(np_cfg.nodes[m].off<off) lo=m+1;else hi=m;}
    return lo<np_cfg.count && np_cfg.nodes[lo].off==off?lo:SIZE_MAX;
}
static int np_merge(struct np_state *dst,const struct np_state *src) {
    if(!dst->reached) {*dst=*src;dst->reached=1;return 1;}
    int change=0;
    for(unsigned r=0;r<NP_VALUES;r++) if(dst->known[r] &&
       (!src->known[r] || dst->value[r]!=src->value[r])) {dst->known[r]=0;change=1;}
    return change;
}
static void np_transfer(const struct wk_image *im,const struct np_function *f,size_t p,
                         struct np_state *s) {
    struct np_call call;
    if(np_call_at(im,p,f->arm,&call)) {
        for(unsigned r=0;r<4;r++) np_unknown(s,r);
        np_unknown(s,12);return;
    }
    if(f->arm) {
        uint32_t w=read_le32(im->b+p);unsigned rd=(w>>12)&15,rn=(w>>16)&15;
        if((w&0x0fff0000)==0x059f0000 || (w&0x0fff0000)==0x051f0000) {
            uint32_t pc=wk_va(im,p)+8;size_t at=wk_off(im,(w&0x800000)?pc+(w&4095):pc-(w&4095));
            np_unknown(s,rd);if(at!=SIZE_MAX && im->len-at>=4) np_constant(s,rd,read_le32(im->b+at));
        } else if((w&0x0fe0fff0)==0x01a00000) np_copy(s,rd,w&15);
        else if((w&0x0e000000)==0x02000000) {
            unsigned op=(w>>21)&15,rot=((w>>8)&15)*2;uint32_t v=w&255;
            if(rot) v=(v>>rot)|(v<<(32-rot));
            if(op==13) np_constant(s,rd,v);
            else if(op==4 && (rn==15 || s->known[rn])) np_constant(s,rd,(rn==15?wk_va(im,p)+8:s->value[rn])+v);
            else if(op!=8 && op!=9 && op!=10 && op!=11) np_unknown(s,rd);
        } else if((w&0x0c100000)==0x04100000) np_unknown(s,rd);
        return;
    }
    uint16_t a=wk_u16(im,p),b=f->end-p>=4?wk_u16(im,p+2):0;
    unsigned rd;uint32_t v;int high;
    int kind;(void)wk_branch(im,p,&kind);if(kind) return;
    if((a&0xf800)==0x4800 || a==0xf8df || a==0xf85f) {
        uint32_t pc=(wk_va(im,p)+4)&~3u;
        rd=(a&0xf800)==0x4800?(a>>8)&7:b>>12;
        size_t at=wk_off(im,(a&0xf800)==0x4800?pc+(a&255)*4:a==0xf8df?pc+(b&4095):pc-(b&4095));
        np_unknown(s,rd);if(at!=SIZE_MAX && im->len-at>=4) np_constant(s,rd,read_le32(im->b+at));
    } else if(wk_mov(a,b,&rd,&v,&high)) {
        if(!high) np_constant(s,rd,v);
        else if(s->known[rd]) np_constant(s,rd,(s->value[rd]&65535)|(v<<16));
    } else if((a&0xff78)==0x4478) {
        rd=(a&7)|((a>>4)&8);if(s->known[rd]) s->value[rd]+=wk_va(im,p)+4;
    } else if((a&0xff00)==0x4600) np_copy(s,(a&7)|((a>>4)&8),(a>>3)&15);
    else if((a&0xf800)==0x2000) np_constant(s,(a>>8)&7,a&255);
    else if((a&0xf800)==0xa000) np_constant(s,(a>>8)&7,((wk_va(im,p)+4)&~3u)+(a&255)*4);
    else if((a&0xf800)==0x9000 || (a&0xf800)==0x9800) {
        unsigned slot=16+(a&255);rd=(a>>8)&7;
        if(slot>=NP_VALUES) {if(a&0x800) np_unknown(s,rd);}
        else if(a&0x800) np_copy(s,rd,slot);else np_copy(s,slot,rd);
    } else if(a==0xf8cd || a==0xf8dd) {
        unsigned off=b&4095,slot=16+off/4;rd=b>>12;
        if(off%4 || slot>=NP_VALUES) {if(a==0xf8dd) np_unknown(s,rd);}
        else if(a==0xf8dd) np_copy(s,rd,slot);else np_copy(s,slot,rd);
    } else if((a&0xf800)==0x3000 || (a&0xf800)==0x3800) {
        rd=(a>>8)&7;if(s->known[rd]) s->value[rd]+=(a&0x800)?-(uint32_t)(a&255):(a&255);
    } else if((a&0xf800)==0x6800 || (a&0xf800)==0x7800 || (a&0xf800)==0x8800) np_unknown(s,a&7);
    else if((a&0xfff0)==0xf8d0) np_unknown(s,b>>12);
    else if((a&0xf800)==0x1800 || (a&0xe000)==0) np_unknown(s,a&7);
    else if((a&0xfc00)==0x4000 && ((a>>6)&15)!=8 && ((a>>6)&15)!=10 && ((a>>6)&15)!=11) np_unknown(s,a&7);
    else if(wk_width(im,p)==4 && (a&0xfe00)==0xf000) np_unknown(s,(b>>8)&15);
}
static int np_cfg_value(const struct wk_image *im,const struct np_function *f,
                         size_t at,unsigned reg,uint32_t *value) {
    if(f->start>=f->end || f->end>im->len) return 0;
    if(!np_cfg.nodes) {
        size_t count=0;
        for(size_t p=f->start;p<f->end;) {
            if(f->end-p<2) return 0;
            size_t width=np_width(im,p,f->arm);
            if(width>f->end-p) return 0;
            count++;p+=width;
        }
        if(!count || count>16384) return 0;
        np_cfg.nodes=calloc(count,sizeof(*np_cfg.nodes));if(!np_cfg.nodes) return 0;
        np_cfg.count=count;np_cfg.start=f->start;
        size_t i=0;for(size_t p=f->start;p<f->end;p+=np_width(im,p,f->arm)) np_cfg.nodes[i++].off=p;
        np_cfg.nodes[0].in.reached=1;
        int change=1;size_t rounds=0;
        while(change && rounds++<count*2) {
            change=0;
            for(i=0;i<count;i++) {
                struct np_node *node=&np_cfg.nodes[i];if(!node->in.reached) continue;
                size_t p=node->off;struct np_state out=node->in;
                np_transfer(im,f,p,&out);
                int kind=0;size_t to=SIZE_MAX;
                uint32_t w=f->arm?read_le32(im->b+p):0;
                uint16_t a=wk_u16(im,p);
                struct np_call call;int iscall=np_call_at(im,p,f->arm,&call);
                if(f->arm) {
                    if(!iscall && (w&0x0f000000)==0x0a000000) {
                        kind=(w>>28)==14?2:1;
                        to=wk_off(im,wk_va(im,p)+8+(uint32_t)wk_signed((w&0xffffff)<<2,26));
                    }
                } else if(!iscall) to=wk_branch(im,p,&kind);
                int ret=f->arm?((w&0xffff8000)==0xe8bd8000 || w==0xe12fff1e):
                    ((a&0xff00)==0xbd00 || a==0x4770 || (a==0xe8bd && (wk_u16(im,p+2)&0x8000)));
                if(kind) {size_t j=np_node_at(to);if(j!=SIZE_MAX) change|=np_merge(&np_cfg.nodes[j].in,&out);}
                if(kind!=2 && !ret && i+1<count) change|=np_merge(&np_cfg.nodes[i+1].in,&out);
            }
        }
        if(change) return 0;
    }
    size_t i=np_node_at(at);
    if(np_cfg.start!=f->start || i==SIZE_MAX || reg>=16 || !np_cfg.nodes[i].in.reached ||
       !np_cfg.nodes[i].in.known[reg]) return 0;
    *value=np_cfg.nodes[i].in.value[reg];return 1;
}
static int np_provider_table(const struct wk_image *im,const struct np_function *f,
                              size_t load,unsigned base,struct np_expression *e) {
    /* FIL uses a runtime provider table. Equal slots in FIL and WMR tables
     * do not identify the same callback. */
    if(f->arm || base!=0) return 0;
    struct np_call getter;
    if(np_previous_call(im,f,load,8,&getter) || getter.off+getter.width!=load ||
       getter.target==SIZE_MAX || !wk_code(im,getter.target).end) return 0;
    size_t p=getter.target;
    if(p>im->len || im->len-p<24 || (wk_u16(im,p)&0xff00)!=0x4800) return 0;
    p+=2;if(wk_u16(im,p)==0x4478) p+=2;
    int self=wk_u16(im,p)==0x6800 && wk_u16(im,p+2)==0x2800 &&
        wk_u16(im,p+4)==0xbf18 && (wk_u16(im,p+6)&0xfbff)==0xf100 &&
        ((wk_u16(im,p+8)>>8)&15)==0 && wk_u16(im,p+10)==0x4770;
    if(!self && (wk_u16(im,p)!=0x6801 || (wk_u16(im,p+2)&0xfbff)!=0xf101 ||
       ((wk_u16(im,p+4)>>8)&15)!=0 || wk_u16(im,p+6)!=0x2900 ||
       wk_u16(im,p+8)!=0xbf08 ||
       (wk_u16(im,p+10)!=0x4608 && wk_u16(im,p+10)!=0x2000) ||
       wk_u16(im,p+12)!=0x4770)) return 0;
    e->table=2;e->base=wk_va(im,getter.target);return 1;
}
static int np_expression(const struct wk_image *im,const struct np_function *f,
                          struct np_call call,struct np_expression *e) {
    memset(e,0,sizeof(*e));
    if(call.target!=SIZE_MAX) {e->target=wk_resolve(im,call.target);return 1;}
    if(call.indirect==2) {
        e->slot=call.slot;e->table=1;
        return np_value(im,f,call.off,call.base,0,&e->base) || np_cfg_value(im,f,call.off,call.base,&e->base);
    }
    /* Find the table load preceding BLX. */
    size_t lo=call.off-f->start>32?call.off-32:f->start;
    size_t step=f->arm?4:2;
    for(size_t p=call.off;p>=lo+step;) {
        p-=step;unsigned base=16,slot=0;
        if(f->arm) {
            uint32_t w=read_le32(im->b+p);
            if((w&0xfff0f000)==(0xe5900000|(call.base<<12))) {
                base=(w>>16)&15;slot=w&4095;
            }
        } else {
            uint16_t a=wk_u16(im,p),b=wk_u16(im,p+2);
            if(((a&0xf800)==0x4800 && ((a>>8)&7)==call.base) ||
               ((a==0xf8df || a==0xf85f) && (b>>12)==call.base)) {
                uint32_t v;
                if(!np_value(im,f,p+wk_width(im,p),call.base,0,&v)) return 0;
                e->target=wk_resolve(im,wk_off(im,v&~1u));return e->target!=SIZE_MAX;
            }
            if((a&0xf800)==0x6800 && (a&7)==call.base) {base=(a>>3)&7;slot=((a>>6)&31)*4;}
            else if((a&0xfff0)==0xf8d0 && b>>12==call.base) {base=a&15;slot=b&4095;}
        }
        if(base==15) {
            uint32_t v;
            if(!np_value(im,f,p+step,call.base,0,&v)) return 0;
            e->target=wk_resolve(im,wk_off(im,v&~1u));return e->target!=SIZE_MAX;
        }
        if(base<15) {
            e->table=1;e->slot=slot;
            return np_value(im,f,p,base,0,&e->base) || np_cfg_value(im,f,p,base,&e->base) ||
                   np_provider_table(im,f,p,base,e);
        }
    }
    uint32_t value;
    if(np_value(im,f,call.off,call.base,0,&value)) {
        e->target=wk_off(im,value&~1u);return e->target!=SIZE_MAX;
    }
    return 0;
}
static int np_same_expression(struct np_expression a,struct np_expression b) {
    return a.table==b.table && (a.table?(a.base==b.base && a.slot==b.slot):a.target==b.target);
}
static int np_format_calls(const struct wk_image *im,const struct np_function *f,
                            struct np_call format,unsigned failure,const char *name) {
    struct np_expression expression;
    if(!np_expression(im,f,format,&expression)) return -1;
    size_t count=0;
    for(size_t p=f->start;p<f->end;p+=np_width(im,p,f->arm)) {
        struct np_call c;struct np_expression other;
        if(!np_call_at(im,p,f->arm,&c)) continue;
        if(!np_expression(im,f,c,&other)) {
            if(other.table==1 && expression.table==1 && other.slot==expression.slot) return -1;
            continue;
        }
        if(!np_same_expression(expression,other)) continue;
        if(np_result(im,f,c,failure,name)) return -1;
        count++;
    }
    return count?0:-1;
}
static int np_production_checked(const struct wk_image *im,const struct np_function *f,
                                  struct np_call call) {
    int compared=0;
    for(size_t p=call.off+call.width;p<f->end && p-call.off<32;p+=np_width(im,p,f->arm)) {
        struct np_call next;if(np_call_at(im,p,f->arm,&next)) break;
        if(f->arm) {if(read_le32(im->b+p)==0xe3500001) compared=1;}
        else if(wk_u16(im,p)==0x2801) compared=1;
        size_t to=np_conditional(im,p,f->arm);
        if(compared && to>=f->start && to<f->end) return 1;
    }
    return 0;
}
static int np_signature_writes(const struct wk_image *im,const struct np_function *f,
                                size_t failure_call) {
    struct np_function owner=*f;size_t ref;
    int failed=np_reference(im,"[FTL:MSG] Write Signature Failed 0x%08X",&owner,&ref,1);
    struct np_call writer;int found=0;
    if(failed<0) return -1;
    if(!failed) {
        /* The success path can copy metadata before logging. Use the failure
         * diagnostic to distinguish the writer from those later calls. */
        for(size_t p=f->start;p<ref;p+=np_width(im,p,f->arm)) {
            size_t to=np_conditional(im,p,f->arm);
            if(to!=SIZE_MAX && to<=ref && ref-to<=24 && np_straight(im,f,to,ref)) {
                struct np_call c;
                if(np_previous_call(im,f,p,28,&c)) continue;
                if(found && writer.off!=c.off) return -1;
                writer=c;found=1;
            }
        }
    } else {
        if(np_reference(im,"[FTL:MSG] Write Signature\t\t[OK]",&owner,&ref,0) ||
           np_previous_call(im,f,ref,80,&writer)) return -1;
        found=1;
    }
    struct np_expression expression;
    if(!found || !np_expression(im,f,writer,&expression)) return -1;
    size_t count=0;
    for(size_t p=f->start;p<f->end;p+=np_width(im,p,f->arm)) {
        struct np_call c;struct np_expression other;
        if(!np_call_at(im,p,f->arm,&c)) continue;
        if(!np_expression(im,f,c,&other)) {
            if(other.table==1 && expression.table==1 && other.slot==expression.slot) return -1;
            continue;
        }
        if(!np_same_expression(expression,other)) continue;
        if(np_jump(im,f,p,failure_call,"Reject NAND signature writes during initialization")) return -1;
        count++;
    }
    return count?0:-1;
}

static int np_preserve(struct wk_image *im) {
    if(im->subtype==12) return kp_unsupported("NAND preservation does not apply to watchOS");
    struct np_function f={0};size_t vfl,ftl,production,factory,epoch;
    const char *vfl_text="[FTL:MSG] VFL_Format";
    const char *ftl_text="[FTL:MSG] FTL_Format";
    if(np_reference(im,vfl_text,&f,&vfl,0)) {
        return kp_unsupported("Cannot identify one NAND initializer and its format result checks");
    }
    struct np_call vfl_call,ftl_call,prod_call;
    if(np_checked_call(im,&f,vfl,&vfl_call)) return kp_unsupported("NAND VFL format failure path is unresolved");
    if(np_format_calls(im,&f,vfl_call,1,"Reject automatic NAND VFL formatting"))
        return kp_unsupported("NAND VFL formatter and its initializer call sites are unresolved");
    int r=np_reference(im,"[WMR:INF] Calling VFL_ProductionFormat()",&f,&production,0);
    if(r) return kp_unsupported("NAND production format path is unresolved");
    if(!r) {
        /* ProductionFormat returns one on success, unlike VFL/FTL_Format. */
        size_t after=production;int calls=0;
        for(size_t p=production;p<f.end && p-production<96;p+=np_width(im,p,f.arm)) {
            struct np_call c;
            if(np_call_at(im,p,f.arm,&c) && ++calls==2) {prod_call=c;after=p;break;}
        }
        if(after==production || !np_production_checked(im,&f,prod_call) ||
           np_format_calls(im,&f,prod_call,0,"Reject automatic NAND production formatting"))
            return kp_unsupported("NAND production formatter and its initializer call sites are unresolved");
    }
    r=np_reference(im,"[FTL:MSG] Calling VFL_FactoryReformat()",&f,&factory,0);
    if(r) return kp_unsupported("NAND factory reformat path is unresolved");
    if(!r && np_jump(im,&f,factory,vfl_call.off,"Reject automatic NAND factory reformatting")) return -1;
    r=np_reference(im,"[WMR:INF] Epoch update in progress.",&f,&epoch,1);
    if(r<0) return kp_unsupported("NAND epoch migration path is ambiguous");
    if(!r) {
        size_t guard=SIZE_MAX,lo=epoch-f.start>112?epoch-112:f.start;
        for(size_t p=f.start;p<epoch;p+=np_width(im,p,f.arm)) if(p>=lo) {
            int match=f.arm?read_le32(im->b+p)==0xe3a00064:wk_u16(im,p)==0x2064;
            if(match) {if(guard!=SIZE_MAX) return -1;guard=p;}
        }
        if(guard==SIZE_MAX || np_jump(im,&f,guard,vfl_call.off,"Reject NAND epoch migration before its first mutation")) return -1;
    }
    if(np_reference(im,ftl_text,&f,&ftl,1)==1)
        ftl_text="[FTL:MSG] FTL Format";
    if(np_reference(im,ftl_text,&f,&ftl,0) || np_checked_call(im,&f,ftl,&ftl_call) ||
       np_format_calls(im,&f,ftl_call,1,"Reject automatic NAND FTL formatting"))
        return kp_unsupported("NAND FTL format failure path is unresolved");
    r=np_reference(im,"[WMR:INF] Converting NAND from N36 NAND format to P2 NAND format - Start",&f,&epoch,1);
    if(r<0 || (!r && np_jump(im,&f,epoch,vfl_call.off,"Reject legacy NAND format conversion"))) return -1;
    if(np_signature_writes(im,&f,vfl_call.off))
        return kp_unsupported("NAND signature writer and all initializer call sites are unresolved");
    return 0;
}
static int wk_nand_preserve(struct wk_image *im) {
    memset(&np_cfg,0,sizeof(np_cfg));
    int result=np_preserve(im);
    free(np_cfg.nodes);memset(&np_cfg,0,sizeof(np_cfg));return result;
}
