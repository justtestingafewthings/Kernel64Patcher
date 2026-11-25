/* Bounded NOR user-client extension. The requested region and offset are
 * checked against the provider's own region size before any operation. */
#include "nor_read_payload.h"
#include "nor_read_2107_payload.h"
#include "nor_read_legacy_payload.h"
#include "nor_bootblock_payload.h"
#include "nor_commit_payload.h"
#include "nor_flash_boot_payload.h"
#include "nor_flash_early_payload.h"
#include "nor_read_arm_payload.h"
#include "nor_read_armv6_payload.h"

static void nor_u32(unsigned char *p,uint32_t v) {
    p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8);
    p[2]=(unsigned char)(v>>16); p[3]=(unsigned char)(v>>24);
}
static int nor_add_payload(size_t offset,uint32_t address,const unsigned char *data,
                           size_t size,const char *name) {
    for(size_t at=0;at<size;at+=sizeof(kp.edits[0].after)) {
        size_t count=size-at;
        if(count>sizeof(kp.edits[0].after)) count=sizeof(kp.edits[0].after);
        if(kp_add(offset+at,address+(uint32_t)at,data+at,count,name,0)) return -1;
    }
    return 0;
}
static int nor_cave(const struct wk_image *im,size_t need,size_t *out);
static int nor_branch32(uint32_t from,uint32_t to,int link,unsigned char *out) {
    int64_t d=(int64_t)to-(int64_t)from-4;
    if ((d&1) || d < -(INT64_C(1)<<24) || d >= (INT64_C(1)<<24)) return -1;
    uint32_t x=(uint32_t)d&0x01ffffffu;
    unsigned s=(x>>24)&1,i1=(x>>23)&1,i2=(x>>22)&1;
    unsigned j1=!(i1^s),j2=!(i2^s);
    uint16_t a=(uint16_t)(0xf000u|(s<<10)|((x>>12)&0x3ff));
    uint16_t b=(uint16_t)((link?0xd000u:0x9000u)|(j1<<13)|(j2<<11)|((x>>1)&0x7ff));
    out[0]=(unsigned char)a;out[1]=(unsigned char)(a>>8);
    out[2]=(unsigned char)b;out[3]=(unsigned char)(b>>8);
    return 0;
}
static int nor_class_module(const struct wk_image *im,struct wk_module *module,const char *name) {
    size_t name_size=strlen(name)+1;
    int found=0;
    for(size_t i=0;i<im->nmodules;i++) {
        struct wk_module m=im->modules[i];
        if(m.strings.end<=m.strings.start ||
           !memmem(im->b+m.strings.start,m.strings.end-m.strings.start,name,name_size)) continue;
        if(found) {
            if(m.text.start==module->text.start && m.text.end==module->text.end &&
               m.strings.start==module->strings.start && m.strings.end==module->strings.end)
                continue;
            return -1;
        }
        found=1;
        *module=m;
    }
    return found==1 ? 0 : -1;
}
static size_t nor_vtable_slot(const struct wk_image *im,struct wk_module module,uint32_t method) {
    size_t found=SIZE_MAX,limit=module.header+0x10000;
    if(limit<module.header || limit>im->len) limit=im->len;
    if(module.header+28<im->len) {
        uint32_t count=read_le32(im->b+module.header+16);
        uint32_t commands=read_le32(im->b+module.header+20);
        size_t p=module.header+28,end=p+commands,extent=0;
        if(count<=128 && end<=im->len) for(uint32_t i=0;i<count && p+8<=end;i++) {
            uint32_t cmd=read_le32(im->b+p),size=read_le32(im->b+p+4);
            if(size<8 || size>end-p) break;
            if(cmd==1 && size>=56) {
                uint32_t fo=read_le32(im->b+p+32),fs=read_le32(im->b+p+36);
                if((uint64_t)fo+fs<0x10000 && extent<fo+fs) extent=fo+fs;
            }
            p+=size;
        }
        if(extent && module.header+extent<limit) limit=module.header+extent;
    }
    for(size_t p=module.header;p+4<=limit;p+=4) {
        if(read_le32(im->b+p)!=method || wk_in(module.text,p,4) || !wk_va(im,p)) continue;
        if(found!=SIZE_MAX) return SIZE_MAX;
        found=p;
    }
    return found;
}
static size_t nor_flash_vtable_slot(const struct wk_image *im,struct wk_module module,uint32_t method) {
    size_t found=SIZE_MAX;
    size_t limit=module.header+0x20000;
    if(limit<module.header || limit>im->len) limit=im->len;
    for(size_t p=module.header;p+4<=limit;p+=4) {
        if(read_le32(im->b+p)!=method || wk_in(module.text,p,4) || !wk_va(im,p)) continue;
        if(found!=SIZE_MAX) return SIZE_MAX;
        found=p;
    }
    return found;
}
static size_t nor_code_pattern(const struct wk_image *im,struct wk_range code,
                               const unsigned char *pattern,size_t length) {
    size_t found=SIZE_MAX;
    for(size_t p=code.start;p+length<=code.end;p+=2) {
        if(memcmp(im->b+p,pattern,length)) continue;
        if(found!=SIZE_MAX) return SIZE_MAX;
        found=p;
    }
    return found;
}
static size_t nor_boot_page_site(const struct wk_image *im,struct wk_range code) {
    size_t found=SIZE_MAX;
    for(size_t p=code.start+2;p+24<=code.end;p+=2) {
        /* hostReadBootPage: backend at +0x44, virtual read at +0x2e0.
         * The register allocation changes between iOS releases. */
        int old=(im->b[p]==0xd1 && im->b[p+1]==0xf8 &&
                 im->b[p+2]==0xe0 && im->b[p+3]==0x62);
        int modern=(im->b[p]==0xd0 && im->b[p+1]==0xf8 &&
                    im->b[p+2]==0xe0 && im->b[p+3]==0x62);
        if(!old && !modern) continue;
        int backend=0,call=0,mode=0;
        size_t start=p>code.start+24 ? p-24:code.start;
        for(size_t q=start;q+2<=p;q+=2) {
            if(wk_u16(im,q)==(old ? 0x6c61:0x6c60)) backend=1;
            if(wk_u16(im,q)==0x2105) mode=1;
        }
        for(size_t q=p+4;q+2<=p+20;q+=2)
            if(wk_u16(im,q)==0x47b0) call=1;
        if(!backend || !mode || !call) continue;
        if(found!=SIZE_MAX) return SIZE_MAX;
        found=p;
    }
    return found;
}
static size_t nor_early_dispatcher(const struct wk_image *im,struct wk_range code) {
    size_t found=SIZE_MAX;
    if(im->xnu<1357) {
        for(size_t p=code.start;p+12<=code.end;p+=4)
            if(read_le32(im->b+p)==0xe3510001u && read_le32(im->b+p+4)==0xe92d40f0u &&
               read_le32(im->b+p+8)==0xe1a04000u) {
                if(found!=SIZE_MAX) return SIZE_MAX;
                found=p;
            }
    } else for(size_t p=code.start+2;p+2<=code.end;p+=2) {
        if(wk_u16(im,p)!=0x2903) continue;
        size_t start=p>code.start+32 ? p-32 : code.start;
        for(size_t q=p-2;q>=start+2;q-=2) if(wk_u16(im,q)==0xb5f0) {
            if(found!=SIZE_MAX) return SIZE_MAX;
            found=q;break;
        }
    }
    return found;
}
static int nor_early_physical_1735_verified(const struct wk_image *im,
                                             struct wk_module module) {
    /* The Image3 accessors call the physical provider at these exact slots:
     * size 0x354, read 0x358, write 0x35c. The OOL input mapping moved one
     * vtable slot in XNU 1735. Refuse selector 6 if either layout differs. */
    size_t text=module.text.start;
    if(text+0x16e>module.text.end ||
       read_le32(im->b+text+0x88)!=0x4358f8dcu ||
       read_le32(im->b+text+0xcc)!=0x435cf8dcu ||
       read_le32(im->b+text+0x13a)!=0x3350f8d3u ||
       read_le32(im->b+text+0x16a)!=0x3354f8d3u)
        return 0;
    size_t descriptor=wk_symbol(im,"__ZTV18IOMemoryDescriptor");
    size_t mapping=wk_symbol(im,"__ZTV11IOMemoryMap");
    size_t map=wk_symbol(im,"__ZN18IOMemoryDescriptor3mapEm");
    size_t address=wk_symbol(im,"__ZN11IOMemoryMap17getVirtualAddressEv");
    size_t length=wk_symbol(im,"__ZN11IOMemoryMap9getLengthEv");
    size_t release=wk_symbol(im,"__ZNK8OSObject7releaseEv");
    if(descriptor==SIZE_MAX || mapping==SIZE_MAX || map==SIZE_MAX ||
       address==SIZE_MAX || length==SIZE_MAX || release==SIZE_MAX ||
       descriptor+8+0xac+4>im->len || mapping+8+0x54+4>im->len)
        return 0;
    return read_le32(im->b+descriptor+8+0xac)==(wk_va(im,map)|1u) &&
           read_le32(im->b+mapping+8+0x4c)==(wk_va(im,address)|1u) &&
           read_le32(im->b+mapping+8+0x54)==(wk_va(im,length)|1u) &&
           read_le32(im->b+mapping+8+0x14)==(wk_va(im,release)|1u);
}
static int nor_early_physical_1504_verified(const struct wk_image *im,
                                             struct wk_module module) {
    /* The 4.2.1 ARMv6 Image3 accessors call the physical provider through
     * read 0x358 and write 0x35c. Its OOL descriptor map is at 0xac. */
    size_t text=module.text.start;
    if(text+0xf6>module.text.end ||
       read_le32(im->b+text+0x8e)!=0x23d66d40u ||
       read_le32(im->b+text+0xd2)!=0x23d76d40u ||
       read_le32(im->b+text+0xec)!=0x009b9c06u ||
       read_le32(im->b+text+0xf0)!=0x58d49400u)
        return 0;
    size_t descriptor=wk_symbol(im,"__ZTV18IOMemoryDescriptor");
    size_t mapping=wk_symbol(im,"__ZTV11IOMemoryMap");
    size_t map=wk_symbol(im,"__ZN18IOMemoryDescriptor3mapEm");
    size_t address=wk_symbol(im,"__ZN11IOMemoryMap17getVirtualAddressEv");
    size_t length=wk_symbol(im,"__ZN11IOMemoryMap9getLengthEv");
    size_t release=wk_symbol(im,"__ZNK8OSObject7releaseEv");
    if(descriptor==SIZE_MAX || mapping==SIZE_MAX || map==SIZE_MAX ||
       address==SIZE_MAX || length==SIZE_MAX || release==SIZE_MAX ||
       descriptor+8+0xac+4>im->len || mapping+8+0x54+4>im->len)
        return 0;
    return read_le32(im->b+descriptor+8+0xac)==(wk_va(im,map)|1u) &&
           read_le32(im->b+mapping+8+0x4c)==(wk_va(im,address)|1u) &&
           read_le32(im->b+mapping+8+0x54)==(wk_va(im,length)|1u) &&
           read_le32(im->b+mapping+8+0x14)==(wk_va(im,release)|1u);
}
static int nor_early_bridge(const struct wk_image *im) {
    struct wk_module module;
    int image2=im->xnu<1228;
    const char *class_name=image2 ? "AppleImage2NORAccessUserClient" :
                                     "AppleImage3NORAccessUserClient";
    if(nor_class_module(im,&module,class_name))
        return kp_unsupported("Early NOR user client was not uniquely identified");
    size_t original=image2 ?
        wk_symbol(im,"__ZN12IOUserClient14externalMethodEjP25IOExternalMethodArgumentsP24IOExternalMethodDispatchP8OSObjectPv") :
        nor_early_dispatcher(im,module.text);
    if(original==SIZE_MAX) return kp_unsupported("Early NOR externalMethod dispatcher was not identified");
    uint32_t old_method=wk_va(im,original)|(image2 || im->xnu>=1357 ? 1u:0u);
    size_t slot=nor_vtable_slot(im,module,old_method);
    if(slot==SIZE_MAX) return kp_unsupported("Early NOR externalMethod vtable slot was not identified");
    const unsigned char *stub=NULL;size_t stub_size=0;
    if(im->subtype!=6 && im->subtype!=9 && im->subtype!=11)
        return kp_unsupported("Early NOR bridge CPU subtype was not identified");
    if(image2) {
        if(im->subtype!=6)
            return kp_unsupported("Image2 NOR bridge requires an ARMv6 kernel");
        stub=nor_read_arm_4;stub_size=sizeof nor_read_arm_4;
    } else if(im->xnu<1357) {
        if(im->subtype==6) {stub=nor_read_arm_0_v6;stub_size=sizeof nor_read_arm_0_v6;}
        else {stub=nor_read_arm_0;stub_size=sizeof nor_read_arm_0;}
    } else if(im->xnu<1504) {
        if(im->subtype==6) {stub=nor_read_arm_1_v6;stub_size=sizeof nor_read_arm_1_v6;}
        else {stub=nor_read_arm_1;stub_size=sizeof nor_read_arm_1;}
    } else if(im->xnu<1735) {
        if(im->subtype==6 && im->xnu==1504) {
            stub=nor_read_arm_5_v6;stub_size=sizeof nor_read_arm_5_v6;
        } else if(im->subtype==6) {
            stub=nor_read_arm_2_v6;stub_size=sizeof nor_read_arm_2_v6;
        }
        else {stub=nor_read_arm_2;stub_size=sizeof nor_read_arm_2;}
    } else {
        if(im->subtype==6)
            return kp_unsupported("XNU 1735 NOR bridge has no ARMv6 build");
        stub=nor_read_arm_3;stub_size=sizeof nor_read_arm_3;
    }
    if(im->xnu==1735 && stub_size!=732)
        return kp_unsupported("XNU 1735 NOR bridge size changed");
    if(im->xnu>1735 && (stub_size!=344 || read_le32(stub+0x74)!=0x93500c01u))
        return kp_unsupported("Early NOR read size guard changed");
    size_t flash_original=SIZE_MAX,flash_slot=SIZE_MAX,flash_nand=SIZE_MAX;
    size_t flash_wrap=SIZE_MAX,flash_alloc=SIZE_MAX,flash_free=SIZE_MAX;
    if(im->xnu==1735) {
        struct wk_module flash;
        static const unsigned char dispatcher[]={
            0x80,0xb5,0x00,0xaf,0xc0,0x6f,0x8c,0x46,
            0x28,0xb9,0x0c,0x48,0x0c,0x49,0x0d,0x4b};
        static const unsigned char nand_command[]={
            0xf0,0xb5,0x03,0xaf,0x2d,0xe9,0x00,0x05,
            0x97,0xb0,0x1e,0x46,0x01,0x93,0x1e,0x9b};
        if(!nor_class_module(im,&flash,"IOFlashPartitionSchemeUserClient")) {
            flash_original=nor_code_pattern(im,flash.text,dispatcher,sizeof dispatcher);
            flash_nand=nor_code_pattern(im,flash.text,nand_command,sizeof nand_command);
            if(flash_original!=SIZE_MAX)
                flash_slot=nor_flash_vtable_slot(im,flash,wk_va(im,flash_original)|1u);
            flash_wrap=wk_symbol(im,"__ZN18IOMemoryDescriptor11withAddressEPvm11IODirection");
            flash_alloc=wk_symbol(im,"_IOMallocAligned");
            flash_free=wk_symbol(im,"_IOFreeAligned");
        }
    }
    int flash_bridge=flash_original!=SIZE_MAX && flash_slot!=SIZE_MAX &&
                     flash_nand!=SIZE_MAX && flash_wrap!=SIZE_MAX &&
                     flash_alloc!=SIZE_MAX && flash_free!=SIZE_MAX;
    int physical_write=!image2 && ((im->xnu>=1357 && im->xnu<1504) ||
                                      (im->xnu==1504 && im->subtype==6) ||
                                      im->xnu==1735);
    if(im->xnu==1504 && im->subtype==6 &&
       !nor_early_physical_1504_verified(im,module))
        return kp_unsupported("XNU 1504 ARMv6 physical NOR methods or OOL map differ");
    if(im->xnu==1735 && !nor_early_physical_1735_verified(im,module))
        return kp_unsupported("XNU 1735 physical NOR methods or OOL map differ");
    size_t stub_at=physical_write ? 40:32;
    size_t flash_at=stub_at+stub_size;
    size_t flash_size=flash_bridge ? 12+sizeof nor_flash_early_thumb:0;
    size_t cave;
    if(nor_cave(im,flash_at+flash_size,&cave))
        return kp_unsupported("No verified executable space for early NOR read bridge");
    uint32_t cv=wk_va(im,cave);
    unsigned char *payload=calloc(1,flash_at+flash_size);
    if(!payload) return -1;
    if(physical_write) {
        nor_u32(payload+0,0xe3510004u);  /* read selector */
        nor_u32(payload+4,0x0a000001u);  /* beq payload */
        nor_u32(payload+8,0xe3510006u);  /* physical write selector */
        nor_u32(payload+12,0x1a000001u); /* bne stock method */
        nor_u32(payload+16,0xe59fc008u);
        nor_u32(payload+20,0xe12fff1cu);
        nor_u32(payload+24,0xe59fc004u);
        nor_u32(payload+28,0xe12fff1cu);
        nor_u32(payload+32,cv+(uint32_t)stub_at);
        nor_u32(payload+36,old_method);
    } else {
        nor_u32(payload+0,image2 ? 0xe3510005u:0xe3510004u);
        nor_u32(payload+4,0x1a000001u);  /* bne old method */
        nor_u32(payload+8,0xe59fc008u);  /* ldr ip,stub */
        nor_u32(payload+12,0xe12fff1cu); /* bx ip */
        nor_u32(payload+16,0xe59fc004u); /* ldr ip,old method */
        nor_u32(payload+20,0xe12fff1cu); /* bx ip */
        nor_u32(payload+24,cv+32);
        nor_u32(payload+28,old_method);
    }
    memcpy(payload+stub_at,stub,stub_size);
    if(image2) {
        size_t provider=wk_symbol(im,"__ZNK9IOService11getProviderEv");
        size_t vtable=wk_symbol(im,"__ZTV22AppleARMNORFlashDevice");
        size_t size_method=wk_symbol(im,"__ZN22AppleARMNORFlashDevice13getRegionSizeEm");
        size_t read_method=wk_symbol(im,"__ZN22AppleARMNORFlashDevice10readRegionEmPhmm");
        size_t size_slot=SIZE_MAX;
        if(vtable!=SIZE_MAX && size_method!=SIZE_MAX && read_method!=SIZE_MAX) {
            /* This early kernel stores the vtable symbol itself in the object. */
            for(size_t off=0;off<0x800 && vtable+off+8<=im->len;off+=4)
                if(read_le32(im->b+vtable+off)==(wk_va(im,size_method)|1u) &&
                   read_le32(im->b+vtable+off+4)==(wk_va(im,read_method)|1u)) {
                    if(size_slot!=SIZE_MAX) { size_slot=SIZE_MAX; break; }
                    size_slot=off;
                }
        }
        if(provider==SIZE_MAX || stub_size!=312 || read_le32(stub+0x90)!=0xe1a0200fu ||
           read_le32(stub+0x134)!=0x13579bdfu ||
           read_le32(stub+0xc0)!=0xe5902354u || read_le32(stub+0xc4)!=0xe5908358u ||
           size_slot==SIZE_MAX || size_slot>0xffbu) {
            free(payload);
            return kp_unsupported("Image2 provider read methods were not validated");
        }
        uint32_t runtime_anchor=cv+32+0x98;
        nor_u32(payload+32+0x134,(wk_va(im,provider)|1u)-runtime_anchor);
        nor_u32(payload+32+0xc0,0xe5902000u|(uint32_t)size_slot);
        nor_u32(payload+32+0xc4,0xe5908000u|(uint32_t)(size_slot+4));
    }
    if(flash_bridge) {
        size_t at=flash_at+12;
        const unsigned char *early=nor_flash_early_thumb;
        if(sizeof nor_flash_early_thumb!=284 ||
           early[0x74]!=0xfa || early[0x75]!=0x46 ||
           read_le32(early+0x10c)!=0x0badc0deu ||
           read_le32(early+0x110)!=0x2468ace1u ||
           read_le32(early+0x114)!=0x31415926u ||
           read_le32(early+0x118)!=0x13579bdfu ||
           nor_branch32(cv+(uint32_t)flash_at+4,wk_va(im,flash_original),0,payload+flash_at+4) ||
           nor_branch32(cv+(uint32_t)flash_at+8,cv+(uint32_t)at,0,payload+flash_at+8)) {
            free(payload);
            return kp_unsupported("Early Flash Boot Block bridge layout changed");
        }
        payload[flash_at]=0x0b;payload[flash_at+1]=0x29;
        payload[flash_at+2]=0x01;payload[flash_at+3]=0xd0;
        memcpy(payload+at,early,sizeof nor_flash_early_thumb);
        uint32_t anchor=cv+(uint32_t)at+0x78u;
        nor_u32(payload+at+0x10c,(wk_va(im,flash_nand)|1u)-anchor);
        nor_u32(payload+at+0x110,(wk_va(im,flash_free)|1u)-anchor);
        nor_u32(payload+at+0x114,(wk_va(im,flash_alloc)|1u)-anchor);
        nor_u32(payload+at+0x118,(wk_va(im,flash_wrap)|1u)-anchor);
    }
    unsigned char pointer[4];nor_u32(pointer,cv);
    int failed=nor_add_payload(cave,cv,payload,flash_at+flash_size,"early bounded NOR access selectors") ||
               kp_add(slot,wk_va(im,slot),pointer,4,"NOR externalMethod vtable",1);
    if(!failed && flash_bridge) {
        nor_u32(pointer,cv+(uint32_t)flash_at+1u);
        failed=kp_add(flash_slot,wk_va(im,flash_slot),pointer,4,"Flash Boot Block read method",1);
    }
    if(!failed && image2 && im->xnu==933) {
        /* The 1.0 Image2 writer checks both the 8900 header MAC and the
         * payload signature before parsing the plaintext 2gmI image.
         * Permit a synthetic wrapper while retaining its length checks and
         * the inner Image2 parser. Both sites must match this exact build. */
        static const unsigned char header_mac_check[]={
            0x98,0x00,0x98,0xe5, /* ldr r0,[r8,#0x98] */
            0x00,0x00,0x50,0xe3, /* cmp r0,#0 */
            0x00,0x50,0xa0,0x01, /* moveq r5,r0 */
            0x27,0x00,0x00,0x0a  /* beq verified wrapper shape */
        };
        static const unsigned char signed_payload_check[]={
            0x3c,0xff,0x2f,0xe1, /* blx ip: authenticate payload */
            0x00,0x40,0xa0,0xe1, /* mov r4,r0: save result */
            0x03,0x00,0x00,0xea, /* b cleanup */
            0x00,0x00,0x5b,0xe3  /* cmp fp,#0 */
        };
        size_t header=nor_code_pattern(im,module.text,header_mac_check,
                                       sizeof header_mac_check);
        size_t check=nor_code_pattern(im,module.text,signed_payload_check,
                                      sizeof signed_payload_check);
        if(header==SIZE_MAX || check==SIZE_MAX)
            failed=kp_unsupported("Image2 authentication sites were not uniquely identified");
        else {
            unsigned char accept[4];nor_u32(accept,0xe3a00000u); /* mov r0,#0 */
            failed=kp_add(header,wk_va(im,header),accept,sizeof accept,
                          "Image2 ramdisk wrapper MAC override",0);
            nor_u32(accept,0xe3a04000u); /* mov r4,#0 */
            if(!failed)
                failed=kp_add(check+4,wk_va(im,check+4),accept,sizeof accept,
                              "Image2 ramdisk payload signature override",0);
        }
    }
    free(payload);
    return failed ? -1:0;
}
static size_t nor_wrapper(const struct wk_image *im,struct wk_range code,
                          unsigned physical,unsigned nand) {
    size_t found=SIZE_MAX;
    for(size_t p=code.start;p+64<=code.end;p+=2) {
        if(wk_u16(im,p)!=0xf890 || (wk_u16(im,p+2)&0xfff)!=0x50) continue;
        int a=0,b=0;
        for(size_t q=p+4;q<p+64;q+=2) {
            uint16_t h=wk_u16(im,q),lo=wk_u16(im,q+2);
            if((h&0xfff0)!=0xf8d0) continue;
            if((lo&0xfff)==physical) a=1;
            if((lo&0xfff)==nand) b=1;
        }
        if(a && b) {
            if(found!=SIZE_MAX) return SIZE_MAX;
            if(p>=code.start+6 && wk_u16(im,p-6)==0xb590 &&
               wk_u16(im,p-4)==0xaf01 && wk_u16(im,p-2)==0xb081)
                found=p-6;
            else
                found=p>=code.start+2 && wk_u16(im,p-2)==0xb580 ? p-2 : p;
        }
    }
    return found;
}
static int nor_verified_nand_stage(const struct wk_image *im) {
    struct wk_module nand;
    static const unsigned char staged_write[]={
        0xf0,0xb5,0x03,0xaf,0x4d,0xf8,0x04,0x8d,
        0x04,0x46,0x90,0x46,0x20,0x68,0x0e,0x46,
        0x1d,0x46,0xd0,0xf8,0x4c,0x23,0x20,0x46};
    static const unsigned char finalize[]={
        0xf0,0xb5,0x03,0xaf,0x2d,0xe9,0x00,0x0d,
        0x82,0xb0,0x04,0x46,0x20,0x6e,0x00,0x28,
        0x22,0xd0,0x20,0x68,0x01,0x21,0xd0,0xf8,
        0x70,0x23,0x20,0x46,0x90,0x47,0x05,0x46};
    if(nor_class_module(im,&nand,"AppleNANDFirmware")) return 0;
    size_t write=nor_code_pattern(im,nand.text,staged_write,sizeof staged_write);
    size_t commit=nor_code_pattern(im,nand.text,finalize,sizeof finalize);
    if(write==SIZE_MAX || commit==SIZE_MAX) return 0;
    size_t slot=nor_vtable_slot(im,nand,wk_va(im,write)|1u);
    if(slot==SIZE_MAX || slot<0x378 || slot>im->len-8) return 0;
    size_t table=slot-0x378;
    return read_le32(im->b+table+0x374)==(wk_va(im,write-0x48)|1u) &&
           read_le32(im->b+table+0x370)!=0 &&
           read_le32(im->b+table+0x37c)!=0;
}
/* XNU 2107 has the same NAND firmware transaction, with its virtual methods
 * eight bytes earlier than XNU 2423. Match the iPhone 4 6.1.3 methods and
 * their vtable positions before selecting the older commit stub slots. */
static int nor_verified_nand_commit_613(const struct wk_image *im) {
    struct wk_module nand;
    static const unsigned char commit[]={
        0xb0,0xb5,0x04,0x46,0x02,0xaf,0x20,0x68,
        0xd0,0xf8,0x3c,0x13,0x20,0x46,0x88,0x47};
    static const unsigned char flush[]={
        0xf0,0xb5,0x03,0xaf,0x2d,0xe9,0x00,0x0d,
        0x82,0xb0,0x04,0x46,0x20,0x6e,0x40,0xb9};
    static const unsigned char stage[]={
        0xf0,0xb5,0x03,0xaf,0x4d,0xf8,0x04,0x8d,
        0x04,0x46,0x90,0x46,0x20,0x68,0x1d,0x46,
        0x0e,0x46,0xd0,0xf8,0x44,0x23};
    static const unsigned char llb_stage[]={
        0x90,0xb5,0x04,0x46,0x00,0x20,0xe3,0x6d,
        0x01,0xaf,0x93,0xb9};
    if(im->xnu!=2107 || nor_class_module(im,&nand,"AppleNANDFirmware")) return 0;
    size_t c=nor_code_pattern(im,nand.text,commit,sizeof commit);
    size_t f=nor_code_pattern(im,nand.text,flush,sizeof flush);
    size_t s=nor_code_pattern(im,nand.text,stage,sizeof stage);
    size_t l=nor_code_pattern(im,nand.text,llb_stage,sizeof llb_stage);
    if(c==SIZE_MAX || f==SIZE_MAX || s==SIZE_MAX || l==SIZE_MAX) return 0;
    size_t slot=nor_vtable_slot(im,nand,wk_va(im,c)|1u);
    if(slot==SIZE_MAX || slot<0x37c) return 0;
    size_t table=slot-0x37c;
    return read_le32(im->b+table+0x33c)==(wk_va(im,f)|1u) &&
           read_le32(im->b+table+0x370)==(wk_va(im,s)|1u) &&
           read_le32(im->b+table+0x378)==(wk_va(im,l)|1u);
}
/* AppleNANDFirmware::commitFirmwareCache on the iOS 7.1.2 NAND-backed
 * Image3 path. Require the paired stage and region-flush vtable entries. */
static int nor_verified_nand_commit_712(const struct wk_image *im) {
    struct wk_module nand;
    static const unsigned char commit[]={
        0xb0,0xb5,0x04,0x46,0x02,0xaf,0x20,0x68,
        0xd0,0xf8,0x44,0x13,0x20,0x46,0x88,0x47};
    static const unsigned char flush[]={
        0xf0,0xb5,0x03,0xaf,0x2d,0xe9,0x00,0x0d,
        0x82,0xb0,0x04,0x46,0x20,0x6e};
    static const unsigned char stage[]={
        0xf0,0xb5,0x03,0xaf,0x4d,0xf8,0x04,0x8d,
        0x04,0x46,0x90,0x46,0x20,0x68};
    static const unsigned char llb_stage[]={
        0x90,0xb5,0x04,0x46,0x00,0x20,0xe3,0x6d,
        0x01,0xaf,0x83,0xb9};
    /* The iPhone 4S 7.1 build branches one instruction farther after the
     * same cached-LLB check; the vtable entry and arguments are unchanged. */
    static const unsigned char llb_stage_4s[]={
        0x90,0xb5,0x04,0x46,0x00,0x20,0xe3,0x6d,
        0x01,0xaf,0x93,0xb9};
    if(im->xnu!=2423 || nor_class_module(im,&nand,"AppleNANDFirmware")) return 0;
    size_t c=nor_code_pattern(im,nand.text,commit,sizeof commit);
    size_t f=nor_code_pattern(im,nand.text,flush,sizeof flush);
    size_t s=nor_code_pattern(im,nand.text,stage,sizeof stage);
    size_t l=nor_code_pattern(im,nand.text,llb_stage,sizeof llb_stage);
    if(l==SIZE_MAX)
        l=nor_code_pattern(im,nand.text,llb_stage_4s,sizeof llb_stage_4s);
    if(c==SIZE_MAX || f==SIZE_MAX || s==SIZE_MAX || l==SIZE_MAX) return 0;
    size_t slot=nor_vtable_slot(im,nand,wk_va(im,c)|1u);
    if(slot==SIZE_MAX || slot<0x384) return 0;
    size_t table=slot-0x384;
    return read_le32(im->b+table+0x344)==(wk_va(im,f)|1u) &&
           read_le32(im->b+table+0x378)==(wk_va(im,s)|1u) &&
           read_le32(im->b+table+0x380)==(wk_va(im,l)|1u);
}
/* XNU 3248 keeps the firmware transaction slots, but changes the stored
 * LLB staging method. Verify each method before exposing selector 7. */
static int nor_verified_nand_commit_935(const struct wk_image *im) {
    struct wk_module nand;
    static const unsigned char commit[]={
        0xb0,0xb5,0x02,0xaf,0x04,0x46,0x20,0x68,
        0xd0,0xf8,0x44,0x13,0x20,0x46,0x88,0x47};
    static const unsigned char flush[]={
        0xf0,0xb5,0x03,0xaf,0x2d,0xe9,0x00,0x0d,
        0x82,0xb0,0x04,0x46,0x20,0x6e};
    static const unsigned char stage[]={
        0xf0,0xb5,0x03,0xaf,0x4d,0xf8,0x04,0x8d,
        0x04,0x46,0x90,0x46,0x20,0x68};
    static const unsigned char llb_stage[]={
        0x90,0xb5,0x01,0xaf,0x04,0x46,0xe0,0x6d,
        0x78,0xb9,0x08,0x46,0x11,0x46};
    if(im->xnu!=3248 || nor_class_module(im,&nand,"AppleNANDFirmware") ||
       !nor_verified_nand_stage(im)) return 0;
    size_t c=nor_code_pattern(im,nand.text,commit,sizeof commit);
    size_t f=nor_code_pattern(im,nand.text,flush,sizeof flush);
    size_t s=nor_code_pattern(im,nand.text,stage,sizeof stage);
    size_t l=nor_code_pattern(im,nand.text,llb_stage,sizeof llb_stage);
    if(c==SIZE_MAX || f==SIZE_MAX || s==SIZE_MAX || l==SIZE_MAX) return 0;
    size_t slot=nor_vtable_slot(im,nand,wk_va(im,c)|1u);
    if(slot==SIZE_MAX || slot<0x384) return 0;
    size_t table=slot-0x384;
    return read_le32(im->b+table+0x344)==(wk_va(im,f)|1u) &&
           read_le32(im->b+table+0x378)==(wk_va(im,s)|1u) &&
           read_le32(im->b+table+0x380)==(wk_va(im,l)|1u);
}
/* XNU 3789 retains the NAND firmware transaction slots, with changed
 * prologues for the flush, region stage, and LLB stage methods. */
static int nor_verified_nand_commit_1033(const struct wk_image *im) {
    struct wk_module nand;
    static const unsigned char commit[]={
        0xb0,0xb5,0x02,0xaf,0x04,0x46,0x20,0x68,
        0xd0,0xf8,0x44,0x13,0x20,0x46,0x88,0x47};
    static const unsigned char flush[]={
        0xf0,0xb5,0x03,0xaf,0x2d,0xe9,0x00,0x0d,
        0x83,0xb0,0x04,0x46,0x20,0x6e};
    static const unsigned char stage[]={
        0xf0,0xb5,0x03,0xaf,0x2d,0xe9,0x00,0x05,
        0x9a,0x46,0x90,0x46,0x0d,0x46,0x04,0x46};
    static const unsigned char llb_stage[]={
        0x90,0xb5,0x01,0xaf,0x91,0x46,0x04,0x46,
        0xe0,0x6d,0x78,0xb9};
    if(im->xnu!=3789 || nor_class_module(im,&nand,"AppleNANDFirmware")) return 0;
    size_t c=nor_code_pattern(im,nand.text,commit,sizeof commit);
    size_t f=nor_code_pattern(im,nand.text,flush,sizeof flush);
    size_t s=nor_code_pattern(im,nand.text,stage,sizeof stage);
    size_t l=nor_code_pattern(im,nand.text,llb_stage,sizeof llb_stage);
    if(c==SIZE_MAX || f==SIZE_MAX || s==SIZE_MAX || l==SIZE_MAX) return 0;
    size_t slot=nor_vtable_slot(im,nand,wk_va(im,c)|1u);
    if(slot==SIZE_MAX || slot<0x384) return 0;
    size_t table=slot-0x384;
    return read_le32(im->b+table+0x344)==(wk_va(im,f)|1u) &&
           read_le32(im->b+table+0x378)==(wk_va(im,s)|1u) &&
           read_le32(im->b+table+0x380)==(wk_va(im,l)|1u);
}
static int nor_physical_2107_verified(const struct wk_image *im) {
    struct wk_module physical;
    static const char chipset[]="RELEASE_ARM_S5L8920X";
    if(im->xnu!=2107 || !memmem(im->b,im->len,chipset,sizeof chipset-1) ||
       nor_class_module(im,&physical,"AppleARMNORFlashDevice")) return 0;
    size_t descriptor=wk_symbol(im,"__ZTV18IOMemoryDescriptor");
    size_t mapping=wk_symbol(im,"__ZTV11IOMemoryMap");
    size_t map=wk_symbol(im,"__ZN18IOMemoryDescriptor3mapEm");
    size_t address=wk_symbol(im,"__ZN11IOMemoryMap17getVirtualAddressEv");
    size_t length=wk_symbol(im,"__ZN11IOMemoryMap9getLengthEv");
    size_t release=wk_symbol(im,"__ZNK8OSObject7releaseEv");
    if(descriptor==SIZE_MAX || mapping==SIZE_MAX || map==SIZE_MAX ||
       address==SIZE_MAX || length==SIZE_MAX || release==SIZE_MAX ||
       descriptor+8+0x98+4>im->len || mapping+8+0x40+4>im->len)
        return 0;
    return read_le32(im->b+descriptor+8+0x98)==(wk_va(im,map)|1u) &&
           read_le32(im->b+mapping+8+0x38)==(wk_va(im,address)|1u) &&
           read_le32(im->b+mapping+8+0x40)==(wk_va(im,length)|1u) &&
           read_le32(im->b+mapping+8+0x14)==(wk_va(im,release)|1u);
}
static int nor_cave(const struct wk_image *im,size_t need,size_t *out) {
    const unsigned char *b=im->b;
    uint32_t n=read_le32(b+16),cmdsize=read_le32(b+20);
    if(n>128 || 28u+cmdsize>im->len) return -1;
    size_t p=28,end=28u+cmdsize;
    int found=0;
    for(uint32_t i=0;i<n;i++) {
        if(p+8>end) return -1;
        uint32_t cmd=read_le32(b+p),sz=read_le32(b+p+4);
        if(sz<8 || sz>end-p) return -1;
        if(cmd==1 && !memcmp(b+p+8,"__TEXT\0",7)) {
            if(found++ || sz<56) return -1;
            uint32_t fo=read_le32(b+p+32),fs=read_le32(b+p+36);
            uint32_t prot=read_le32(b+p+44),ns=read_le32(b+p+48);
            if(!(prot&4) || fo>im->len || fs>im->len-fo || ns>(sz-56)/68) return -1;
            size_t first=fo,last=fo+fs;
            for(uint32_t j=0;j<ns;j++) {
                size_t q=p+56+(size_t)j*68;
                uint32_t at=read_le32(b+q+40),length=read_le32(b+q+36);
                if(at && length) {
                    if(at<fo || at>last || length>last-at) return -1;
                    if(first<at+length) first=at+length;
                }
            }
            first=(first+3)&~(size_t)3;
            if(first<=last && need<=last-first && wk_va(im,first)) {
                size_t q=first;
                while(q<first+need && !b[q]) q++;
                if(q==first+need) { *out=first; p+=sz; continue; }
            }
            /* Some early kernels leave less than one payload at the end of
             * __TEXT. The zero-filled gap after the load commands is also
             * mapped by this executable segment, before its first section. */
            size_t header_end=(28u+cmdsize+3u)&~(size_t)3u;
            size_t section_start=last;
            for(uint32_t j=0;j<ns;j++) {
                size_t q=p+56+(size_t)j*68;
                uint32_t at=read_le32(b+q+40),length=read_le32(b+q+36);
                if(at && length && at<section_start) section_start=at;
            }
            if(header_end<fo || header_end>section_start ||
               need>section_start-header_end || !wk_va(im,header_end)) return -1;
            for(size_t q=header_end;q<header_end+need;q++) if(b[q]) return -1;
            *out=header_end;
        }
        p+=sz;
    }
    return found==1 ? 0 : -1;
}
static int wk_nor_read_bridge(const struct wk_image *im) {
    if(im->subtype==12) return kp_unsupported("watchOS has no targeted NOR store");
    if(im->xnu<1878) return nor_early_bridge(im);
    struct wk_module module;
    if(nor_class_module(im,&module,"AppleImage3NORAccessUserClient"))
        return kp_unsupported("Apple Image3 NOR user client was not uniquely identified");
    unsigned size_slot=im->xnu<2423 ? 0x340:0x348;
    unsigned read_slot=size_slot+4;
    size_t size_fn=nor_wrapper(im,module.text,size_slot,size_slot+0x28);
    size_t read_fn=nor_wrapper(im,module.text,read_slot,read_slot+0x28);
    if(size_fn==SIZE_MAX || read_fn==SIZE_MAX || size_fn==read_fn)
        return kp_unsupported("NOR region size and read methods were not uniquely identified");
    /* The NAND staging paths on these kernels are verified against the
     * AppleNANDFirmware vtable before exposing the bounded write selector. */
    size_t write_fn=SIZE_MAX;
    int commit_bridge=nor_verified_nand_commit_613(im) ||
                      nor_verified_nand_commit_712(im) ||
                      nor_verified_nand_commit_935(im) ||
                      nor_verified_nand_commit_1033(im);
    if(commit_bridge || (im->xnu==3248 && nor_verified_nand_stage(im))) {
        unsigned write_slot=read_slot+4;
        write_fn=nor_wrapper(im,module.text,write_slot,write_slot+0x28);
        if(write_fn==SIZE_MAX || write_fn==read_fn || write_fn==size_fn)
            return kp_unsupported("NOR region write method was not uniquely identified");
    }
    size_t hook=SIZE_MAX,original=SIZE_MAX,default_path=SIZE_MAX;
    int fifth_generation=0;
    for(size_t p=module.text.start;p+10<=module.text.end;p+=2) {
        if(wk_u16(im,p)!=0x2903 || wk_u16(im,p+6)!=0xe8df || wk_u16(im,p+8)!=0xf001) continue;
        int kind=0;size_t to=wk_branch(im,p+2,&kind);
        if(kind!=1 || to==SIZE_MAX || !wk_in(module.text,to,2)) continue;
        if(hook!=SIZE_MAX) return kp_unsupported("Ambiguous NOR externalMethod dispatcher");
        hook=p+2;original=p+6;default_path=to;
    }
    if(hook==SIZE_MAX && im->xnu>=1878 && im->xnu<2107)
        for(size_t p=module.text.start;p+18<=module.text.end;p+=2) {
            if(wk_u16(im,p)!=0x2903 || wk_u16(im,p+12)!=0xe8df ||
               wk_u16(im,p+14)!=0xf001 || wk_u16(im,p+10)!=0x4604) continue;
            int kind=0;size_t to=wk_branch(im,p+6,&kind);
            if(kind!=1 || to==SIZE_MAX || !wk_in(module.text,to,2)) continue;
            if(hook!=SIZE_MAX) return kp_unsupported("Ambiguous NOR externalMethod dispatcher");
            hook=p+6;original=p+10;default_path=to;fifth_generation=1;
        }
    if(hook==SIZE_MAX) return kp_unsupported("NOR externalMethod dispatcher was not found");
    size_t boot_reader=SIZE_MAX,boot_alloc=SIZE_MAX,boot_free=SIZE_MAX;
    if(im->xnu>=2423) {
        struct wk_module flash;
        if(!nor_class_module(im,&flash,"IOFlashStoragePartition")) {
            boot_reader=nor_boot_page_site(im,flash.text);
            boot_alloc=wk_symbol(im,"_IOMallocAligned");
            boot_free=wk_symbol(im,"_IOFreeAligned");
        }
    }
    int boot_bridge=boot_reader!=SIZE_MAX && boot_alloc!=SIZE_MAX && boot_free!=SIZE_MAX;
    size_t flash_original=SIZE_MAX,flash_slot=SIZE_MAX,flash_wrap=SIZE_MAX;
    size_t flash_nand=SIZE_MAX;
    size_t flash_alloc=SIZE_MAX,flash_free=SIZE_MAX;
    int early_flash=im->xnu>=1878 && im->xnu<2107;
    if(early_flash) {
        struct wk_module flash;
        static const unsigned char dispatcher[]={
            0x80,0xb5,0xc0,0x6f,0x6f,0x46,0x30,0xb9,
            0x17,0x48,0x14,0x49,0x17,0x4a,0x90,0x47};
        static const unsigned char nand_command[]={
            0xf0,0xb5,0x03,0xaf,0x2d,0xe9,0x00,0x05,
            0x99,0xb0,0xd7,0xf8,0x08,0xc0,0x04,0x46};
        if(!nor_class_module(im,&flash,"IOFlashPartitionSchemeUserClient")) {
            flash_original=nor_code_pattern(im,flash.text,dispatcher,sizeof dispatcher);
            flash_nand=nor_code_pattern(im,flash.text,nand_command,sizeof nand_command);
            if(flash_original!=SIZE_MAX)
                flash_slot=nor_flash_vtable_slot(im,flash,wk_va(im,flash_original)|1u);
            flash_wrap=wk_symbol(im,"__ZN18IOMemoryDescriptor11withAddressEPvm11IODirection");
            flash_alloc=wk_symbol(im,"_IOMallocAligned");
            flash_free=wk_symbol(im,"_IOFreeAligned");
        }
    } else if(im->xnu==2107) {
        struct wk_module flash;
        static const unsigned char signature[]={
            0xf0,0xb5,0x03,0xaf,0x4d,0xf8,0x04,0x8d,
            0x8b,0xb0,0x15,0x46,0x40,0xf2,0xc2,0x26};
        if(!nor_class_module(im,&flash,"IOFlashControllerUserClient")) {
            for(size_t p=flash.text.start;p+sizeof signature<=flash.text.end;p+=2)
                if(!memcmp(im->b+p,signature,sizeof signature)) {
                    if(flash_original!=SIZE_MAX) { flash_original=SIZE_MAX;break; }
                    flash_original=p;
                }
            if(flash_original!=SIZE_MAX)
                flash_slot=nor_flash_vtable_slot(im,flash,wk_va(im,flash_original)|1u);
            flash_wrap=wk_symbol(im,"__ZN18IOMemoryDescriptor11withAddressEPvm11IODirection");
            flash_alloc=wk_symbol(im,"_IOMallocAligned");
            flash_free=wk_symbol(im,"_IOFreeAligned");
        }
    }
    int flash_bridge=flash_original!=SIZE_MAX && flash_slot!=SIZE_MAX && flash_wrap!=SIZE_MAX &&
                     flash_alloc!=SIZE_MAX && flash_free!=SIZE_MAX &&
                     (!early_flash || flash_nand!=SIZE_MAX);
    size_t epilogue=SIZE_MAX;
    for(size_t p=default_path;p<default_path+16 && p+4<=module.text.end;p+=2)
        if(wk_u16(im,p)==0xb001) { epilogue=p;break; }
    if(epilogue==SIZE_MAX) return kp_unsupported("NOR dispatcher return path was not found");
    size_t cave;
    size_t trampoline=(boot_bridge && commit_bridge) ? 44:
                      (boot_bridge || commit_bridge) ? 32:16;
    size_t boot_size=boot_bridge ? sizeof nor_bootblock_thumb:0;
    int write_bridge=write_fn!=SIZE_MAX;
    int physical_2107=write_bridge && nor_physical_2107_verified(im);
    size_t read_size=physical_2107 ? sizeof nor_read_2107_thumb:
                     write_bridge ? sizeof nor_read_thumb:sizeof nor_read_legacy_thumb;
    size_t commit_size=commit_bridge ? sizeof nor_commit_thumb:0;
    size_t commit_at=trampoline+read_size+boot_size;
    /* The Flash Boot Block stub has PC-relative word literals.  A 358-byte
     * commit stub otherwise places it on a halfword boundary and makes its
     * LDRs fetch overlapping, invalid function pointers. */
    size_t flash_at=(commit_at+commit_size+3u)&~(size_t)3u;
    size_t flash_payload=early_flash ? sizeof nor_flash_early_thumb:sizeof nor_flash_boot_thumb;
    size_t flash_size=flash_bridge ? 12+flash_payload:0;
    if(nor_cave(im,flash_at+flash_size,&cave))
        return kp_unsupported("No verified executable space for NOR read bridge");
    uint32_t cv=wk_va(im,cave),hv=wk_va(im,hook);
    if(flash_bridge && ((cv+(uint32_t)flash_at+12u)&3u))
        return kp_unsupported("Flash Boot Block stub is not word aligned");
    unsigned char branch[4];
    if(nor_branch32(hv,cv,0,branch)) return kp_unsupported("NOR bridge is outside Thumb branch range");
    unsigned char payload[44+sizeof nor_read_2107_thumb+sizeof nor_bootblock_thumb+
                          sizeof nor_commit_thumb+12+sizeof nor_flash_boot_thumb];
    memset(payload,0,sizeof payload);
    payload[0]=0x01;payload[1]=0xd8; /* bhi high */
    if(commit_bridge && boot_bridge) {
        payload[6]=0x07;payload[7]=0x29; /* cmp r1, #7 */
        payload[8]=0x0b;payload[9]=0xd0; /* beq commit call at +34 */
        payload[10]=0x05;payload[11]=0x29; /* cmp r1, #5 */
        payload[12]=0x04;payload[13]=0xd0; /* beq boot call at +24 */
        payload[14]=0x20;payload[15]=0x46;
        payload[24]=0x20;payload[25]=0x46;
        payload[34]=0x20;payload[35]=0x46;
        if(nor_branch32(cv+2,wk_va(im,original),0,payload+2) ||
           nor_branch32(cv+16,cv+trampoline,1,payload+16) ||
           nor_branch32(cv+20,wk_va(im,epilogue),0,payload+20) ||
           nor_branch32(cv+26,cv+trampoline+read_size,1,payload+26) ||
           nor_branch32(cv+30,wk_va(im,epilogue),0,payload+30) ||
           nor_branch32(cv+36,cv+commit_at,1,payload+36) ||
           nor_branch32(cv+40,wk_va(im,epilogue),0,payload+40))
            return kp_unsupported("NOR dispatcher return is outside Thumb branch range");
    } else if(boot_bridge || commit_bridge) {
        payload[6]=boot_bridge ? 0x05:0x07;payload[7]=0x29;
        payload[8]=0x04;payload[9]=0xd0; /* beq second call at +20 */
        for(unsigned p=10;p<=20;p+=10) {
            if(fifth_generation) {payload[p]=0x00;payload[p+1]=0xbf;}
            else {payload[p]=0x20;payload[p+1]=0x46;} /* mov r0,r4 */
        }
        if(nor_branch32(cv+2,wk_va(im,original),0,payload+2) ||
           nor_branch32(cv+12,cv+trampoline,1,payload+12) ||
           nor_branch32(cv+16,wk_va(im,epilogue),0,payload+16) ||
           nor_branch32(cv+22,boot_bridge ? cv+trampoline+read_size:
                        cv+commit_at,1,payload+22) ||
           nor_branch32(cv+26,wk_va(im,epilogue),0,payload+26))
            return kp_unsupported("NOR dispatcher return is outside Thumb branch range");
    } else {
        if(nor_branch32(cv+2,wk_va(im,original),0,payload+2) ||
           nor_branch32(cv+8,cv+trampoline,1,payload+8) ||
           nor_branch32(cv+12,wk_va(im,epilogue),0,payload+12))
            return kp_unsupported("NOR dispatcher return is outside Thumb branch range");
        if(fifth_generation) {payload[6]=0x00;payload[7]=0xbf;}
        else {payload[6]=0x20;payload[7]=0x46;}
    }
    if(physical_2107) {
        memcpy(payload+trampoline,nor_read_2107_thumb,sizeof nor_read_2107_thumb);
        if(sizeof nor_read_2107_thumb!=548 ||
           nor_read_2107_thumb[0x7e]!=0xfb || nor_read_2107_thumb[0x7f]!=0x46 ||
           nor_read_2107_thumb[0x1d4]!=0x79 || nor_read_2107_thumb[0x1d5]!=0x46 ||
           nor_read_2107_thumb[0x1f0]!=0x78 || nor_read_2107_thumb[0x1f1]!=0x46 ||
           read_le32(nor_read_2107_thumb+0x210)!=0x10203040u ||
           read_le32(nor_read_2107_thumb+0x214)!=0x2468ace1u ||
           read_le32(nor_read_2107_thumb+0x218)!=0x13579bdfu ||
           read_le32(nor_read_2107_thumb+0x21c)!=0x55667788u ||
           read_le32(nor_read_2107_thumb+0x220)!=0xdec0addeu)
            return kp_unsupported("XNU 2107 physical NOR payload layout changed");
        uint32_t runtime_anchor=cv+trampoline+0x82;
        nor_u32(payload+trampoline+0x210,read_slot-0xc);
        nor_u32(payload+trampoline+0x214,(wk_va(im,read_fn)|1u)-runtime_anchor);
        nor_u32(payload+trampoline+0x218,(wk_va(im,size_fn)|1u)-runtime_anchor);
        nor_u32(payload+trampoline+0x21c,(wk_va(im,size_fn)|1u)-
                (cv+trampoline+0x1d8));
        nor_u32(payload+trampoline+0x220,(wk_va(im,write_fn)|1u)-
                (cv+trampoline+0x1f4));
    } else if(write_bridge) {
        memcpy(payload+trampoline,nor_read_thumb,sizeof nor_read_thumb);
        if(sizeof nor_read_thumb!=340 ||
           nor_read_thumb[0xbc]!=0xfb || nor_read_thumb[0xbd]!=0x46 ||
           read_le32(nor_read_thumb+0x144)!=0x10203040u ||
           read_le32(nor_read_thumb+0x148)!=0x2468ace1u ||
           read_le32(nor_read_thumb+0x14c)!=0x13579bdfu ||
           read_le32(nor_read_thumb+0x150)!=0xdec0addeu)
            return kp_unsupported("NOR write bridge payload layout changed");
        /* The Thumb PC at payload+0xbc reads runtime(payload+0xc0). */
        uint32_t runtime_anchor=cv+trampoline+0xc0;
        nor_u32(payload+trampoline+0x144,read_slot-0xc);
        nor_u32(payload+trampoline+0x148,(wk_va(im,read_fn)|1u)-runtime_anchor);
        nor_u32(payload+trampoline+0x14c,(wk_va(im,size_fn)|1u)-runtime_anchor);
        nor_u32(payload+trampoline+0x150,(wk_va(im,write_fn)|1u)-runtime_anchor);
    } else {
        memcpy(payload+trampoline,nor_read_legacy_thumb,sizeof nor_read_legacy_thumb);
        if(sizeof nor_read_legacy_thumb!=204 ||
           nor_read_legacy_thumb[0x74]!=0xf8 || nor_read_legacy_thumb[0x75]!=0x46 ||
           read_le32(nor_read_legacy_thumb+0xc0)!=0x10203040u ||
           read_le32(nor_read_legacy_thumb+0xc4)!=0x2468ace1u ||
           read_le32(nor_read_legacy_thumb+0xc8)!=0x13579bdfu)
            return kp_unsupported("NOR read bridge payload layout changed");
        uint32_t runtime_anchor=cv+trampoline+0x78;
        nor_u32(payload+trampoline+0xc0,read_slot-0xc);
        nor_u32(payload+trampoline+0xc4,(wk_va(im,read_fn)|1u)-runtime_anchor);
        nor_u32(payload+trampoline+0xc8,(wk_va(im,size_fn)|1u)-runtime_anchor);
    }
    if(boot_bridge) {
        size_t at=trampoline+read_size;
        if(sizeof nor_bootblock_thumb!=316 ||
           nor_bootblock_thumb[0xd8]!=0xe0 || nor_bootblock_thumb[0xd9]!=0x47 ||
           read_le32(nor_bootblock_thumb+0x134)!=0x31415926u ||
           read_le32(nor_bootblock_thumb+0x138)!=0x13579bdfu)
            return kp_unsupported("Boot Block bridge payload layout changed");
        memcpy(payload+at,nor_bootblock_thumb,boot_size);
        /* Thumb mov r1, pc at payload offset 0x8e observes instruction+4. */
        uint32_t anchor=cv+(uint32_t)at+0x92u;
        nor_u32(payload+at+0x134,(wk_va(im,boot_free)|1u)-anchor);
        nor_u32(payload+at+0x138,(wk_va(im,boot_alloc)|1u)-anchor);
    }
    if(commit_bridge) {
        memcpy(payload+commit_at,nor_commit_thumb,commit_size);
        if(im->xnu==2107) {
            /* XNU 2107's LLB stage/commit vtable slots are 0x378/0x37c.
             * The checked Thumb loads use 0x380/0x384 on later kernels. */
            if(commit_size!=358 ||
               read_le32(nor_commit_thumb+284)!=0x7380f8d7u ||
               read_le32(nor_commit_thumb+340)!=0x1384f8d7u)
                return kp_unsupported("XNU 2107 NAND commit stub layout changed");
            payload[commit_at+286]=0x78;
            payload[commit_at+342]=0x7c;
        }
    }
    if(flash_bridge) {
        size_t at=flash_at+12;
        const unsigned char *stub=early_flash ? nor_flash_early_thumb:nor_flash_boot_thumb;
        if(early_flash) {
            if(sizeof nor_flash_early_thumb!=284 ||
               stub[0x74]!=0xfa || stub[0x75]!=0x46 ||
               read_le32(stub+0x10c)!=0x0badc0deu ||
               read_le32(stub+0x110)!=0x2468ace1u ||
               read_le32(stub+0x114)!=0x31415926u ||
               read_le32(stub+0x118)!=0x13579bdfu)
                return kp_unsupported("Early Flash Boot Block payload layout changed");
        } else {
        if(sizeof nor_flash_boot_thumb!=304 ||
           nor_flash_boot_thumb[0x76]!=0x7e || nor_flash_boot_thumb[0x77]!=0x46 ||
           read_le32(nor_flash_boot_thumb+0x124)!=0x2468ace1u ||
           read_le32(nor_flash_boot_thumb+0x128)!=0x31415926u ||
           read_le32(nor_flash_boot_thumb+0x12c)!=0x13579bdfu)
            return kp_unsupported("Flash Boot Block payload layout changed");
        }
        payload[flash_at]=0x0b;payload[flash_at+1]=0x29; /* cmp r1, #11 */
        payload[flash_at+2]=0x01;payload[flash_at+3]=0xd0; /* beq boot call */
        if(nor_branch32(cv+(uint32_t)flash_at+4,wk_va(im,flash_original),0,payload+flash_at+4) ||
           nor_branch32(cv+(uint32_t)flash_at+8,cv+(uint32_t)at,0,payload+flash_at+8))
            return kp_unsupported("Flash Boot Block bridge is outside Thumb branch range");
        memcpy(payload+at,stub,flash_payload);
        uint32_t anchor=cv+(uint32_t)at+(early_flash ? 0x78u:0x7au);
        if(early_flash) {
            nor_u32(payload+at+0x10c,(wk_va(im,flash_nand)|1u)-anchor);
            nor_u32(payload+at+0x110,(wk_va(im,flash_free)|1u)-anchor);
            nor_u32(payload+at+0x114,(wk_va(im,flash_alloc)|1u)-anchor);
            nor_u32(payload+at+0x118,(wk_va(im,flash_wrap)|1u)-anchor);
        } else {
            nor_u32(payload+at+0x124,(wk_va(im,flash_free)|1u)-anchor);
            nor_u32(payload+at+0x128,(wk_va(im,flash_alloc)|1u)-anchor);
            nor_u32(payload+at+0x12c,(wk_va(im,flash_wrap)|1u)-anchor);
        }
    }
    if(nor_add_payload(cave,cv,payload,flash_at+flash_size,
              commit_bridge ? "bounded NOR read/write/commit selectors":
              write_bridge ? "bounded NOR read/write selectors":"bounded NOR read selector") ||
       wk_add(im,"NOR read dispatcher branch",hook,branch,sizeof branch)) return -1;
    if(flash_bridge) {
        unsigned char pointer[4];nor_u32(pointer,cv+(uint32_t)flash_at+1u);
        if(kp_add(flash_slot,wk_va(im,flash_slot),pointer,4,"Flash Boot Block read method",1)) return -1;
    }
    return 0;
}
