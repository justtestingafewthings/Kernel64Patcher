/* ARM64 auxiliary patch discovery. */
#include <stdio.h>
#include <string.h>

static int da_bl(uint32_t w) { return (w & 0xfc000000u) == 0x94000000u; }
static int da_b(uint32_t w) { return (w & 0xfc000000u) == 0x14000000u; }
static int da_cbnz(uint32_t w) { return (w & 0x7f000000u) == 0x35000000u; }
static int da_ret(uint32_t w) { return w == 0xd65f03c0u || w == 0xd65f0fffu || w == 0xd65f0bffu; }
static int da_mov0(uint32_t w) { return (w & 0xffe0ffffu) == 0xaa0003e0u; }

static int da_fail(const char *what) {
    fprintf(stderr, "Could not unambiguously discover %s. No output written.\n", what);
    return -1;
}

/* Diagnostics may contain a leading quote, source-file prefix or format args. */
static size_t da_anchor(const struct kd_ctx *c, size_t p) {
    size_t a = p;
    while (a && c->buf[a-1] && p-a < 1024) --a;
    return a && c->buf[a-1] ? KD_NONE : a;
}
static size_t da_strings(const struct kd_ctx *c, const char *needle,
                         size_t *out, size_t capacity) {
    size_t count = 0, n = strlen(needle);
    if (n > c->len) return 0;
    for (size_t p = 0; p <= c->len-n; ++p) {
        if (c->buf[p] != (unsigned char)needle[0] || memcmp(c->buf+p,needle,n)) continue;
        size_t a = da_anchor(c,p);
        if (a == KD_NONE) return KD_NONE;
        int duplicate = 0;
        for (size_t k=0;k<count;k++) duplicate |= out[k] == a;
        if (!duplicate) {
            if (count == capacity) return KD_NONE;
            out[count++] = a;
        }
        p += n-1;
    }
    return count;
}
static size_t da_refs(const struct kd_ctx *c, size_t string,
                      size_t *out, size_t capacity) {
    size_t count = 0;
    for (size_t k=0;k<c->region_count;k++) {
        const struct kd_region *r=&c->regions[k];
        if (!r->executable) continue;
        size_t end=r->off+r->size, start=r->off;
        while (start < end) {
            size_t p=kd_xref(c,start,end,string);
            if (p==KD_NONE) break;
            int duplicate=0;
            for(size_t i=0;i<count;i++) duplicate |= out[i]==p;
            if(!duplicate) {
                if (count==capacity) return KD_NONE;
                out[count++]=p;
            }
            start=p+4;
        }
    }
    return count;
}
static int da_unique(size_t *slots,size_t *count,size_t cap,size_t p) {
    for(size_t k=0;k<*count;k++) if(slots[k]==p) return 0;
    if(*count==cap) return -1;
    slots[(*count)++]=p;
    return 0;
}

/* A conditional error edge must enter the diagnostic block, with no call,
 * return or other branch between its destination and the string reference. */
static int da_linear(const struct kd_ctx *c,size_t start,size_t end) {
    if(start>end || end-start>96 || !kd_executable(c,start)) return 0;
    for(size_t p=start;p<end;p+=4) {
        uint32_t w=kd_word(c,p);
        if(da_bl(w)||da_b(w)||da_ret(w)||(w&0x7e000000u)==0x34000000u ||
           (w&0x7e000000u)==0x36000000u || (w&0xff000010u)==0x54000000u ||
           (w&0xfffffc1fu)==0xd61f0000u) return 0;
    }
    return 1;
}
static int da_guards(const struct kd_ctx *c,size_t reference,
                     size_t *slots,size_t *count,size_t capacity,int return_zero) {
    size_t start,end;
    if(!kd_exec_bounds(c,reference,&start,&end)) return -1;
    size_t function=kd_function(c,reference);
    if(function==KD_NONE) return -1;
    /* The edge can be far from the shared panic block; use function metadata. */
    if(function>start) start=function;
    for(size_t p=start;p+4<=end;p+=4) {
        uint32_t w=kd_word(c,p);
        if(!da_cbnz(w) || (return_zero && (w&31)!=0 && (w&31)!=31)) continue;
        size_t target=kd_branch(c,p);
        if(target==KD_NONE || !da_linear(c,target,reference)) continue;
        if(kd_function(c,p)!=function) continue;
        if(da_unique(slots,count,capacity,p)<0) return -1;
    }
    return 0;
}

/* Compilers outline fatal assertion blocks into small frameless helpers. */
static int da_indirect_guards_depth(const struct kd_ctx *c,size_t reference,
                              size_t *sites,size_t *count,size_t capacity,int zero,unsigned depth) {
    for(size_t k=0;k<c->region_count;k++) {
        const struct kd_region *r=&c->regions[k];
        if(!r->executable) continue;
        for(size_t p=r->off;p+4<=r->off+r->size;p+=4) {
            if(!da_bl(kd_word(c,p))) continue;
            size_t target=kd_branch(c,p);
            if(target==KD_NONE||target>reference||reference-target>128 ||
               kd_function(c,target+(reference-target<16?reference-target:16))!=kd_function(c,reference)) continue;
            int valid=1;
            for(size_t q=target;q<reference;q+=4) {
                uint32_t op=kd_word(c,q);
                if(da_ret(op)||da_b(op)||(op&0x7e000000u)==0x34000000u||
                   (op&0x7e000000u)==0x36000000u||(op&0xff000010u)==0x54000000u||
                   (op&0xfffffc1fu)==0xd61f0000u) { valid=0; break; }
            }
            if(valid) {
                size_t prior = *count;
                if(da_guards(c,p,sites,count,capacity,zero)<0) return -1;
                /* Source-location setup and the diagnostic can occupy
                 * separate cold helpers. */
                if(*count == prior && depth < 2 &&
                   da_indirect_guards_depth(c,p,sites,count,capacity,zero,depth+1)<0)
                    return -1;
            }
        }
    }
    return 0;
}

static int da_indirect_guards(const struct kd_ctx *c,size_t reference,
                              size_t *sites,size_t *count,size_t capacity,int zero) {
    return da_indirect_guards_depth(c,reference,sites,count,capacity,zero,0);
}

static int da_panic_guard(struct kd_ctx *c,const char *needle,const char *label,
                           char flag,int absent_ok,int return_zero) {
    size_t strings[16],sites[16],count=0;
    size_t ns=da_strings(c,needle,strings,16);
    if(ns==KD_NONE) return da_fail(label);
    if(!ns) {
        if(absent_ok) { kp_absent("corresponding diagnostic/feature is absent"); return 0; }
        return da_fail(label);
    }
    for(size_t s=0;s<ns;s++) {
        if(flag=='p' && c->buf[strings[s]]!='"') continue; /* ordinary error logs are not fatal guards */
        size_t refs[32],nr=da_refs(c,strings[s],refs,32);
        if(nr==KD_NONE || !nr) return da_fail(label);
        for(size_t r=0;r<nr;r++) {
            size_t local[16],nlocal=0;
            if(da_guards(c,refs[r],local,&nlocal,16,return_zero)<0 ||
               da_indirect_guards(c,refs[r],local,&nlocal,16,return_zero)<0 || !nlocal) return da_fail(label);
            for(size_t i=0;i<nlocal;i++)
                if(da_unique(sites,&count,16,local[i])<0) return da_fail(label);
        }
    }
    if(!count) return da_fail(label);
    /* CBNZ ZR never branches and retains the diagnostic edge for repeat runs. */
    for(size_t i=0;i<count;i++) if(kd_add_word(c,sites[i],kd_word(c,sites[i])|31u,label)<0) return -1;
    return 0;
}

static int da_firmware(struct kd_ctx *c) {
    const char *label="AppleFirmwareUpdate IMG4 validation";
    size_t strings[4],sites[8],count=0;
    size_t ns=da_strings(c,"Performing img4 validation outside of workloop",strings,4);
    if(ns==KD_NONE) return da_fail(label);
    if(!ns) {
        if(kd_string(c,"AppleFirmwareUpdate")==KD_NONE) {
            kp_absent("AppleFirmwareUpdate driver is absent"); return 0;
        }
        return da_fail(label);
    }
    for(size_t s=0;s<ns;s++) {
        size_t refs[8],nr=da_refs(c,strings[s],refs,8);
        if(!nr||nr==KD_NONE) return da_fail(label);
        for(size_t r=0;r<nr;r++) {
            size_t ref=refs[r],region_start,end,call=KD_NONE;
            if(!kd_exec_bounds(c,ref,&region_start,&end)) return da_fail(label);
            size_t limit=ref+48<end?ref+48:end;
            for(size_t p=ref+4;p+12<=limit;p+=4) {
                if(!da_bl(kd_word(c,p))) continue;
                /* Log call; restore this in X0 and invoke validation. */
                if(!da_mov0(kd_word(c,p+4))) continue;
                uint32_t w=kd_word(c,p+8);
                if(!da_bl(w) && w!=0xd2800000u) continue;
                if(da_bl(w) && !kd_executable(c,kd_branch(c,p+8))) continue;
                if(call!=KD_NONE) return da_fail(label);
                call=p+8;
            }
            if(call==KD_NONE||da_unique(sites,&count,8,call)<0) return da_fail(label);
        }
    }
    for(size_t i=0;i<count;i++) if(kd_add_word(c,sites[i],0xd2800000u,label)<0) return -1;
    return 0;
}

static int da_spu(struct kd_ctx *c) {
    const char *label="SPU firmware-validation failure guard";
    size_t strings[8],sites[16],count=0;
    size_t ns=da_strings(c,"firmware validation failed",strings,8);
    if(ns==KD_NONE) return da_fail(label);
    if(!ns) {
        if(c->xnu<8019 || (kd_string(c,"com.apple.driver.AppleSPU")==KD_NONE && kd_string(c,"AppleSPUFirmwareService")==KD_NONE)) {
            kp_absent("SPU firmware-validation panic path is absent"); return 0;
        }
        return da_fail(label);
    }
    for(size_t s=0;s<ns;s++) {
        size_t refs[16],nr=da_refs(c,strings[s],refs,16);
        if(nr==KD_NONE||!nr) return da_fail(label);
        for(size_t r=0;r<nr;r++) {
            size_t local[16],nlocal=0;
            if(da_indirect_guards(c,refs[r],local,&nlocal,16,0)<0 || !nlocal) return da_fail(label);
            for(size_t i=0;i<nlocal;i++)
                if(da_unique(sites,&count,16,local[i])<0) return da_fail(label);
        }
    }
    if(!count) return da_fail(label);
    for(size_t i=0;i<count;i++) if(kd_add_word(c,sites[i],kd_word(c,sites[i])|31u,label)<0) return -1;
    return 0;
}

static int da_auth_entry(const struct kd_ctx *c,size_t p,size_t target) {
    if(p>c->len||c->len-p<20) return 0;
    uint32_t load=kd_word(c,p),cmp=kd_word(c,p+4),sel=kd_word(c,p+8),arg=kd_word(c,p+12);
    unsigned value=cmp>>5&31,object=sel>>5&31;
    /* object->authentication context, nullable context selection, mode, call. */
    if((load&0xffc00000u)!=0xf9400000u && !(da_b(load)&&kd_branch(c,p)==target)) return 0;
    if((load&0xffc00000u)==0xf9400000u && ((load&31)!=value || (load>>5&31)!=object || !(load>>10&4095))) return 0;
    if(cmp!=(0xf100001fu|(value<<5)) ||
       sel!=(0x9a800000u|(value<<16)|(object<<5)) || object<19 || object>28) return 0;
    if((arg&0xffe0ffffu)!=0xaa0003e1u && arg!=0x52800001u && arg!=0xd2800001u) return 0;
    return da_bl(kd_word(c,p+16)) && kd_executable(c,kd_branch(c,p+16));
}
static int da_roothash(struct kd_ctx *c) {
    const char *label="personalized root-hash authentication";
    size_t fails[8],successes[8],nf=da_strings(c,"could not authenticate personalized root hash!",fails,8),
           ns=da_strings(c,"successfully validated on-disk root hash",successes,8);
    if(nf==KD_NONE||ns==KD_NONE) return da_fail(label);
    if(!nf&&!ns&&c->xnu<8019) { kp_absent("personalized root-hash authentication is absent"); return 0; }
    if(nf!=1||ns!=1) return da_fail(label);
    size_t fr[8],sr[8],nfr=da_refs(c,fails[0],fr,8),nsr=da_refs(c,successes[0],sr,8);
    if(nfr!=1||nsr!=1) return da_fail(label);
    size_t function=kd_function(c,fr[0]),start,end;
    if(function==KD_NONE||kd_function(c,sr[0])!=function || !kd_exec_bounds(c,fr[0],&start,&end)) return da_fail(label);
    if(end-function>0x20000) end=function+0x20000;
    size_t target=KD_NONE,zero_return=KD_NONE,success_entry=KD_NONE;
    /* New APFS success blocks mark the filesystem authenticated under a lock.
     * Those state writes must run; returning success alone is insufficient. */
    size_t lo=sr[0]>384?sr[0]-384:function;
    if(lo<function) lo=function;
    for(size_t p=lo;p<sr[0];p+=4) {
        uint32_t op=kd_word(c,p);
        if((op&0x7f000000u)!=0x34000000u) continue; /* CBZ */
        size_t t=kd_branch(c,p);
        if(t==KD_NONE||t<=p||t>sr[0]||sr[0]-t>128) continue;
        int valid=1;
        for(size_t q=t;q<sr[0];q+=4) {
            uint32_t w=kd_word(c,q);
            if(da_b(w)||da_ret(w)||(w&0x7e000000u)==0x34000000u||
               (w&0x7e000000u)==0x36000000u||(w&0xff000010u)==0x54000000u) { valid=0; break; }
        }
        if(!valid) continue;
        if(success_entry!=KD_NONE&&success_entry!=t) return da_fail(label);
        success_entry=t;
    }
    for(size_t p=sr[0]+4;p+8<=end&&p<sr[0]+32;p+=4) {
        if(!da_bl(kd_word(c,p))) continue;
        if(da_b(kd_word(c,p+4))) {
            size_t t=kd_branch(c,p+4);
            if(t!=KD_NONE&&t>=function&&t+4<=end&&kd_word(c,t)==0x52800000u) zero_return=t;
        }
        break;
    }
    if(success_entry!=KD_NONE) {
        int state_write=0;
        for(size_t q=success_entry;q<sr[0];q+=4) {
            uint32_t w=kd_word(c,q);unsigned base=(w>>5)&31;
            if((w&0x3b400000u)==0x39000000u&&base>=19&&base<=28) state_write=1;
        }
        target=state_write||zero_return==KD_NONE?success_entry:zero_return;
    } else if(zero_return!=KD_NONE) target=zero_return;
    if(target==KD_NONE) {
        /* Earlier APFS continues through a success diagnostic and cleanup. */
        lo=sr[0]>128?sr[0]-128:function;
        if(lo<function) lo=function;
        for(size_t p=lo;p<sr[0];p+=4)
            if(da_cbnz(kd_word(c,p))&&da_linear(c,p+4,sr[0])) target=p+4;
    }
    if(target==KD_NONE) return da_fail(label);
    size_t entry=KD_NONE,limit=fr[0]<sr[0]?fr[0]:sr[0];
    for(size_t p=function;p+20<=limit;p+=4) {
        if(!da_auth_entry(c,p,target)) continue;
        if(entry!=KD_NONE) return da_fail(label);
        entry=p;
    }
    if(entry==KD_NONE || target<=entry || !kd_executable(c,target)) return da_fail(label);
    int64_t delta=(int64_t)kd_va(c,target)-(int64_t)kd_va(c,entry);
    if((delta&3)||delta<-(INT64_C(1)<<27)||delta>=(INT64_C(1)<<27)) return da_fail(label);
    return kd_add_word(c,entry,0x14000000u|((uint32_t)(delta/4)&0x03ffffffu),label);
}

/* Bypass the encryption-policy panic edge while preserving normal cleanup. */
static int da_unencrypted(struct kd_ctx *c) {
    const char *label = "unencrypted data-volume panic guard";
    size_t strings[8], sites[16], count = 0;
    size_t ns = da_strings(c, "unencrypted data volume is not allowed", strings, 8);
    if (ns == KD_NONE) return da_fail(label);
    if (!ns) {
        kp_absent("unencrypted data-volume panic diagnostic is absent");
        return 0;
    }
    for (size_t s = 0; s < ns; ++s) {
        size_t refs[16], nr = da_refs(c, strings[s], refs, 16);
        if (!nr || nr == KD_NONE) return da_fail(label);
        for (size_t r = 0; r < nr; ++r) {
            size_t ref = refs[r], fn = kd_function(c, ref), site = KD_NONE;
            if (fn == KD_NONE) return da_fail(label);
            unsigned string_register;
            size_t string_target;
            if (!kd_address(c, ref, &string_register, &string_target) ||
                string_register != 0 || string_target != strings[s]) return da_fail(label);
            size_t lo = ref > 128 ? ref - 128 : fn;
            if (lo < fn + 4) lo = fn + 4;
            for (size_t p = lo; p + 8 <= ref; p += 4) {
                uint32_t op = kd_word(c, p), load = kd_word(c, p - 4);
                /* TBNZ Wn,#0 follows a byte load of that policy flag. */
                if ((op & 0xfff80000u) != 0x37000000u ||
                    (load & 0xffc00000u) != 0x39400000u ||
                    ((load & 31) != (op & 31) && (op & 31) != 31)) continue;
                size_t target = kd_branch(c, p);
                if (target == KD_NONE || target <= p + 4 ||
                    !da_linear(c, target, ref) || kd_function(c, p) != fn) continue;
                int returned = 0, valid = 1;
                for (size_t q = p + 4; q < target; q += 4) {
                    uint32_t w = kd_word(c, q);
                    if (da_ret(w)) { returned = 1; break; }
                    if (da_bl(w) || da_b(w) ||
                        (w & 0x7e000000u) == 0x34000000u ||
                        (w & 0x7e000000u) == 0x36000000u ||
                        (w & 0xff000010u) == 0x54000000u) { valid = 0; break; }
                }
                if (!valid || !returned) continue;
                if (site != KD_NONE && site != p) return da_fail(label);
                site = p;
            }
            int called = 0;
            for (size_t p = ref + 4; p < ref + 24 && p + 4 <= c->len; p += 4) {
                if (da_bl(kd_word(c, p)) && kd_executable(c, kd_branch(c, p))) {
                    called = 1; break;
                }
                if (da_ret(kd_word(c, p)) || da_b(kd_word(c, p))) break;
            }
            if (site == KD_NONE || !called ||
                da_unique(sites, &count, 16, site) < 0) return da_fail(label);
        }
    }
    for (size_t i = 0; i < count; ++i)
        if (kd_add_word(c, sites[i], kd_word(c, sites[i]) | 31u, label) < 0) return -1;
    return 0;
}

/* Tie the kernel-task comparison to the mount diagnostic and panic tail. */
static int da_apfs_mount_auth(struct kd_ctx *c) {
    static const char anchor[] = "%s:%d: not allowed to mount as root\n";
    const char *label = "APFS kernel-task mount authorization";
    size_t strings[4], refs[8], candidate = KD_NONE;
    size_t ns = da_strings(c, anchor, strings, 4);
    if (ns == KD_NONE) return da_fail(label);
    if (!ns) {
        kp_absent("APFS kernel-task mount authorization diagnostic is absent");
        return 0;
    }
    for (size_t s = 0; s < ns; ++s) {
        size_t nr = da_refs(c, strings[s], refs, 8);
        if (nr == KD_NONE || !nr) return da_fail(label);
        for (size_t r = 0; r < nr; ++r) {
            size_t ref = refs[r], fn = kd_function(c, ref), local = KD_NONE;
            unsigned reg;
            size_t target;
            if (fn == KD_NONE || !kd_address(c, ref, &reg, &target) || target != strings[s] ||
                (kd_word(c, ref + 8) & 0xfc000000u) != 0x94000000u ||
                !kd_executable(c, kd_branch(c, ref + 8)) ||
                (kd_word(c, ref + 12) & 0x9f7ffc20u) != 0x12000020u ||
                (kd_word(c, ref + 16) & 0xfc000000u) != 0x14000000u)
                return da_fail(label);
            size_t lo = ref > 128 ? ref - 128 : fn;
            if (lo < fn + 16) lo = fn + 16;
            for (size_t p = lo; p + 4 <= ref; p += 4) {
                uint32_t cmp = kd_word(c, p);
                if ((cmp != 0xeb08001fu && cmp != 0xeb00001fu) ||
                    kd_function(c, p) != fn || p < 12 ||
                    (kd_word(c, p - 4) & 0xffc003ffu) != 0xf9400108u ||
                    (kd_word(c, p - 8) & 0xffc003ffu) != 0xf9400108u ||
                    (kd_word(c, p - 12) & 0x9f00001fu) != 0x90000008u)
                    continue;
                if (local != KD_NONE && local != p) return da_fail(label);
                local = p;
            }
            if (local == KD_NONE) return da_fail(label);
            if (candidate != KD_NONE && candidate != local) return da_fail(label);
            candidate = local;
        }
    }
    if (candidate == KD_NONE) return da_fail(label);
    return kd_add_word(c, candidate, 0xeb00001fu, label);
}

/* Require the remount guard's branch to reach the read/write diagnostic. */
static int da_apfs_remount(struct kd_ctx *c) {
    static const char anchor[] = "Updating mount to read/write mode is not allowed\n";
    const char *label = "APFS root-volume read/write remount guard";
    size_t strings[4], site = KD_NONE;
    size_t ns = da_strings(c, anchor, strings, 4);
    if (ns == KD_NONE) return da_fail(label);
    if (!ns) {
        kp_absent("APFS read/write remount diagnostic is absent");
        return 0;
    }
    for (size_t ri = 0; ri < c->region_count; ++ri) {
        const struct kd_region *region = &c->regions[ri];
        if (!region->executable) continue;
        for (size_t p = region->off; p + 8 <= region->off + region->size; p += 4) {
            if ((kd_word(c, p) & 0xfc000000u) != 0x94000000u ||
                (kd_word(c, p + 4) & 0xfff8001fu) != 0x37700000u)
                continue;
            size_t target = kd_branch(c, p + 4);
            if (target == KD_NONE || !kd_executable(c, target) ||
                kd_function(c, p) == KD_NONE || kd_function(c, target) != kd_function(c, p))
                continue;
            int matched = 0;
            for (size_t q = target, end = target + 80; q + 4 <= end && q + 4 <= c->len; q += 4) {
                unsigned reg;
                size_t value;
                if (!kd_address(c, q, &reg, &value)) continue;
                for (size_t s = 0; s < ns; ++s)
                    if (value == strings[s]) matched = 1;
            }
            if (!matched) continue;
            if (site != KD_NONE && site != p + 4) return da_fail(label);
            site = p + 4;
        }
    }
    /* The patched guard has no branch target. Match its replacement and
     * preceding call in the diagnostic's function on repeat runs. */
    if (site == KD_NONE) for (size_t s = 0; s < ns; ++s) {
        size_t refs[8], nr = da_refs(c, strings[s], refs, 8);
        if (nr == KD_NONE || !nr) return da_fail(label);
        for (size_t r = 0; r < nr; ++r) {
            size_t ref = refs[r], fn = kd_function(c, ref), begin, end;
            if (fn == KD_NONE || !kd_exec_bounds(c, ref, &begin, &end)) return da_fail(label);
            if (begin < fn) begin = fn;
            size_t lo = ref > 0x4000 ? ref - 0x4000 : begin;
            if (lo < begin) lo = begin;
            for (size_t p = lo; p + 8 <= ref && p + 8 <= end; p += 4) {
                if ((kd_word(c, p) & 0xfc000000u) != 0x94000000u ||
                    kd_word(c, p + 4) != 0x52800000u ||
                    !kd_executable(c, kd_branch(c, p)) || kd_function(c, p) != fn)
                    continue;
                if (site != KD_NONE && site != p + 4) return da_fail(label);
                site = p + 4;
            }
        }
    }
    if (site == KD_NONE) return da_fail(label);
    return kd_add_word(c, site, 0x52800000u, label);
}

static int kd_aux(struct kd_ctx *c,int flags) {
    if((flags&2)&&da_firmware(c)<0) return -1;
    if((flags&4)&&da_spu(c)<0) return -1;
    if((flags&8)&&da_panic_guard(c,"rootvp not authenticated after mounting",
          "rootvp authentication panic branch",'r',c->xnu<8019,1)<0) return -1;
    if((flags&16)&&da_roothash(c)<0) return -1;
    if((flags&32)&&da_panic_guard(c,"unable to obtain local signing public key",
          "AMFI local-signing-key failure guard",'p',c->xnu<8019||(c->platform==3 && kd_string(c,"failed to get local signing public key")==KD_NONE && kd_string(c,"unable to obtain AKS services for local signing public key")==KD_NONE),0)<0) return -1;
    if((flags&64)&&da_unencrypted(c)<0) return -1;
    return 0;
}
