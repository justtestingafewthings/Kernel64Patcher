static size_t sk_pattern(struct kd_ctx *c,const unsigned char *pattern,size_t size,size_t *count) {
    size_t found=KD_NONE;*count=0;
    for(size_t p=0;p<=c->len && size<=c->len-p;p+=4)
        if(kd_executable(c,p) && !memcmp(c->buf+p,pattern,size)) { found=p;(*count)++; }
    return found;
}
static size_t sk_either(struct kd_ctx *c,const unsigned char *pattern,size_t size,size_t changed,uint32_t replacement,size_t *count) {
    unsigned char alternate[64];
    if(size>sizeof(alternate) || changed+4>size) { *count=0;return KD_NONE; }
    memcpy(alternate,pattern,size);
    for(unsigned i=0;i<4;i++) alternate[changed+i]=(unsigned char)(replacement>>(8*i));
    size_t first_count,second_count;
    size_t first=sk_pattern(c,pattern,size,&first_count),second=sk_pattern(c,alternate,size,&second_count);
    *count=first_count+second_count;
    return first_count?first:second;
}
static int sk_word(struct kd_ctx *c,size_t p,uint32_t value,const char *name) {
    return kd_executable(c,p)?kd_add_word(c,p,value,name):-1;
}
static int sk_storage_keys(struct kd_ctx *c) {
    static const unsigned char native_uid[]={0x88,0x02,0x80,0x52,0xbf,0x42,0x1f,0x71,0x00,0x02,0x00,0x54,0xbf,0xa6,0x0f,0x71,0x61,0x00,0x00,0x54};
    static const unsigned char trust[]={0xe8,0x03,0x00,0xaa,0x60,0x2a,0x04,0x91,0x1f,0x01,0x00,0x31,0xe8,0x17,0x9f,0x1a,0x68,0x32,0x04,0x39,0xe8,0x03,0x00,0x32,0x68,0x2a,0x04,0x39};
    static const unsigned char derived[]={0x08,0x61,0x22,0x51,0xfa,0xff,0xa3,0x12,0x3a,0x58,0x80,0x72,0x1f,0x91,0x01,0x71};
    static const unsigned char aes[]={0x68,0x26,0x40,0xb9,0x1f,0xa1,0x0f,0x71,0x80,0x01,0x00,0x54,0x1f,0x41,0x1f,0x71};
    static const unsigned char art8[]={0x7f,0x82,0x07,0x39,0x88,0x02,0x40,0xf9,0x08,0x15,0x40,0xf9,0xe0,0x03,0x14,0xaa,0x00,0x01,0x3f,0xd6,0x68,0xda,0x40,0xf9,0x68,0x09,0x00,0xb4,0x68,0xea,0x40,0xf9,0xa8,0x01,0x00,0xb5};
    static const unsigned char art7[]={0x68,0xda,0x40,0xf9,0x88,0x0b,0x00,0xb4,0x68,0xea,0x40,0xf9,0x88,0x01,0x00,0xb5};
    if(c->xnu!=2423 && c->xnu!=2783 && c->xnu!=2784) {
        if(c->xnu>=3248) { kp_absent("The iOS 7/8 UID/ART adjustments do not apply to this kernel generation");return 0; }
        return kp_unsupported("Unrecognized kernel generation for legacy ARM64 storage keys");
    }
    size_t count,art;
    uint32_t art_jump=0x14000000u|((uint32_t)((int32_t)(read_le32(art8+24)<<8)>>13)&0x3ffffff);
    if(c->xnu==2423) art=sk_pattern(c,art7,sizeof(art7),&count);
    else art=sk_either(c,art8,sizeof(art8),24,art_jump,&count);
    if(count!=1) return da_fail("unique legacy ART flow");
    size_t branch=art+(c->xnu==2423?4:24),target=kd_branch(c,branch);
    if(((kd_word(c,branch)&0x7e000000)!=0x34000000 && kd_word(c,branch)!=art_jump) || target==KD_NONE || !kd_executable(c,target))
        return da_fail("legacy ART branch");
    size_t names[4],refs[16];size_t n=da_strings(c,"IOReturn AppleSEPARTStorage::handle_first_connected()",names,4);
    int contextual=0;
    if(n==KD_NONE) return -1;
    for(size_t i=0;i<n;i++) {
        size_t nr=da_refs(c,names[i],refs,16);if(nr==KD_NONE) return -1;
        for(size_t j=0;j<nr;j++) if(refs[j]+0x80>=branch && refs[j]<=branch+0x180) contextual=1;
    }
    if(!contextual) return da_fail("ART method string context");
    if(c->xnu==2783 || c->xnu==2784) {
        size_t p=sk_pattern(c,aes,sizeof(aes),&count);
        if(count!=1 || ((kd_word(c,p+16)&0xff000010)!=0x54000000 && kd_word(c,p+16)!=0xd503201f)) return da_fail("UID AES handle dispatch");
        uint64_t from=kd_va(c,branch),to=kd_va(c,target);int64_t delta=(int64_t)(to-from);
        if((delta&3) || delta<-(INT64_C(1)<<27) || delta>=(INT64_C(1)<<27)) return -1;
        if(sk_word(c,p+16,0xd503201f,"Permit UID AES handle 0x7d0")) return -1;
        return sk_word(c,branch,0x14000000u|((uint32_t)(delta/4)&0x3ffffff),"Select ART_NO_ART on iOS 8");
    }
    sk_pattern(c,native_uid,sizeof(native_uid),&count);
    if(count!=2) return da_fail("native iOS 7 UID AES dispatch");
    size_t p=sk_either(c,trust,sizeof(trust),12,0x52800028,&count);
    if(count!=1) return da_fail("SecureRoot trust result");
    n=da_strings(c,"SecureRootName",names,4);size_t near=0;
    if(n==KD_NONE) return -1;
    for(size_t i=0;i<n;i++) {
        size_t nr=da_refs(c,names[i],refs,16);if(nr==KD_NONE) return -1;
        for(size_t j=0;j<nr;j++) if(refs[j]+0x100>=p && refs[j]<=p+0x100) near++;
    }
    if(near!=1) return da_fail("SecureRoot name context");
    size_t reject=sk_pattern(c,derived,sizeof(derived),&count),uid=KD_NONE;
    if(count!=1 || ((kd_word(c,reject+sizeof(derived))&0xff000010)!=0x54000000 && kd_word(c,reject+sizeof(derived))!=0xd503201f)) return da_fail("derived-key descriptor rejection");
    size_t lo=reject>0x40?reject-0x40:0;
    for(size_t q=lo;q<reject;q+=4) if(kd_word(c,q)==0x711f411f) { if(uid!=KD_NONE)return -1;uid=q+4; }
    if(uid==KD_NONE || ((kd_word(c,uid)&0xff00001f)!=0x54000000 && kd_word(c,uid)!=0xd503201f)) return da_fail("UID descriptor rejection");
    if(sk_word(c,p+12,0x52800028,"Trust SecureRoot for iOS 7 key derivation") ||
       sk_word(c,uid,0xd503201f,"Permit UID handle through iOS 7 descriptor wrapper") ||
       sk_word(c,reject+sizeof(derived),0xd503201f,"Permit derived handles through iOS 7 descriptor wrapper")) return -1;
    return 0;
}
