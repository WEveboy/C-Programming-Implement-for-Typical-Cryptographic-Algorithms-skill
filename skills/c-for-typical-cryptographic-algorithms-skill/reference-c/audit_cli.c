/* Independently reconstructed audit kernels, not recovered book source.
 * C11, explicit byte order. Educational/data-validation scope; no security claim.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "constants.h"
_Static_assert(CHAR_BIT == 8, "8-bit bytes required");
static uint32_t load32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static void store32(uint8_t *p,uint32_t v) {
    for(unsigned i=0;i<4;i++) p[i]=(uint8_t)(v>>(24-8*i));
}
static uint32_t rot32(uint32_t x,unsigned n) { n &= 31; return (x<<n)|(x>>((32-n)&31)); }
static uint64_t rot64(uint64_t x,unsigned n) { n &= 63; return (x<<n)|(x>>((64-n)&63)); }
static uint64_t perm(uint64_t x,unsigned width,const uint8_t *table,unsigned count) {
    uint64_t r=0;
    for(unsigned i=0;i<count;i++) r=(r<<1)|((x>>(width-table[i]))&1);
    return r;
}
static void des_block(const uint8_t *key,const uint8_t *in,uint8_t *out,int decrypt) {
    uint64_t k=0,b=0,roundkey[16];
    for(unsigned i=0;i<8;i++) { k=(k<<8)|key[i]; b=(b<<8)|in[i]; }
    k=perm(k,64,des_pc1,56);
    uint32_t c=(uint32_t)(k>>28),d=(uint32_t)(k&0xfffffff);
    for(unsigned i=0;i<16;i++) {
        unsigned n=des_shifts[i];
        c=((c<<n)|(c>>(28-n)))&0xfffffff;
        d=((d<<n)|(d>>(28-n)))&0xfffffff;
        roundkey[i]=perm(((uint64_t)c<<28)|d,56,des_pc2,48);
    }
    b=perm(b,64,des_ip,64);
    uint32_t l=(uint32_t)(b>>32),r=(uint32_t)b;
    for(unsigned i=0;i<16;i++) {
        uint64_t e=perm(r,32,des_e,48)^roundkey[decrypt?15-i:i];
        uint32_t s=0;
        for(unsigned j=0;j<8;j++) {
            unsigned a=(unsigned)((e>>(42-6*j))&63);
            unsigned row=((a&32)>>4)|(a&1),col=(a>>1)&15;
            s=(s<<4)|des_s[j][16*row+col];
        }
        uint32_t next=l^(uint32_t)perm(s,32,des_p,32); l=r; r=next;
    }
    b=perm(((uint64_t)r<<32)|l,64,des_fp,64);
    for(unsigned i=0;i<8;i++) out[i]=(uint8_t)(b>>(56-8*i));
}
static uint8_t gf_mul(uint8_t a,uint8_t b) {
    uint8_t r=0;
    for(unsigned i=0;i<8;i++) {
        if(b&1) r^=a;
        unsigned top=a>>7; a=(uint8_t)(a<<1); if(top) a^=0x1b; b>>=1;
    }
    return r;
}
static void aes_shift(uint8_t s[16],int inverse) {
    uint8_t t[16];
    for(unsigned r=0;r<4;r++) for(unsigned c=0;c<4;c++)
        t[4*c+r]=s[4*((c+(inverse?4-r:r))%4)+r];
    memcpy(s,t,16);
}
static void aes_mix(uint8_t s[16],int inverse) {
    static const uint8_t forward[4]={2,3,1,1},backward[4]={14,11,13,9};
    const uint8_t *m=inverse?backward:forward; uint8_t t[16];
    for(unsigned c=0;c<4;c++) for(unsigned r=0;r<4;r++) {
        uint8_t v=0;
        for(unsigned j=0;j<4;j++) v^=gf_mul(s[4*c+j],m[(j+4-r)%4]);
        t[4*c+r]=v;
    }
    memcpy(s,t,16);
}
static void aes_add(uint8_t s[16],const uint8_t *key) { for(unsigned i=0;i<16;i++) s[i]^=key[i]; }
static void aes_block(const uint8_t *key,size_t keylen,const uint8_t *in,uint8_t *out,int inverse) {
    uint8_t rk[240],temp[4],rcon=1,s[16]; unsigned nk=(unsigned)keylen/4,nr=nk+6;
    memcpy(rk,key,keylen); memcpy(s,in,16);
    for(unsigned i=nk;i<4*(nr+1);i++) {
        memcpy(temp,rk+4*(i-1),4);
        if(i%nk==0) {
            uint8_t t=temp[0]; temp[0]=aes_s[temp[1]]^rcon; temp[1]=aes_s[temp[2]];
            temp[2]=aes_s[temp[3]]; temp[3]=aes_s[t]; rcon=gf_mul(rcon,2);
        } else if(nk==8 && i%nk==4) for(unsigned j=0;j<4;j++) temp[j]=aes_s[temp[j]];
        for(unsigned j=0;j<4;j++) rk[4*i+j]=rk[4*(i-nk)+j]^temp[j];
    }
    if(!inverse) {
        aes_add(s,rk);
        for(unsigned r=1;r<=nr;r++) {
            for(unsigned i=0;i<16;i++) s[i]=aes_s[s[i]];
            aes_shift(s,0); if(r!=nr) aes_mix(s,0); aes_add(s,rk+16*r);
        }
    } else {
        aes_add(s,rk+16*nr);
        for(unsigned r=nr;r>0;r--) {
            aes_shift(s,1); for(unsigned i=0;i<16;i++) s[i]=aes_inv[s[i]];
            aes_add(s,rk+16*(r-1)); if(r!=1) aes_mix(s,1);
        }
    }
    memcpy(out,s,16);
}
static uint32_t sm4_tau(uint32_t x) {
    return ((uint32_t)sm4_s[x>>24]<<24)|((uint32_t)sm4_s[(x>>16)&255]<<16)|
           ((uint32_t)sm4_s[(x>>8)&255]<<8)|sm4_s[x&255];
}
static uint32_t sm4_l(uint32_t x,int key) {
    return key?(x^rot32(x,13)^rot32(x,23)):(x^rot32(x,2)^rot32(x,10)^rot32(x,18)^rot32(x,24));
}
static void sm4_block(const uint8_t *key,const uint8_t *in,uint8_t *out,int inverse,int trace) {
    static const uint32_t fk[4]={0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc};
    uint32_t k[36],x[36],rk[32];
    for(unsigned i=0;i<4;i++) { k[i]=load32(key+4*i)^fk[i]; x[i]=load32(in+4*i); }
    for(unsigned i=0;i<32;i++) {
        uint32_t ck=0;
        for(unsigned j=0;j<4;j++) ck=(ck<<8)|(((4*i+j)*7)&255);
        rk[i]=k[i+4]=k[i]^sm4_l(sm4_tau(k[i+1]^k[i+2]^k[i+3]^ck),1);
    }
    for(unsigned i=0;i<32;i++) {
        x[i+4]=x[i]^sm4_l(sm4_tau(x[i+1]^x[i+2]^x[i+3]^rk[inverse?31-i:i]),0);
        if(trace) printf("%08lx %08lx\n",(unsigned long)rk[i],(unsigned long)x[i+4]);
    }
    for(unsigned i=0;i<4;i++) store32(out+4*i,x[35-i]);
}
typedef struct { uint32_t s[16],r1,r2,x[4]; } zuc_state;
static void zuc_br(zuc_state *z) {
    z->x[0]=((z->s[15]&0x7fff8000)<<1)|(z->s[14]&0xffff);
    z->x[1]=((z->s[11]&0xffff)<<16)|(z->s[9]>>15);
    z->x[2]=((z->s[7]&0xffff)<<16)|(z->s[5]>>15);
    z->x[3]=((z->s[2]&0xffff)<<16)|(z->s[0]>>15);
}
static uint32_t zuc_sub(uint32_t x) {
    return ((uint32_t)zuc_s0[x>>24]<<24)|((uint32_t)zuc_s1[(x>>16)&255]<<16)|
           ((uint32_t)zuc_s0[(x>>8)&255]<<8)|zuc_s1[x&255];
}
static uint32_t zuc_f(zuc_state *z) {
    uint32_t w=(z->x[0]^z->r1)+z->r2,w1=z->r1+z->x[1],w2=z->r2^z->x[2];
    uint32_t u=(w1<<16)|(w2>>16),v=(w2<<16)|(w1>>16);
    z->r1=zuc_sub(u^rot32(u,2)^rot32(u,10)^rot32(u,18)^rot32(u,24));
    z->r2=zuc_sub(v^rot32(v,8)^rot32(v,14)^rot32(v,22)^rot32(v,30));
    return w;
}
static void zuc_lfsr(zuc_state *z,uint32_t u) {
    uint64_t v=((uint64_t)z->s[15]<<15)+((uint64_t)z->s[13]<<17)+
               ((uint64_t)z->s[10]<<21)+((uint64_t)z->s[4]<<20)+
               ((uint64_t)z->s[0]<<8)+z->s[0]+u;
    uint32_t a=(uint32_t)(v%UINT32_C(0x7fffffff)); if(a==0) a=0x7fffffff;
    for(unsigned i=0;i<15;i++) z->s[i]=z->s[i+1];
    z->s[15]=a;
}
static void zuc(const uint8_t *key,const uint8_t *iv,uint8_t *out,size_t words) {
    static const uint16_t d[16]={0x44d7,0x26bc,0x626b,0x135e,0x5789,0x35e2,0x7135,0x09af,
        0x4d78,0x2f13,0x6bc4,0x1af1,0x5e26,0x3c4d,0x789a,0x47ac};
    zuc_state z; memset(&z,0,sizeof z);
    for(unsigned i=0;i<16;i++) z.s[i]=((uint32_t)key[i]<<23)|((uint32_t)d[i]<<8)|iv[i];
    for(unsigned i=0;i<32;i++) { zuc_br(&z); uint32_t w=zuc_f(&z); zuc_lfsr(&z,w>>1); }
    zuc_br(&z); (void)zuc_f(&z); zuc_lfsr(&z,0);
    for(size_t i=0;i<words;i++) { zuc_br(&z); uint32_t w=zuc_f(&z); store32(out+4*i,w^z.x[3]); zuc_lfsr(&z,0); }
}
static void keccak_f(uint64_t a[25]) {
    static const uint64_t rc[24]={UINT64_C(0x1),UINT64_C(0x8082),UINT64_C(0x800000000000808a),UINT64_C(0x8000000080008000),
        UINT64_C(0x808b),UINT64_C(0x80000001),UINT64_C(0x8000000080008081),UINT64_C(0x8000000000008009),
        UINT64_C(0x8a),UINT64_C(0x88),UINT64_C(0x80008009),UINT64_C(0x8000000a),UINT64_C(0x8000808b),
        UINT64_C(0x800000000000008b),UINT64_C(0x8000000000008089),UINT64_C(0x8000000000008003),
        UINT64_C(0x8000000000008002),UINT64_C(0x8000000000000080),UINT64_C(0x800a),UINT64_C(0x800000008000000a),
        UINT64_C(0x8000000080008081),UINT64_C(0x8000000000008080),UINT64_C(0x80000001),UINT64_C(0x8000000080008008)};
    static const unsigned rho[25]={0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};
    for(unsigned round=0;round<24;round++) {
        uint64_t c[5],d[5],b[25];
        for(unsigned x=0;x<5;x++) c[x]=a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20];
        for(unsigned x=0;x<5;x++) d[x]=c[(x+4)%5]^rot64(c[(x+1)%5],1);
        for(unsigned y=0;y<5;y++) for(unsigned x=0;x<5;x++)
            b[y+5*((2*x+3*y)%5)]=rot64(a[x+5*y]^d[x],rho[x+5*y]);
        for(unsigned y=0;y<5;y++) for(unsigned x=0;x<5;x++)
            a[x+5*y]=b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y]);
        a[0]^=rc[round];
    }
}
static void sha3(const uint8_t *msg,size_t len,uint8_t *out,size_t outlen,uint8_t domain) {
    uint64_t a[25]={0}; size_t rate=200-2*outlen;
    while(len>=rate) {
        for(size_t i=0;i<rate;i++) a[i/8]^=(uint64_t)msg[i]<<(8*(i%8));
        keccak_f(a); msg+=rate; len-=rate;
    }
    for(size_t i=0;i<len;i++) a[i/8]^=(uint64_t)msg[i]<<(8*(i%8));
    a[len/8]^=(uint64_t)domain<<(8*(len%8));
    a[(rate-1)/8]^=UINT64_C(0x80)<<(8*((rate-1)%8)); keccak_f(a);
    for(size_t i=0;i<outlen;i++) out[i]=(uint8_t)(a[i/8]>>(8*(i%8)));
}
static int hexval(char c) { if(c>='0'&&c<='9') return c-'0'; if(c>='a'&&c<='f') return c-'a'+10; if(c>='A'&&c<='F') return c-'A'+10; return -1; }
static int unhex(const char *s,uint8_t *out,size_t cap,size_t *size) {
    size_t n=strlen(s); if(n%2 || n/2>cap) return 0;
    for(size_t i=0;i<n/2;i++) { int a=hexval(s[2*i]),b=hexval(s[2*i+1]); if(a<0||b<0) return 0; out[i]=(uint8_t)(16*a+b); }
    *size=n/2; return 1;
}
int main(int argc,char **argv) {
    uint8_t key[32],input[8192],output[8192]; size_t kl=0,n=0,outlen=0;
    if(argc!=5) return 2;
    int inverse=strcmp(argv[2],"dec")==0;
    if(strcmp(argv[2],"enc") && strcmp(argv[2],"dec")) return 2;
    if(!unhex(argv[3],key,sizeof key,&kl)||!unhex(argv[4],input,sizeof input,&n)) return 2;
    if(!strcmp(argv[1],"des")) {
        if(kl!=8||n!=8) return 2;
        des_block(key,input,output,inverse); outlen=8;
    } else if(!strcmp(argv[1],"aes")) {
        if((kl!=16&&kl!=24&&kl!=32)||n!=16) return 2;
        aes_block(key,kl,input,output,inverse); outlen=16;
    } else if(!strcmp(argv[1],"sm4")||!strcmp(argv[1],"sm4trace")) {
        if(kl!=16||n!=16) return 2;
        sm4_block(key,input,output,inverse,!strcmp(argv[1],"sm4trace")); outlen=16;
    } else if(!strcmp(argv[1],"zuc")) {
        if(kl!=16||n!=16||inverse) return 2;
        zuc(key,input,output,2); outlen=8;
    } else if(!strncmp(argv[1],"sha3-",5)||!strcmp(argv[1],"keccak-256")) {
        if(kl||inverse) return 2;
        if(!strcmp(argv[1],"keccak-256")) outlen=32;
        else if(!strcmp(argv[1],"sha3-224")) outlen=28;
        else if(!strcmp(argv[1],"sha3-256")) outlen=32;
        else if(!strcmp(argv[1],"sha3-384")) outlen=48;
        else if(!strcmp(argv[1],"sha3-512")) outlen=64;
        else return 2;
        sha3(input,n,output,outlen,(uint8_t)(argv[1][0]=='k'?1:6));
    } else return 2;
    for(size_t i=0;i<outlen;i++) printf("%02x",output[i]);
    putchar('\n'); return 0;
}
