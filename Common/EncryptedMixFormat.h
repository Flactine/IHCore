#pragma once
// IH encrypted MIX v1. All integers are little endian; Windows CNG is required.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <vector>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <climits>
#include <cerrno>
#pragma comment(lib, "bcrypt.lib")

namespace IHEncryptedMix {
constexpr uint32_t BlockSize = 65536;
constexpr size_t HeaderSize = 64;
using Key = std::array<unsigned char, 32>;
using Header = std::array<unsigned char, HeaderSize>;
inline void Require(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
inline void Check(NTSTATUS status) { Require(status >= 0, "Windows CNG operation failed"); }
inline void Put(unsigned char* p, uint64_t n, unsigned bytes) { for (unsigned i=0;i<bytes;++i) p[i] = static_cast<unsigned char>(n >> (8*i)); }
inline uint64_t Get(const unsigned char* p, unsigned bytes) { uint64_t n=0; for(unsigned i=0;i<bytes;++i) n |= uint64_t(p[i]) << (8*i); return n; }
inline bool HasMagic(const unsigned char* p) { return !memcmp(p, "IHMIXENC", 8); }
inline Key ParseKey(const std::string& text) {
    Require(text.size()==64, "Key must contain exactly 64 hexadecimal characters");
    Key key{};
    auto digit=[](char c)->int { if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; };
    for(size_t i=0;i<32;++i) { int a=digit(text[2*i]),b=digit(text[2*i+1]); Require(a>=0&&b>=0,"Invalid hexadecimal key"); key[i]=static_cast<unsigned char>((a<<4)|b); }
    return key;
}
struct File {
    FILE* p=nullptr;
    File()=default;
    explicit File(const char* name,const char* mode) {
        p=fopen(name,mode);
        if(!p) {
            const int error=errno;
            std::string message="Cannot open file '"+std::string(name)+"': ";
            if(error==EEXIST) message+="file already exists; refusing to overwrite it. Use a new output filename.";
            else if(error==ENOENT) message+="file or parent directory does not exist. Check the path and current working directory.";
            else if(error==EACCES) message+="access denied. Check directory permissions, read-only attributes, or whether the file is in use.";
            else message+=std::strerror(error);
            message+=" (errno="+std::to_string(error)+")";
            throw std::runtime_error(message);
        }
    }
    ~File(){ if(p) fclose(p); }
    File(const File&)=delete; File& operator=(const File&)=delete;
};
inline void Read(FILE* f,void* p,size_t n) { Require(fread(p,1,n,f)==n,"Truncated file or read error"); }
inline void Write(FILE* f,const void* p,size_t n) { Require(fwrite(p,1,n,f)==n,"File write failed"); }
inline uint64_t Size(FILE* f) { Require(_fseeki64(f,0,SEEK_END)==0,"Cannot seek file"); auto n=_ftelli64(f); Require(n>=0,"Cannot measure file"); Require(_fseeki64(f,0,SEEK_SET)==0,"Cannot rewind file"); return uint64_t(n); }
struct Algorithm {
    BCRYPT_ALG_HANDLE h=nullptr;
    Algorithm(LPCWSTR name,ULONG flags=0) { Check(BCryptOpenAlgorithmProvider(&h,name,nullptr,flags)); }
    ~Algorithm(){if(h)BCryptCloseAlgorithmProvider(h,0);}
    Algorithm(const Algorithm&)=delete;
};
class Cipher {
    Algorithm aes{BCRYPT_AES_ALGORITHM};
    BCRYPT_KEY_HANDLE key=nullptr;
public:
    Cipher(const Key& master,const Header& header) {
        Check(BCryptSetProperty(aes.h,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_GCM,sizeof(BCRYPT_CHAIN_MODE_GCM),0));
        Algorithm sha(BCRYPT_SHA256_ALGORITHM,BCRYPT_ALG_HANDLE_HMAC_FLAG);
        Key derived{};
        auto status=BCryptDeriveKeyPBKDF2(sha.h,const_cast<PUCHAR>(master.data()),32,const_cast<PUCHAR>(header.data()+24),16,10000,derived.data(),32,0);
        if(status>=0) status=BCryptGenerateSymmetricKey(aes.h,&key,nullptr,0,derived.data(),32,0);
        SecureZeroMemory(derived.data(),derived.size()); Check(status);
    }
    ~Cipher(){if(key)BCryptDestroyKey(key);}
    Cipher(const Cipher&)=delete;
    void Transform(bool encrypt,const Header& header,uint32_t index,const unsigned char* input,ULONG length,unsigned char* output,unsigned char* tag) {
        unsigned char nonce[12],aad[52];
        memcpy(nonce,header.data()+40,8); Put(nonce+8,index,4);
        memcpy(aad,header.data(),48); Put(aad+48,index,4);
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info; BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce=nonce; info.cbNonce=12; info.pbAuthData=aad; info.cbAuthData=52; info.pbTag=tag; info.cbTag=16;
        ULONG written=0; unsigned char dummy=0;
        auto in=length?const_cast<PUCHAR>(input):&dummy;
        auto out=length?output:&dummy;
        NTSTATUS status=encrypt ? BCryptEncrypt(key,in,length,&info,nullptr,0,out,length,&written,0) : BCryptDecrypt(key,in,length,&info,nullptr,0,out,length,&written,0);
        Require(status>=0 && written==length,"Authentication failed: wrong key, damaged or modified MIX");
    }
};
inline uint64_t ValidateHeader(const Header& h) {
    Require(HasMagic(h.data()) && Get(h.data()+8,4)==1,"Unsupported encrypted MIX format");
    Require(Get(h.data()+12,4)==BlockSize,"Invalid encrypted MIX block size");
    auto size=Get(h.data()+16,8);
    Require(size>0 && size<=INT_MAX,"MIX size must be between 1 and 2147483647 bytes"); return size;
}
class Reader {
    File file;
    Header header{};
    Cipher* cipher=nullptr;
    uint64_t length=0;
    uint32_t cached=UINT32_MAX;
    std::vector<unsigned char> plain;
public:
    Reader(const char* path,const Key& master):file(path,"rb") {
        auto physical=IHEncryptedMix::Size(file.p); Read(file.p,header.data(),header.size()); length=ValidateHeader(header);
        Require(physical==HeaderSize+length+16*((length+BlockSize-1)/BlockSize),"Invalid encrypted MIX length");
        Cipher temporary(master,header);
        temporary.Transform(false,header,UINT32_MAX,nullptr,0,nullptr,header.data()+48);
        cipher=new Cipher(master,header);
    }
    ~Reader(){ if(!plain.empty())SecureZeroMemory(plain.data(),plain.size()); delete cipher; }
    Reader(const Reader&)=delete;
    int Size()const{return static_cast<int>(length);}
    size_t ReadAt(uint64_t offset,void* output,size_t count) {
        if(offset>=length)return 0;
        count=static_cast<size_t>(std::min<uint64_t>(count,length-offset));
        auto dest=static_cast<unsigned char*>(output); size_t done=0;
        while(done<count) {
            auto index=static_cast<uint32_t>(offset/BlockSize);
            if(cached!=index) {
                cached=UINT32_MAX;
                if(!plain.empty())SecureZeroMemory(plain.data(),plain.size());
                auto n=static_cast<size_t>(std::min<uint64_t>(BlockSize,length-uint64_t(index)*BlockSize));
                std::vector<unsigned char> encrypted(n); unsigned char tag[16]; plain.resize(n);
                Require(_fseeki64(file.p,HeaderSize+uint64_t(index)*(BlockSize+16),SEEK_SET)==0,"Cannot seek encrypted MIX");
                Read(file.p,encrypted.data(),n); Read(file.p,tag,16);
                cipher->Transform(false,header,index,encrypted.data(),static_cast<ULONG>(n),plain.data(),tag); cached=index;
            }
            auto within=static_cast<size_t>(offset%BlockSize); auto n=std::min(count-done,plain.size()-within);
            memcpy(dest+done,plain.data()+within,n); done+=n; offset+=n;
        }
        return done;
    }
};
inline void Encrypt(FILE* input,FILE* output,const Key& master) {
    auto length=Size(input); Header h{}; memcpy(h.data(),"IHMIXENC",8); Put(h.data()+8,1,4); Put(h.data()+12,BlockSize,4); Put(h.data()+16,length,8);
    ValidateHeader(h); Check(BCryptGenRandom(nullptr,h.data()+24,24,BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    Cipher cipher(master,h); cipher.Transform(true,h,UINT32_MAX,nullptr,0,nullptr,h.data()+48); Write(output,h.data(),h.size());
    std::vector<unsigned char> plain(BlockSize),encrypted(BlockSize);
    for(uint32_t index=0;uint64_t(index)*BlockSize<length;++index) {
        auto n=static_cast<ULONG>(std::min<uint64_t>(BlockSize,length-uint64_t(index)*BlockSize)); unsigned char tag[16];
        Read(input,plain.data(),n); cipher.Transform(true,h,index,plain.data(),n,encrypted.data(),tag); Write(output,encrypted.data(),n); Write(output,tag,16);
    }
    SecureZeroMemory(plain.data(),plain.size()); Require(fflush(output)==0,"Cannot flush encrypted MIX");
}
}
