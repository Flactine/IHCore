#include "../../Common/EncryptedMixFormat.h"
#include <iostream>
#include <random>
#include "EmbeddedKey.h"
using namespace IHEncryptedMix;

Key LoadKey(const char* path) {
    File f(path,"rb"); char text[67]{}; size_t n=fread(text,1,sizeof(text),f.p);
    std::string value(text,n); while(!value.empty()&&(value.back()=='\n'||value.back()=='\r'))value.pop_back();
    auto key=ParseKey(value); SecureZeroMemory(value.data(),value.size()); return key;
}
void Test(const char* directory) {
    std::string base=std::string(directory)+"/ihmix-test-"+std::to_string(GetCurrentProcessId());
    Key key{}; for(size_t i=0;i<key.size();++i)key[i]=static_cast<unsigned char>(i);
    for(size_t length : {size_t(1),size_t(65535),size_t(65536),size_t(65537),size_t(196741)}) {
        std::string source=base+".raw",target=base+".mix";
        std::vector<unsigned char> expected(length); for(size_t i=0;i<length;++i)expected[i]=static_cast<unsigned char>((i*37+i/251)%256);
        { File f(source.c_str(),"wb"); Write(f.p,expected.data(),expected.size()); }
        { File in(source.c_str(),"rb"),out(target.c_str(),"wb"); Encrypt(in.p,out.p,key); }
        {
            Reader r(target.c_str(),key); Require(static_cast<size_t>(r.Size())==length,"Size test failed"); std::mt19937 random(123);
            for(int i=0;i<150;++i) {
                size_t offset=i==0?0:random()%(length+100),count=i==0?length:random()%100000;
                std::vector<unsigned char> actual(count); auto n=r.ReadAt(offset,actual.data(),count);
                auto wanted=offset>=length?0:std::min(count,length-offset);
                Require(n==wanted && (n==0 || !memcmp(actual.data(),expected.data()+offset,n)),"Random read test failed");
            }
        }
        auto rejects=[&](const Key& k) {try{Reader r(target.c_str(),k);std::vector<unsigned char> data(length);r.ReadAt(0,data.data(),data.size());}catch(const std::exception&){return true;}return false;};
        Key wrong=key;wrong[0]^=1;Require(rejects(wrong),"Wrong key accepted");
        auto flip=[&](int64_t offset) {File f(target.c_str(),"r+b");Require(_fseeki64(f.p,offset,SEEK_SET)==0,"Test seek failed");int c=fgetc(f.p);Require(c!=EOF,"Test read failed");_fseeki64(f.p,offset,SEEK_SET);fputc(c^1,f.p);};
        for(int64_t offset : {int64_t(8),int64_t(16),int64_t(24),int64_t(40),int64_t(48),int64_t(64),int64_t(HeaderSize+length+16*((length+BlockSize-1)/BlockSize)-1)}) {
            flip(offset);Require(rejects(key),"Tampering accepted");flip(offset);
        }
        { File f(target.c_str(),"ab"); fputc(0,f.p); } Require(rejects(key),"Trailing bytes accepted");
        // Truncate the last tag; a damaged container must be rejected before use.
        {File in(source.c_str(),"rb"),out(target.c_str(),"wb");Encrypt(in.p,out.p,key);}
        {HANDLE h=CreateFileA(target.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);Require(h!=INVALID_HANDLE_VALUE,"Test open failed");LARGE_INTEGER end;end.QuadPart=-1;SetFilePointerEx(h,end,nullptr,FILE_END);SetEndOfFile(h);CloseHandle(h);}
        Require(rejects(key),"Truncated file accepted");
        remove(source.c_str());remove(target.c_str());
    }
    std::cout<<"PASS: boundaries, random reads, EOF, wrong key, header/payload/tag tampering, truncation and trailing bytes\n";
}
int main(int argc,char** argv) {
    try {
        if(argc==3 && std::string(argv[1])=="selftest") {Test(argv[2]);return 0;}
        if(argc==4 && std::string(argv[1])=="embed-key") {
            auto key=LoadKey(argv[2]);
            try { WriteEmbeddedKey(key,argv[3]); }
            catch(...) { SecureZeroMemory(key.data(),key.size()); throw; }
            SecureZeroMemory(key.data(),key.size());
            std::cout<<"Encoded key header written. Rebuild IHCore before distribution.\n";return 0;
        }
        if(argc==3 && std::string(argv[1])=="keygen") {
            Key key{};Check(BCryptGenRandom(nullptr,key.data(),32,BCRYPT_USE_SYSTEM_PREFERRED_RNG));
            File output(argv[2],"wbx");const char* digits="0123456789abcdef";char text[65];
            for(size_t i=0;i<32;++i){text[2*i]=digits[key[i]>>4];text[2*i+1]=digits[key[i]&15];}text[64]='\n';Write(output.p,text,sizeof(text));Require(fflush(output.p)==0,"Cannot flush key file");SecureZeroMemory(key.data(),key.size());SecureZeroMemory(text,sizeof(text));
            std::cout<<"Key file created. Keep it private.\n";return 0;
        }
        if(argc==5 && std::string(argv[1])=="encrypt") {
            auto key=LoadKey(argv[4]);
            File input(argv[2],"rb");
            unsigned char magic[8]{};auto n=fread(magic,1,8,input.p);Require(n!=8||!HasMagic(magic),"Input is already encrypted");
            // Exclusive create avoids overwriting the input or an existing release asset.
            File output(argv[3],"wbx"); Encrypt(input.p,output.p,key);SecureZeroMemory(key.data(),key.size());
            std::cout<<"Encrypted MIX written.\n";return 0;
        }
        if(argc==4 && std::string(argv[1])=="verify") {
            auto key=LoadKey(argv[3]);Reader reader(argv[2],key);SecureZeroMemory(key.data(),key.size());std::vector<unsigned char> buffer(BlockSize);
            for(uint64_t offset=0;offset<static_cast<uint64_t>(reader.Size());offset+=BlockSize)reader.ReadAt(offset,buffer.data(),buffer.size());
            SecureZeroMemory(buffer.data(),buffer.size());std::cout<<"All blocks authenticated.\n";return 0;
        }
        std::cerr<<"Usage:\n  IHMixCrypt keygen KEYFILE\n  IHMixCrypt embed-key KEYFILE OUTPUT_HEADER\n  IHMixCrypt encrypt INPUT.mix OUTPUT.mix KEYFILE\n  IHMixCrypt verify INPUT.mix KEYFILE\n  IHMixCrypt selftest TEMP_DIRECTORY\n";return 2;
    }catch(const std::exception& e){std::cerr<<"Error: "<<e.what()<<"\n";return 1;}
}
