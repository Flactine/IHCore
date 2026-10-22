#include "../Common/EncryptedMixFormat.h"
#include "EncryptedMix.h"
#include "EncryptedMixKey.h"
#include "ExtCD.h"
#include "Debug.h"
#include "../Common/LocalData.h"
#include "../Common/IHLoader/IH.File.h"

namespace {
constexpr char StreamName[] = "IHEncryptedMixFile";
class EncryptedMixFileClass final : public IHReadOnlyFileClass {
    // IH constructs registered streams as zeroed memory + vtable, then Initialize.
    std::string* name;
    IHEncryptedMix::Reader* reader;
    int position;
    bool opened;
    bool failed;
    bool EnsureReader() {
        if(failed)return false;
        if(reader)return true;
        try {
            IHEncryptedMix::Key key{};
            IHEncryptedMix::Require(IHEncryptedMixConfig::LoadKey(key.data()),"Encrypted MIX key not configured; run IHMixCrypt embed-key and rebuild IHCore");
            try { reader=new IHEncryptedMix::Reader(name->c_str(),key); }
            catch(...) { SecureZeroMemory(key.data(),key.size()); throw; }
            SecureZeroMemory(key.data(),key.size()); return true;
        } catch(const std::exception& e) {
            failed=true; Debug::Log("[EncryptedMix] %s: %s\n",name->c_str(),e.what()); return false;
        }
    }
public:
    explicit EncryptedMixFileClass(noinit_t n):IHReadOnlyFileClass(n),name(nullptr),reader(nullptr),position(0),opened(false),failed(false){}
    ~EncryptedMixFileClass() override {delete reader; delete name;}
    void Initialize() override {name=new std::string; reader=nullptr; position=0; opened=false; failed=false;}
    const char* GetFileName()const override{return name->c_str();}
    const char* SetFileName(const char* value)override {Close(); *name=value?value:""; return name->c_str();}
    bool Exists(bool=false)override{return EnsureReader();}
    bool HasHandle()override{return opened && !failed;}
    bool Open(FileAccessMode mode)override { if(mode!=FileAccessMode::Read)return false; position=0; opened=EnsureReader(); return opened; }
    int GetFileSize()override{return EnsureReader()?reader->Size():0;}
    int ReadBytes(void* buffer,int count)override {
        if(!opened || failed || !buffer || count<=0)return 0;
        try {auto n=reader->ReadAt(position,buffer,count); position+=static_cast<int>(n); return static_cast<int>(n);}
        catch(const std::exception& e) {failed=true; opened=false; Debug::Log("[EncryptedMix] %s: %s\n",name->c_str(),e.what()); return 0;}
    }
    int Seek(int offset,FileSeekMode mode)override {
        if(!EnsureReader())return 0;
        int64_t base=0;
        switch(mode) {case FileSeekMode::Set:break; case FileSeekMode::Current:base=position;break;case FileSeekMode::End:base=reader->Size();break;default:return position;}
        position=static_cast<int>(std::clamp<int64_t>(base+offset,0,reader->Size())); return position;
    }
    void Close()override {delete reader; reader=nullptr; opened=false; position=0; failed=false;}
};
}

void SetName_Impl(CDFileClass*,const std::string&,const char*);
void EncryptedMix_Register() {
    Local::RegisterIHFileStream(StreamName,{GetIHFileRegisterKey<EncryptedMixFileClass>(),sizeof(EncryptedMixFileClass)});
}
void EncryptedMix_TryBind(CDFileClass* file) {
    if(file->IHExtPtr || UseOriginalFileClass())return;
    const char* path=file->GetFileName();
    const char* extension=strrchr(path,'.');
    if(!extension || _stricmp(extension,".mix"))return;
    FILE* input=fopen(path,"rb"); if(!input)return;
    unsigned char magic[8]; bool encrypted=fread(magic,1,8,input)==8 && IHEncryptedMix::HasMagic(magic); fclose(input);
    if(!encrypted)return;
    // Bind even when the configured key is absent/incorrect: never feed ciphertext
    // into the original MIX parser. Open/Exists will report the precise error.
    std::string stablePath(path);
    const char* previous=file->FileName;
    SetName_Impl(file,StreamName,stablePath.c_str());
    if(file->IHExtPtr)CRT::free(const_cast<char*>(previous));
}
