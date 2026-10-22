#pragma once
#include "../../Common/EncryptedMixFormat.h"
#include <sstream>
// Encoding only: this prevents plain string searches, not reverse engineering.
inline void WriteEmbeddedKey(const IHEncryptedMix::Key& key,const char* path) {
    using namespace IHEncryptedMix;
    const char* extension=strrchr(path,'.');
    Require(extension && _stricmp(extension,".h")==0,"Output must be a .h header, not a key file");
    Key mask{}; Check(BCryptGenRandom(nullptr,mask.data(),32,BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    std::ostringstream source;
    source<<"#pragma once\n#include <cstddef>\n// Generated private key material. Do not distribute. Not cryptographic key hiding.\nnamespace IHEncryptedMixConfig {\n";
    auto array=[&](const char* name,bool encoded) {
        source<<"inline volatile unsigned char "<<name<<"[32] = {";
        for(size_t i=0;i<32;++i) {if(i)source<<',';source<<unsigned(encoded ? (key[(i*13+7)%32]^mask[i]) : mask[i]);}
        source<<"};\n";
    };
    array("Mask",false);array("Encoded",true);
    source<<"__declspec(noinline) inline bool LoadKey(unsigned char* output) {\n"
        <<"    for(std::size_t i=0;i<32;++i) output[(i*13+7)%32] = Encoded[i] ^ Mask[i];\n"
        <<"    return true;\n}\n}\n";
    auto text=source.str();File output(path,"wb");Write(output.p,text.data(),text.size());Require(fflush(output.p)==0,"Cannot flush key header");
    SecureZeroMemory(mask.data(),mask.size());
}
