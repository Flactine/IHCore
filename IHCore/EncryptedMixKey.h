#pragma once
#include <cstddef>
// Generated private key material. Do not distribute. Not cryptographic key hiding.
namespace IHEncryptedMixConfig {
inline volatile unsigned char Mask[32] = {15,204,121,104,209,150,210,33,142,181,89,16,168,71,38,34,123,28,163,10,185,237,64,49,82,150,212,9,7,53,227,210};
inline volatile unsigned char Encoded[32] = {213,241,31,220,55,193,239,183,93,196,112,58,116,0,151,49,22,170,127,101,120,171,187,62,192,208,20,196,127,240,176,51};
__declspec(noinline) inline bool LoadKey(unsigned char* output) {
    for(std::size_t i=0;i<32;++i) output[(i*13+7)%32] = Encoded[i] ^ Mask[i];
    return true;
}
}
