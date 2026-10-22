#include "ResourcePack.h"
#include <cassert>
#include <cstring>
#include <iostream>
#include <iterator>
int main(int argc, char**) {
    auto& m = FA2Pack::ResourcePackManager::instance();
    if (argc > 1) { assert(!m.loadPack("packs/one.pack")); std::cout << "mismatched cipher rejected\n"; return 0; }
    assert(m.loadPack("packs/one.pack"));
    assert(m.loadPack("packs/two.pack"));
    assert(m.hasFile("EXAMPLE.INI"));
    assert(!m.hasFile("missing.ini"));
    size_t n = 0;
    auto data = m.getFileData("EXAMPLE.INI", &n);
    assert(data && n == 18 && !memcmp(data.get(), "[Test]\r\nValue=42\r\n", n));
    data = m.getFileData("empty.bin", &n); assert(data && n == 0);
    data = m.getFileData("binary.bin", &n); assert(data && n == 256);
    for (size_t i=0;i<n;++i) assert(data[i] == i);
    std::ifstream in("packs/two.pack", std::ios::binary);
    std::vector<char> bytes((std::istreambuf_iterator<char>(in)), {});
    bytes.back() ^= 1;
    { std::ofstream out("packs/corrupt.pack", std::ios::binary); out.write(bytes.data(), bytes.size()); }
    m.clear(); assert(m.loadPack("packs/corrupt.pack"));
    assert(!m.getFileData("binary.bin"));
    bytes.resize(30);
    { std::ofstream out("packs/short.pack", std::ios::binary); out.write(bytes.data(), bytes.size()); }
    assert(!m.loadPack("packs/short.pack"));
    m.clear(); assert(m.loadPack("packs/two.pack"));
    assert(m.getFileData("BINARY.BIN", &n) && n == 256);
    std::cout << "PASS: round-trip, case, empty, missing, multiple packs, corrupt payload, truncated header, reload\n";
}
