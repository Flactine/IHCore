#pragma once
#include "../Common/IHLoader/IH.File.h"

inline constexpr const char* FA2PackStreamName = "FA2PackFile";
void FA2PackInitialize();
bool FA2PackContains(const char* name);

// IHCore constructs streams by installing the vtable on zeroed memory.
// Keep owning C++ objects in State, allocated by Initialize, not inline members.
class FA2PackFile final : public IHReadOnlyFileClass
{
public:
    explicit FA2PackFile(noinit_t n) : IHReadOnlyFileClass(n) {}
    ~FA2PackFile() override;
    void Initialize() override;
    const char* GetFileName() const override;
    const char* SetFileName(const char* name) override;
    bool Exists(bool writeShared = false) override;
    bool HasHandle() override;
    bool Open(FileAccessMode access) override;
    int ReadBytes(void* buffer, int count) override;
    int Seek(int offset, FileSeekMode origin) override;
    int GetFileSize() override;
    void Close() override;
private:
    struct State;
    State* state = nullptr;
};
