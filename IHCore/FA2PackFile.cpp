#include "FA2PackFile.h"
#include "ResourcePack/ResourcePack.h"
#include "Debug.h"
#include "ExtJson.h"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <mutex>

JsonObject GetIHCoreJson();
namespace {
// Process lifetime: streams may be destroyed after other static destructors.
FA2Pack::ResourcePackManager& Packs() { return FA2Pack::ResourcePackManager::instance(); }
std::recursive_mutex& PackMutex() { static auto* m = new std::recursive_mutex; return *m; }
}

void FA2PackInitialize()
{
    std::lock_guard<std::recursive_mutex> lock(PackMutex());
    static bool initialized = false;
    if (initialized) return;
    initialized = true;
    auto cfg = GetIHCoreJson();
    if (!cfg) return;
    auto list = cfg.GetObjectItem("FA2ResourcePacks");
    if (!list.Available() || !list.IsNotEmptyArray()) return;
    for (const auto& entry : list.GetArrayString()) {
        try {
            auto path = std::filesystem::path(entry);
            if (path.is_relative()) path = std::filesystem::path(SyringeData::ExecutableDirectoryPath()) / path;
            const auto name = path.string();
            const bool ok = Packs().loadPack(name);
            Debug::Log("IHCore : [FA2Pack] %s: %s\n", ok ? "loaded" : "FAILED (missing, corrupt or mismatched cipher)", name.c_str());
        } catch (const std::exception& e) {
            Debug::Log("IHCore : [FA2Pack] Failed to load %s: %s\n", entry.c_str(), e.what());
        }
    }
}

bool FA2PackContains(const char* name)
{
    if (!name || !*name) return false;
    std::lock_guard<std::recursive_mutex> lock(PackMutex());
    try { return Packs().hasFile(name); }
    catch (const std::exception&) { return false; }
}

struct FA2PackFile::State {
    std::string name;
    std::unique_ptr<uint8_t[]> data;
    size_t size = 0;
    int position = 0;
    bool open = false;
};
FA2PackFile::~FA2PackFile() { delete state; }
void FA2PackFile::Initialize() { state = new State; }
const char* FA2PackFile::GetFileName() const { return state ? state->name.c_str() : ""; }
const char* FA2PackFile::SetFileName(const char* name) {
    Close(); state->name = name ? name : ""; return GetFileName();
}
bool FA2PackFile::Exists(bool) { return state && FA2PackContains(state->name.c_str()); }
bool FA2PackFile::HasHandle() { return state && state->open; }
bool FA2PackFile::Open(FileAccessMode access) {
    if (!state || access != FileAccessMode::Read) return FALSE;
    Close();
    std::lock_guard<std::recursive_mutex> lock(PackMutex());
    try { state->data = Packs().getFileData(state->name, &state->size); }
    catch (const std::exception&) { state->data.reset(); }
    state->open = !!state->data;
    if (!state->open) {
        state->size = 0;
        Debug::Log("IHCore : [FA2Pack] Cannot decrypt %s\n", state->name.c_str());
    }
    return state->open ? TRUE : FALSE;
}
int FA2PackFile::ReadBytes(void* buffer, int count) {
    if (!HasHandle() || !buffer || count <= 0) return 0;
    const int amount = std::min(count, static_cast<int>(state->size) - state->position);
    if (amount) memcpy(buffer, state->data.get() + state->position, amount);
    state->position += amount;
    return amount;
}
int FA2PackFile::Seek(int offset, FileSeekMode origin) {
    if (!HasHandle()) return 0;
    int64_t base = 0;
    switch (origin) {
    case FileSeekMode::Set: break;
    case FileSeekMode::Current: base = state->position; break;
    case FileSeekMode::End: base = state->size; break;
    default: return state->position;
    }
    state->position = static_cast<int>(std::clamp<int64_t>(base + offset, 0, state->size));
    return state->position;
}
int FA2PackFile::GetFileSize() {
    if (!state) return 0;
    if (!state->open && !Open(FileAccessMode::Read)) return 0;
    return static_cast<int>(state->size);
}
void FA2PackFile::Close() {
    if (!state) return;
    state->data.reset(); state->size = 0; state->position = 0; state->open = false;
}
