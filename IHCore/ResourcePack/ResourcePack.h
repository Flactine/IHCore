#pragma once
#include <array>
#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <fstream>
#include "Body.Cipher.h"
namespace FA2Pack {
using NameTag = std::array<uint8_t, ResourceCipher::kNameTagLen>;
// Random per entry id. The name table pairs a token with one of these, so the token never
// has to be stored next to the entry it belongs to.
using EntryId = std::array<uint8_t, ResourceCipher::kEntryIdLen>;

template <size_t N>
struct ArrayHash
{
	size_t operator()(const std::array<uint8_t, N>& key) const
	{
		size_t h = 2166136261u;
		for (uint8_t b : key)
		{
			h ^= b;
			h *= 16777619u;
		}
		return h;
	}
};

struct PackIndexEntry
{
	uint32_t tailOffset;   // offset of salt/prevChain/params/mac inside the decrypted index
	uint32_t dataOffset;   // offset of the entry key part inside the data region
	uint32_t entryIndex;   // ordinal inside the pack
	uint32_t encSize;
	uint32_t rawSize;
	uint64_t parentInfo;
	uint16_t slot;
	uint16_t saltLen;
	uint16_t prevChainLen;
	uint16_t paramsLen;
	uint16_t macLen;
};

class ResourcePack 
{
public:
	bool load(const std::string& filename);
	// The token is the key; name is the name the entry was packed under and is needed again
	// only because the content key is derived from it.
	std::unique_ptr<uint8_t[]> getFileData(const uint8_t nameTag[ResourceCipher::kNameTagLen],
		const char* name, size_t nameLen, size_t* out_size = nullptr, bool debugLog = false);
	bool hasFile(const uint8_t nameTag[ResourceCipher::kNameTagLen]) const;
	// Nonce of this pack. The token is derived from it, so it is needed to look anything up
	// in this pack and cannot be shared between packs.
	const uint8_t* packNonce() const { return pack_nonce.data(); }

private:
	std::unordered_map<NameTag, PackIndexEntry, ArrayHash<ResourceCipher::kNameTagLen>> index_map;
	std::vector<uint8_t> index_plain;
	std::vector<uint8_t> pack_key_part;
	std::vector<uint8_t> index_key_part;
	std::array<uint8_t, ResourceCipher::kMacLen> index_mac{};
	std::array<uint8_t, ResourceCipher::kPackIdLen> pack_id{};
	std::array<uint8_t, ResourceCipher::kPackNonceLen> pack_nonce{};
	ResourceCipher::PackContext pack_ctx{};
	ResourceCipher::LayoutInfo layout{};
	size_t data_region_offset = 0;
	uint64_t data_region_size = 0;
	std::string file_path;
	std::ifstream file_stream; 

	bool parseIndex(const uint8_t* data, size_t len);
	const uint8_t* tailPtr(const PackIndexEntry& entry) const { return index_plain.data() + entry.tailOffset; }
};

class ResourcePackManager 
{
public:

	static ResourcePackManager& instance();
	bool loadPack(const std::string& packPath);
	std::unique_ptr<uint8_t[]> getFileData(const std::string& filename, size_t* out_size = nullptr);
	bool hasFile(const std::string& filename);
	void clear();

private:
	std::vector<std::unique_ptr<ResourcePack>> packs;

	// A token costs a memory hard KDF, so it is computed once per distinct name and reused
	// for every pack that gets asked about it.
	std::mutex name_tag_mutex;
	// One table per pack: the token depends on that pack's nonce, so a single name maps to a
	// different token in every pack.
	std::unordered_map<size_t, std::unordered_map<std::string, NameTag>> name_tag_cache;

	bool nameTagFor(size_t packIndex, const std::string& filename, std::string& name, uint8_t* out);
};


}
