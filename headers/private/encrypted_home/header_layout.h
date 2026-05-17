/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#ifndef _PRIVATE_ENCRYPTED_HOME_HEADER_LAYOUT_H
#define _PRIVATE_ENCRYPTED_HOME_HEADER_LAYOUT_H


#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>


namespace BPrivate::EncryptedHome::wire {

inline constexpr std::size_t kHeaderSize = 4096;

inline constexpr std::size_t kMagicOffset = 0x000;
inline constexpr std::size_t kMagicSize = 8;
inline constexpr std::array<unsigned char, kMagicSize> kMagic = {
	'H', 'A', 'I', 'K', 'U', 'E', 'N', 'C'
};

inline constexpr std::size_t kVersionOffset = 0x008;
inline constexpr std::size_t kVersionSize = 2;
inline constexpr std::uint16_t kHeaderVersion = 1;

inline constexpr std::size_t kFlagsOffset = 0x00a;
inline constexpr std::size_t kFlagsSize = 2;

inline constexpr std::size_t kSectorSizeOffset = 0x00c;
inline constexpr std::size_t kSectorSizeSize = 4;

inline constexpr std::size_t kPayloadOffsetSectorsOffset = 0x010;
inline constexpr std::size_t kPayloadOffsetSectorsSize = 8;
inline constexpr std::uint64_t kPayloadOffsetSectors = 16;

inline constexpr std::size_t kPayloadSizeSectorsOffset = 0x018;
inline constexpr std::size_t kPayloadSizeSectorsSize = 8;

inline constexpr std::size_t kCipherIdOffset = 0x020;
inline constexpr std::size_t kCipherIdSize = 4;
inline constexpr std::uint32_t kCipherAES128XTS = 1;
inline constexpr std::uint32_t kCipherAES256XTS = 2;

inline constexpr std::size_t kKdfIdOffset = 0x024;
inline constexpr std::size_t kKdfIdSize = 4;
inline constexpr std::uint32_t kKdfArgon2id = 1;

inline constexpr std::size_t kArgon2TimeCostOffset = 0x028;
inline constexpr std::size_t kArgon2TimeCostSize = 4;
inline constexpr std::uint32_t kDefaultArgon2TimeCost = 3;
inline constexpr std::uint32_t kMaxArgon2TimeCost = 10;

inline constexpr std::size_t kArgon2MemoryCostOffset = 0x02c;
inline constexpr std::size_t kArgon2MemoryCostSize = 4;
inline constexpr std::uint32_t kDefaultArgon2MemoryCostKiB = 65536;
inline constexpr std::uint32_t kMaxArgon2MemoryCostKiB = 65536;

inline constexpr std::size_t kArgon2ParallelismOffset = 0x030;
inline constexpr std::size_t kArgon2ParallelismSize = 4;
inline constexpr std::uint32_t kDefaultArgon2Parallelism = 4;
inline constexpr std::uint32_t kMaxArgon2Parallelism = 16;

inline constexpr std::size_t kReserved0Offset = 0x034;
inline constexpr std::size_t kReserved0Size = 12;

inline constexpr std::size_t kVolumeUuidOffset = 0x040;
inline constexpr std::size_t kVolumeUuidSize = 16;

inline constexpr std::size_t kKdfSaltOffset = 0x050;
inline constexpr std::size_t kKdfSaltSize = 32;

inline constexpr std::size_t kWrappedMasterKeyOffset = 0x070;
inline constexpr std::size_t kWrappedMasterKeySize = 72;
inline constexpr std::size_t kAes128WrappedMasterKeySize = 40;

inline constexpr std::size_t kSequenceNumberOffset = 0x0b8;
inline constexpr std::size_t kSequenceNumberSize = 4;

inline constexpr std::size_t kReserved1Offset = 0x0bc;
inline constexpr std::size_t kReserved1Size = 4;

inline constexpr std::size_t kHeaderHmacOffset = 0x0c0;
inline constexpr std::size_t kHeaderHmacSize = 32;
inline constexpr std::size_t kHmacCoveredEnd = kHeaderHmacOffset;

inline constexpr std::size_t kPaddingOffset = 0x0e0;
inline constexpr std::size_t kPaddingSize = kHeaderSize - kPaddingOffset;

struct HeaderField {
	std::string_view name;
	std::size_t offset;
	std::size_t size;
	std::string_view description;
};

inline constexpr std::array<HeaderField, 19> kHeaderFields = {{
	{"magic", kMagicOffset, kMagicSize, "\"HAIKUENC\""},
	{"version", kVersionOffset, kVersionSize, "Format version; currently 1"},
	{"flags", kFlagsOffset, kFlagsSize, "Reserved for v1; must be zero"},
	{"sector_size", kSectorSizeOffset, kSectorSizeSize, "512 or 4096"},
	{"payload_offset_sectors", kPayloadOffsetSectorsOffset,
		kPayloadOffsetSectorsSize, "First plaintext payload sector; always 16"},
	{"payload_size_sectors", kPayloadSizeSectorsOffset,
		kPayloadSizeSectorsSize, "Plaintext payload size in sectors"},
	{"cipher_id", kCipherIdOffset, kCipherIdSize,
		"1 = AES-128-XTS, 2 = AES-256-XTS"},
	{"kdf_id", kKdfIdOffset, kKdfIdSize, "1 = Argon2id"},
	{"argon2_t_cost", kArgon2TimeCostOffset, kArgon2TimeCostSize,
		"Argon2id time cost"},
	{"argon2_m_cost", kArgon2MemoryCostOffset, kArgon2MemoryCostSize,
		"Argon2id memory cost in KiB"},
	{"argon2_parallelism", kArgon2ParallelismOffset,
		kArgon2ParallelismSize, "Argon2id lane count"},
	{"reserved", kReserved0Offset, kReserved0Size, "Must be zero"},
	{"volume_uuid", kVolumeUuidOffset, kVolumeUuidSize, "Random volume UUID"},
	{"kdf_salt", kKdfSaltOffset, kKdfSaltSize, "Argon2id salt"},
	{"wrapped_master_key", kWrappedMasterKeyOffset, kWrappedMasterKeySize,
		"AES key-wrap output; AES-128-XTS tail must be zero"},
	{"sequence_number", kSequenceNumberOffset, kSequenceNumberSize,
		"Monotonic header generation; zero is invalid"},
	{"reserved", kReserved1Offset, kReserved1Size, "Must be zero"},
	{"header_hmac_sha256", kHeaderHmacOffset, kHeaderHmacSize,
		"HMAC-SHA256 over bytes [0x000, 0x0c0)"},
	{"padding", kPaddingOffset, kPaddingSize, "Must be zero"},
}};

constexpr bool
HeaderFieldsAreValid()
{
	for (std::size_t i = 0; i < kHeaderFields.size(); i++) {
		const HeaderField& field = kHeaderFields[i];
		if (field.offset + field.size > kHeaderSize)
			return false;
		if (i > 0) {
			const HeaderField& previous = kHeaderFields[i - 1];
			if (previous.offset + previous.size > field.offset)
				return false;
		}
	}
	return kHmacCoveredEnd == kHeaderHmacOffset
		&& kHeaderHmacOffset + kHeaderHmacSize <= kHeaderSize;
}

static_assert(HeaderFieldsAreValid());

} // namespace BPrivate::EncryptedHome::wire


#endif	// _PRIVATE_ENCRYPTED_HOME_HEADER_LAYOUT_H
