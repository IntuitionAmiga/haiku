/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#ifndef _PRIVATE_ENCRYPTED_HOME_SECURE_BUFFER_H
#define _PRIVATE_ENCRYPTED_HOME_SECURE_BUFFER_H


#include <cstddef>

#ifdef _KERNEL_MODE
#	include <string.h>
#else
#	include <span>
#	include <openssl/crypto.h>
#endif


namespace BPrivate::EncryptedHome {

template<size_t Size>
class secure_buffer {
public:
	secure_buffer() = default;

	secure_buffer(const secure_buffer&) = delete;
	secure_buffer& operator=(const secure_buffer&) = delete;

	secure_buffer(secure_buffer&& other) noexcept
	{
		for (size_t i = 0; i < Size; i++)
			fData[i] = other.fData[i];
		other.Cleanse();
	}

	secure_buffer& operator=(secure_buffer&& other) noexcept
	{
		if (this != &other) {
			Cleanse();
			for (size_t i = 0; i < Size; i++)
				fData[i] = other.fData[i];
			other.Cleanse();
		}
		return *this;
	}

	~secure_buffer()
	{
		Cleanse();
	}

	std::byte* data()
	{
		return fData;
	}

	const std::byte* data() const
	{
		return fData;
	}

	size_t size() const
	{
		return Size;
	}

#ifndef _KERNEL_MODE
	std::span<std::byte, Size> span()
	{
		return {fData, Size};
	}

	std::span<const std::byte, Size> span() const
	{
		return {fData, Size};
	}
#endif

	void Fill(std::byte value)
	{
		for (size_t i = 0; i < Size; i++)
			fData[i] = value;
	}

	void Cleanse()
	{
#ifdef _KERNEL_MODE
		explicit_bzero(fData, Size);
#else
		OPENSSL_cleanse(fData, Size);
#endif
	}

private:
	std::byte fData[Size] = {};
};

} // namespace BPrivate::EncryptedHome


#endif	// _PRIVATE_ENCRYPTED_HOME_SECURE_BUFFER_H
