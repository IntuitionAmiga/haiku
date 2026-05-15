/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "Argon2KatTest.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <argon2.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"
#include <cppunit/TestCaller.h>
#include <cppunit/TestSuite.h>
#pragma GCC diagnostic pop


namespace {

using Hash = std::array<uint8_t, 32>;

struct Argon2idVector {
	uint32_t timeCost;
	uint32_t memoryCostKiB;
	uint32_t parallelism;
	const char* password;
	const char* salt;
	Hash expected;
};

constexpr Argon2idVector kVectors[] = {
	{
		2, 65536, 1, "password", "somesalt",
		{
			0x09, 0x31, 0x61, 0x15, 0xd5, 0xcf, 0x24, 0xed,
			0x5a, 0x15, 0xa3, 0x1a, 0x3b, 0xa3, 0x26, 0xe5,
			0xcf, 0x32, 0xed, 0xc2, 0x47, 0x02, 0x98, 0x7c,
			0x02, 0xb6, 0x56, 0x6f, 0x61, 0x91, 0x3c, 0xf7
		}
	},
	{
		2, 256, 1, "password", "somesalt",
		{
			0x9d, 0xfe, 0xb9, 0x10, 0xe8, 0x0b, 0xad, 0x03,
			0x11, 0xfe, 0xe2, 0x0f, 0x9c, 0x0e, 0x2b, 0x12,
			0xc1, 0x79, 0x87, 0xb4, 0xca, 0xc9, 0x0c, 0x2e,
			0xf5, 0x4d, 0x5b, 0x30, 0x21, 0xc6, 0x8b, 0xfe
		}
	},
	{
		2, 256, 2, "password", "somesalt",
		{
			0x6d, 0x09, 0x3c, 0x50, 0x1f, 0xd5, 0x99, 0x96,
			0x45, 0xe0, 0xea, 0x3b, 0xf6, 0x20, 0xd7, 0xb8,
			0xbe, 0x7f, 0xd2, 0xdb, 0x59, 0xc2, 0x0d, 0x9f,
			0xff, 0x95, 0x39, 0xda, 0x2b, 0xf5, 0x70, 0x37
		}
	},
	{
		2, 65536, 1, "differentpassword", "somesalt",
		{
			0x0b, 0x84, 0xd6, 0x52, 0xcf, 0x6b, 0x0c, 0x4b,
			0xea, 0xef, 0x0d, 0xfe, 0x27, 0x8b, 0xa6, 0xa8,
			0x0d, 0xf6, 0x69, 0x62, 0x81, 0xd7, 0xe0, 0xd2,
			0x89, 0x1b, 0x81, 0x7d, 0x8c, 0x45, 0x8f, 0xde
		}
	}
};

constexpr Hash kPublishedKatHash = {
	0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c,
	0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
	0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e,
	0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59
};


void
HashVector(const Argon2idVector& vector)
{
	Hash hash = {};

	const int result = argon2id_hash_raw(vector.timeCost, vector.memoryCostKiB,
		vector.parallelism, vector.password, std::strlen(vector.password),
		vector.salt, std::strlen(vector.salt), hash.data(), hash.size());

	CPPUNIT_ASSERT(result == ARGON2_OK);
	CPPUNIT_ASSERT(std::equal(hash.begin(), hash.end(),
		vector.expected.begin()));
}

} // namespace


CppUnit::Test*
Argon2KatTest::Suite()
{
	CppUnit::TestSuite* suite = new CppUnit::TestSuite("Argon2KatTest");
	typedef CppUnit::TestCaller<Argon2KatTest> TestCaller;

	suite->addTest(new TestCaller("upstream Argon2id vectors",
		&Argon2KatTest::TestUpstreamArgon2idVectors));
	suite->addTest(new TestCaller("published KAT with secret and AD",
		&Argon2KatTest::TestPublishedKatWithSecretAndAssociatedData));
	suite->addTest(new TestCaller("rejects too little memory",
		&Argon2KatTest::TestRejectsTooLittleMemory));

	return suite;
}


void
Argon2KatTest::TestUpstreamArgon2idVectors()
{
	for (const Argon2idVector& vector : kVectors)
		HashVector(vector);
}


void
Argon2KatTest::TestPublishedKatWithSecretAndAssociatedData()
{
	Hash hash = {};
	std::array<uint8_t, 32> password = {};
	std::array<uint8_t, 16> salt = {};
	std::array<uint8_t, 8> secret = {};
	std::array<uint8_t, 12> associatedData = {};
	password.fill(0x01);
	salt.fill(0x02);
	secret.fill(0x03);
	associatedData.fill(0x04);

	argon2_context context = {};
	context.out = hash.data();
	context.outlen = hash.size();
	context.pwd = password.data();
	context.pwdlen = password.size();
	context.salt = salt.data();
	context.saltlen = salt.size();
	context.secret = secret.data();
	context.secretlen = secret.size();
	context.ad = associatedData.data();
	context.adlen = associatedData.size();
	context.t_cost = 3;
	context.m_cost = 32;
	context.lanes = 4;
	context.threads = 4;
	context.flags = ARGON2_DEFAULT_FLAGS;
	context.version = ARGON2_VERSION_NUMBER;

	CPPUNIT_ASSERT(argon2id_ctx(&context) == ARGON2_OK);
	CPPUNIT_ASSERT(std::equal(hash.begin(), hash.end(),
		kPublishedKatHash.begin()));
}


void
Argon2KatTest::TestRejectsTooLittleMemory()
{
	Hash hash = {};
	const int result = argon2id_hash_raw(2, 1, 1, "password",
		std::strlen("password"), "somesalt", std::strlen("somesalt"),
		hash.data(), hash.size());

	CPPUNIT_ASSERT(result == ARGON2_MEMORY_TOO_LITTLE);
}
