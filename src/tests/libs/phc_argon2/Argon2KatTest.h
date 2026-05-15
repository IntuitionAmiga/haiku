/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef ARGON2_KAT_TEST_H
#define ARGON2_KAT_TEST_H


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"
#include <cppunit/TestFixture.h>
#pragma GCC diagnostic pop


namespace CppUnit {
	class Test;
}


class Argon2KatTest : public CppUnit::TestFixture {
public:
	static CppUnit::Test* Suite();

	void TestUpstreamArgon2idVectors();
	void TestPublishedKatWithSecretAndAssociatedData();
	void TestRejectsTooLittleMemory();
};


#endif /* ARGON2_KAT_TEST_H */
