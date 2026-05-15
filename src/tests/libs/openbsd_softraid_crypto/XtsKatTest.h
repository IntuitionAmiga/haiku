/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef XTS_KAT_TEST_H
#define XTS_KAT_TEST_H


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"
#include <cppunit/TestFixture.h>
#pragma GCC diagnostic pop


namespace CppUnit {
	class Test;
}


class XtsKatTest : public CppUnit::TestFixture {
public:
	static CppUnit::Test* Suite();

	void TestIeee1619XtsAes128Encrypt();
	void TestIeee1619XtsAes128Decrypt();
	void TestNistXtsAes256Encrypt();
	void TestNistXtsAes256Decrypt();
	void TestRejectInvalidKeyLength();
};


#endif /* XTS_KAT_TEST_H */
