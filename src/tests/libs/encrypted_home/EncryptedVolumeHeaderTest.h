/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#ifndef ENCRYPTED_VOLUME_HEADER_TEST_H
#define ENCRYPTED_VOLUME_HEADER_TEST_H


#include <cppunit/TestCase.h>


class EncryptedVolumeHeaderTest : public CppUnit::TestCase {
public:
	static CppUnit::Test* Suite();

	void TestSerializeRoundTrip();
	void TestRejectBadMagic();
	void TestRejectFutureVersion();
	void TestReservedFieldsMustBeZero();
	void TestRejectExcessiveKdfParameters();
	void TestUnlockSuccess();
	void TestUnlockWrongPassphrase();
	void TestOpenWrongPassphrase();
	void TestHmacTamperDetected();
	void TestAes128WrapTailMustBeZero();
	void TestFormatProducesDifferentMasterKeys();
	void TestFuzzRandomHeaders();
	void TestTornWriteRecovery();
	void TestSequenceMonotonic();
	void TestChangePassphraseUsesSelectedHeader();
	void TestOpenDoesNotRollbackNewerHeader();
	void TestChangePassphraseRejectsSequenceOverflow();
	void TestZeroizationAfterUnlock();
	void TestZeroizationAfterWrongPassphrase();
	void TestZeroizationAfterFormat();
};


#endif	// ENCRYPTED_VOLUME_HEADER_TEST_H
