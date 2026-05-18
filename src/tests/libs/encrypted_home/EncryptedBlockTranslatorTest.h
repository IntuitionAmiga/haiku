/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#ifndef ENCRYPTED_BLOCK_TRANSLATOR_TEST_H
#define ENCRYPTED_BLOCK_TRANSLATOR_TEST_H


#include <cppunit/TestCase.h>


class EncryptedBlockTranslatorTest : public CppUnit::TestCase {
public:
	static CppUnit::Test* Suite();

	void TestFormatThenReopen();
	void TestFormatZeroFillsPayload();
	void TestFormatZeroFillsPayloadInChunks();
	void TestFormatDoesNotExtendSmallFileForAlternateBackupClear();
	void TestFormatDoesNotClearOutsideDeclaredVolume();
	void TestRandomIO();
	void TestUnalignedReadFails();
	void TestRejectBackingOffsetWraparound();
	void TestPersistAcrossClose();
	void TestCloseFlushesWrites();
	void TestFileBackingStoreLargeOffset();
	void TestWrongPassphrase();
	void TestHeaderCorruptionDetected();
	void TestBackupHeaderRecovery();
	void TestFailedRepairPreservesBackupHeader();
	void TestRecoveryIgnoresUnauthenticatedPrimaryMetadata();
	void TestBackupHeaderRecoveryIgnoresUnauthenticatedSectorSize();
	void TestOpenDoesNotRollbackNewerBackup();
	void TestOpenDoesNotRollbackNewerFourKiBBackup();
	void TestAuthenticatedPrimaryIgnoresStaleBackupAtWrongOffset();
	void TestOldPassphraseCannotOpenStaleBackupAfterReformat();
	void TestCorruptPrimaryRejectsAmbiguousStaleBackup();
	void TestCorruptPrimaryRejectsAmbiguousStaleFourKiBBackup();
	void TestFourKiBSectors();
};


#endif	// ENCRYPTED_BLOCK_TRANSLATOR_TEST_H
