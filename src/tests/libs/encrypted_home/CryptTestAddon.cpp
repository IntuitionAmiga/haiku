/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include <TestSuiteAddon.h>
#include <TestSuite.h>

#include "EncryptedVolumeHeaderTest.h"


const char*
getTestSuiteName()
{
	return "EncryptedHome";
}


BTestSuite*
getTestSuite()
{
	BTestSuite* suite = new BTestSuite(getTestSuiteName());
	suite->addTest("Encrypted volume header",
		EncryptedVolumeHeaderTest::Suite());
	return suite;
}
