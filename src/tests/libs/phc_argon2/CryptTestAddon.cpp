/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include <TestSuiteAddon.h>
#include <TestSuite.h>

#include "Argon2KatTest.h"


const char*
getTestSuiteName()
{
	return "PhcArgon2";
}


BTestSuite*
getTestSuite()
{
	BTestSuite* suite = new BTestSuite(getTestSuiteName());
	suite->addTest("Argon2 KAT", Argon2KatTest::Suite());
	return suite;
}
