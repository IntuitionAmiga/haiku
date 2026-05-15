/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include <TestSuiteAddon.h>
#include <TestSuite.h>

#include "XtsKatTest.h"


const char*
getTestSuiteName()
{
	return "OpenBSDSoftraidCrypto";
}


BTestSuite*
getTestSuite()
{
	BTestSuite* suite = new BTestSuite(getTestSuiteName());
	suite->addTest("XTS KAT", XtsKatTest::Suite());
	return suite;
}
