/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include <TestSuiteAddon.h>
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#define private public
#include "Job.h"
#undef private

#include <unistd.h>


class AsyncWaitForExitJob : public Job {
public:
	AsyncWaitForExitJob()
		:
		Job("async_wait_for_exit")
	{
		SetWaitForExit(true);
	}

protected:
	status_t Execute() override
	{
		thread_id thread = spawn_thread(&_ExitImmediately,
			"async_wait_for_exit_main", B_NORMAL_PRIORITY, NULL);
		if (thread < 0)
			return thread;

		fMainThread = thread;
		fTeam = getpid();

		status_t status = resume_thread(thread);
		if (status != B_OK) {
			fMainThread = -1;
			fTeam = -1;
			return status;
		}

		return B_OK;
	}

private:
	static status_t _ExitImmediately(void*)
	{
		return B_OK;
	}
};


class JobStateTest : public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE(JobStateTest);
	CPPUNIT_TEST(TestSuccessfulWaitForExitJobRemainsSucceeded);
	CPPUNIT_TEST(TestSuccessfulWaitForExitJobCanRelaunch);
	CPPUNIT_TEST_SUITE_END();

public:
	void TestSuccessfulWaitForExitJobRemainsSucceeded()
	{
		AsyncWaitForExitJob job;

		CPPUNIT_ASSERT_EQUAL(B_OK, job.Run());
		_WaitForJob(job);

		CPPUNIT_ASSERT_EQUAL(B_JOB_STATE_SUCCEEDED, job.State());
	}

	void TestSuccessfulWaitForExitJobCanRelaunch()
	{
		AsyncWaitForExitJob job;

		CPPUNIT_ASSERT_EQUAL(B_OK, job.Run());
		_WaitForJob(job);
		CPPUNIT_ASSERT_EQUAL(B_JOB_STATE_SUCCEEDED, job.State());

		CPPUNIT_ASSERT_EQUAL(B_OK, job.Run());
		_WaitForJob(job);

		CPPUNIT_ASSERT_EQUAL(B_JOB_STATE_SUCCEEDED, job.State());
	}

private:
	void _WaitForJob(AsyncWaitForExitJob& job)
	{
		for (int32 tries = 0; tries < 100
				&& job.State() == B_JOB_STATE_IN_PROGRESS; tries++) {
			snooze(10000);
		}
	}
};


CPPUNIT_TEST_SUITE_NAMED_REGISTRATION(JobStateTest, getTestSuiteName());
