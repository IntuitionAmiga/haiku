/*
 * Copyright 2015, Axel Dörfler, axeld@pinc-software.de.
 * Distributed under the terms of the MIT License.
 */


#include <stdlib.h>

#include <driver_settings.h>
#include <String.h>

#include <TestSuiteAddon.h>
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include "SettingsParser.h"


class SettingsParserTest : public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE(SettingsParserTest);
	CPPUNIT_TEST(TestConditionsEmpty);
	CPPUNIT_TEST(TestConditionsMultiLine);
	CPPUNIT_TEST(TestConditionsFlat);
	CPPUNIT_TEST(TestConditionsFlatWithNot);
	CPPUNIT_TEST(TestConditionsFlatWithArgs);
	CPPUNIT_TEST(TestConditionsFlatWithNotAndArgs);
	CPPUNIT_TEST(TestConditionsMultiLineFlatNot);
	CPPUNIT_TEST(TestConditionsMultiLineFlatNotWithArgs);
	CPPUNIT_TEST(TestConditionsMultiLineNot);
	CPPUNIT_TEST(TestEventsEmpty);
	CPPUNIT_TEST(TestEventsMultiLine);
	CPPUNIT_TEST(TestEventsFlat);
	CPPUNIT_TEST(TestEventsFlatWithArgs);
	CPPUNIT_TEST(TestEnvironmentMultiLine);
	CPPUNIT_TEST(TestEnvironmentFlat);
	CPPUNIT_TEST(TestRunFlat);
	CPPUNIT_TEST(TestRunMultiLine);
	CPPUNIT_TEST(TestRunIfThenElseFlat);
	CPPUNIT_TEST(TestRunIfThenElseMultiLine);
	CPPUNIT_TEST(TestEncryptedHomeLaunchOrdering);
	CPPUNIT_TEST_SUITE_END();

	status_t _ParseCondition(const char* text, BMessage& message)
	{
		return _ParseName("if", text, message);
	}

	status_t _ParseEvent(const char* text, BMessage& message)
	{
		return _ParseName("on", text, message);
	}

	status_t _ParseName(const char* name, const char* text, BMessage& message)
	{
		SettingsParser parser;
		BString input("job A {\n");
		input << text << "\n}\n";

		BMessage jobs;
		status_t status = parser.Parse(input, jobs);
		if (status != B_OK)
			return status;

		BMessage job;
		status = jobs.FindMessage("job", 0, &job);
		if (status != B_OK)
			return status;

		CPPUNIT_ASSERT_EQUAL(2, (int)job.CountNames(B_ANY_TYPE));
		CPPUNIT_ASSERT_EQUAL(BString("A"), BString(job.GetString("name")));

		return job.FindMessage(name, &message);
	}

	int32 _ArrayCount(BMessage& message, const char* name)
	{
		int32 found;
		if (message.GetInfo(name, NULL, &found, NULL) != B_OK)
			return 0;

		return found;
	}

public:
	void TestConditionsEmpty()
	{
		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, _ParseCondition("if {\n"
			"}\n", message));
		CPPUNIT_ASSERT(message.IsEmpty());
	}

	void TestConditionsMultiLine()
	{
		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, _ParseCondition("if {\n"
			"\tsafemode\n"
			"\tfile_exists one\n"
			"}\n", message));
		CPPUNIT_ASSERT_EQUAL(2, (int)message.CountNames(B_ANY_TYPE));

		BMessage subMessage;
		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("safemode", &subMessage));
		CPPUNIT_ASSERT(subMessage.IsEmpty());

		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("file_exists",
			&subMessage));
		CPPUNIT_ASSERT_EQUAL(BString("one"),
			BString(subMessage.GetString("args", 0, "-")));
		CPPUNIT_ASSERT_EQUAL(1, (int)subMessage.CountNames(B_ANY_TYPE));
	}

	void TestConditionsFlat()
	{
		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, _ParseCondition("if safemode\n", message));
		CPPUNIT_ASSERT_EQUAL(1, (int)message.CountNames(B_ANY_TYPE));

		BMessage args;
		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("safemode", &args));
		CPPUNIT_ASSERT(args.IsEmpty());
	}

	void TestConditionsFlatWithNot()
	{
		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, _ParseCondition("if not safemode\n", message));
		CPPUNIT_ASSERT_EQUAL(1, (int)message.CountNames(B_ANY_TYPE));

		BMessage subMessage;
		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("not",
			&subMessage));

		BMessage args;
		CPPUNIT_ASSERT_EQUAL(B_OK, subMessage.FindMessage("safemode", &args));
		CPPUNIT_ASSERT(args.IsEmpty());
	}

	void TestConditionsFlatWithArgs()
	{
		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK,
			_ParseCondition("if file_exists one\n", message));
		CPPUNIT_ASSERT_EQUAL(1, (int)message.CountNames(B_ANY_TYPE));

		BMessage args;
		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("file_exists", &args));
		CPPUNIT_ASSERT_EQUAL(BString("one"),
			BString(args.GetString("args", 0, "-")));
		CPPUNIT_ASSERT_EQUAL(1, (int)args.CountNames(B_ANY_TYPE));
	}

	void TestConditionsFlatWithNotAndArgs()
	{
		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK,
			_ParseCondition("if not file_exists one\n", message));
		CPPUNIT_ASSERT_EQUAL(1, (int)message.CountNames(B_ANY_TYPE));

		BMessage subMessage;
		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("not",
			&subMessage));

		BMessage args;
		CPPUNIT_ASSERT_EQUAL(B_OK, subMessage.FindMessage("file_exists", &args));
		CPPUNIT_ASSERT_EQUAL(BString("one"),
			BString(args.GetString("args", 0, "-")));
		CPPUNIT_ASSERT_EQUAL(1, (int)args.CountNames(B_ANY_TYPE));
	}

	void TestConditionsMultiLineFlatNot()
	{
		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, _ParseCondition("if {\n"
			"\tnot safemode\n"
			"}\n", message));

		BMessage subMessage;
		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("not",
			&subMessage));
		CPPUNIT_ASSERT_EQUAL(1, (int)message.CountNames(B_ANY_TYPE));

		BMessage args;
		CPPUNIT_ASSERT_EQUAL(B_OK, subMessage.FindMessage("safemode", &args));
		CPPUNIT_ASSERT_EQUAL(1, (int)subMessage.CountNames(B_ANY_TYPE));
		CPPUNIT_ASSERT(args.IsEmpty());
	}

	void TestConditionsMultiLineFlatNotWithArgs()
	{
		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, _ParseCondition("if {\n"
			"\tnot file_exists one two\n"
			"}\n", message));

		BMessage subMessage;
		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("not",
			&subMessage));

		BMessage args;
		CPPUNIT_ASSERT_EQUAL(B_OK, subMessage.FindMessage("file_exists", &args));
		CPPUNIT_ASSERT_EQUAL(BString("one"),
			BString(args.GetString("args", 0, "-")));
		CPPUNIT_ASSERT_EQUAL(BString("two"),
			BString(args.GetString("args", 1, "-")));
		CPPUNIT_ASSERT_EQUAL(1, (int)args.CountNames(B_ANY_TYPE));
		CPPUNIT_ASSERT_EQUAL(2, (int)_ArrayCount(args, "args"));
	}

	void TestConditionsMultiLineNot()
	{
		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, _ParseCondition("if {\n"
			"\tnot {\n"
			"\t\tsafemode\n"
			"\t}\n"
			"}\n", message));

		BMessage subMessage;
		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("not", &subMessage));

		BMessage args;
		CPPUNIT_ASSERT_EQUAL(B_OK, subMessage.FindMessage("safemode", &args));
		CPPUNIT_ASSERT(args.IsEmpty());
	}

	void TestEventsEmpty()
	{
		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, _ParseEvent("on {\n"
			"}\n", message));
		CPPUNIT_ASSERT(message.IsEmpty());
	}

	void TestEventsMultiLine()
	{
		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, _ParseEvent("on {\n"
			"\tfile_created one\n"
			"\tdemand\n"
			"}\n", message));
		CPPUNIT_ASSERT_EQUAL(2, (int)message.CountNames(B_ANY_TYPE));

		BMessage subMessage;
		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("demand", &subMessage));
		CPPUNIT_ASSERT(subMessage.IsEmpty());

		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("file_created",
			&subMessage));
		CPPUNIT_ASSERT_EQUAL(BString("one"),
			BString(subMessage.GetString("args", 0, "-")));
		CPPUNIT_ASSERT_EQUAL(1, (int)subMessage.CountNames(B_ANY_TYPE));
	}

	void TestEventsFlat()
	{
		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, _ParseEvent("on demand\n", message));
		CPPUNIT_ASSERT_EQUAL(1, (int)message.CountNames(B_ANY_TYPE));

		BMessage args;
		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("demand", &args));
		CPPUNIT_ASSERT(args.IsEmpty());
	}

	void TestEventsFlatWithArgs()
	{
		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, _ParseEvent("on file_created one\n", message));
		CPPUNIT_ASSERT_EQUAL(1, (int)message.CountNames(B_ANY_TYPE));

		BMessage args;
		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("file_created", &args));
		CPPUNIT_ASSERT_EQUAL(BString("one"),
			BString(args.GetString("args", 0, "-")));
		CPPUNIT_ASSERT_EQUAL(1, (int)args.CountNames(B_ANY_TYPE));
	}

	void TestEnvironmentMultiLine()
	{
		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, _ParseName("env", "env {\n"
			"from_script SetupEnvironment\n"
			"TEST well, yes\n"
			"}\n", message));
		CPPUNIT_ASSERT_EQUAL(2, (int)message.CountNames(B_ANY_TYPE));

		CPPUNIT_ASSERT_EQUAL(BString("SetupEnvironment"),
			BString(message.GetString("from_script", "-")));
		CPPUNIT_ASSERT_EQUAL(1, (int)_ArrayCount(message, "from_script"));

		CPPUNIT_ASSERT_EQUAL(BString("well,"),
			BString(message.GetString("TEST", 0, "-")));
		CPPUNIT_ASSERT_EQUAL(BString("yes"),
			BString(message.GetString("TEST", 1, "-")));
		CPPUNIT_ASSERT_EQUAL(2, (int)_ArrayCount(message, "TEST"));
	}

	void TestEnvironmentFlat()
	{
		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, _ParseName("env", "env SetupEnvironment\n",
			message));
		CPPUNIT_ASSERT_EQUAL(1, (int)message.CountNames(B_ANY_TYPE));

		CPPUNIT_ASSERT_EQUAL(BString("SetupEnvironment"),
			BString(message.GetString("from_script", "-")));
		CPPUNIT_ASSERT_EQUAL(1, (int)_ArrayCount(message, "from_script"));
	}

	void TestRunFlat()
	{
		SettingsParser parser;
		BMessage jobs;
		CPPUNIT_ASSERT_EQUAL(B_OK, parser.Parse("run me", jobs));
		CPPUNIT_ASSERT_EQUAL(1, (int)jobs.CountNames(B_ANY_TYPE));

		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, jobs.FindMessage("run", &message));
		CPPUNIT_ASSERT_EQUAL(BString("me"),
			BString(message.GetString("target", "-")));
		CPPUNIT_ASSERT_EQUAL(1, (int)_ArrayCount(message, "target"));
		CPPUNIT_ASSERT_EQUAL(1, (int)message.CountNames(B_ANY_TYPE));
	}

	void TestRunMultiLine()
	{
		SettingsParser parser;
		BMessage jobs;
		status_t status = parser.Parse("run {\n"
			"\tme\n"
			"\tyou\n"
			"}\n", jobs);
		CPPUNIT_ASSERT_EQUAL(B_OK, status);
		CPPUNIT_ASSERT_EQUAL(1, (int)jobs.CountNames(B_ANY_TYPE));

		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, jobs.FindMessage("run", &message));
		CPPUNIT_ASSERT_EQUAL(BString("me"),
			BString(message.GetString("target", 0, "-")));
		CPPUNIT_ASSERT_EQUAL(BString("you"),
			BString(message.GetString("target", 1, "-")));
		CPPUNIT_ASSERT_EQUAL(2, (int)_ArrayCount(message, "target"));
		CPPUNIT_ASSERT_EQUAL(1, (int)message.CountNames(B_ANY_TYPE));
	}

	void TestRunIfThenElseFlat()
	{
		SettingsParser parser;
		BMessage jobs;
		status_t status = parser.Parse("run {\n"
			"\tif safemode\n"
			"\tthen this\n"
			"\telse that\n"
			"}\n", jobs);
		CPPUNIT_ASSERT_EQUAL(B_OK, status);

		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, jobs.FindMessage("run", &message));
		CPPUNIT_ASSERT_EQUAL(3, (int)message.CountNames(B_ANY_TYPE));

		BMessage then;
		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("then", &then));
		CPPUNIT_ASSERT_EQUAL(BString("this"),
			BString(then.GetString("target", "-")));
		CPPUNIT_ASSERT_EQUAL(1, (int)_ArrayCount(then, "target"));
		CPPUNIT_ASSERT_EQUAL(1, (int)then.CountNames(B_ANY_TYPE));

		BMessage otherwise;
		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("else", &otherwise));
		CPPUNIT_ASSERT_EQUAL(BString("that"),
			BString(otherwise.GetString("target", "-")));
		CPPUNIT_ASSERT_EQUAL(1, (int)_ArrayCount(otherwise, "target"));
		CPPUNIT_ASSERT_EQUAL(1, (int)otherwise.CountNames(B_ANY_TYPE));
	}

	void TestRunIfThenElseMultiLine()
	{
		SettingsParser parser;
		BMessage jobs;
		status_t status = parser.Parse("run {\n"
			"\tif {\n"
			"\t\tread_only\n"
			"\t}\n"
			"\tthen {\n"
			"\t\tthis\n"
			"\t}\n"
			"\telse {\n"
			"\t\tthat\n"
			"\t}\n"
			"}\n", jobs);
		CPPUNIT_ASSERT_EQUAL(B_OK, status);

		BMessage message;
		CPPUNIT_ASSERT_EQUAL(B_OK, jobs.FindMessage("run", &message));
		CPPUNIT_ASSERT_EQUAL(3, (int)message.CountNames(B_ANY_TYPE));

		BMessage then;
		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("then", &then));
		CPPUNIT_ASSERT_EQUAL(BString("this"),
			BString(then.GetString("target", "-")));
		CPPUNIT_ASSERT_EQUAL(1, (int)_ArrayCount(then, "target"));
		CPPUNIT_ASSERT_EQUAL(1, (int)then.CountNames(B_ANY_TYPE));

		BMessage otherwise;
		CPPUNIT_ASSERT_EQUAL(B_OK, message.FindMessage("else", &otherwise));
		CPPUNIT_ASSERT_EQUAL(BString("that"),
			BString(otherwise.GetString("target", "-")));
		CPPUNIT_ASSERT_EQUAL(1, (int)_ArrayCount(otherwise, "target"));
		CPPUNIT_ASSERT_EQUAL(1, (int)otherwise.CountNames(B_ANY_TYPE));
	}

	void TestEncryptedHomeLaunchOrdering()
	{
		SettingsParser parser;
		BMessage jobs;
		status_t status = parser.Parse("service x-vnd.Haiku-app_server {\n"
			"\tlaunch /system/servers/app_server\n"
			"\tif file_exists /system/apps/unlock_volume\n"
			"}\n"
			"service x-vnd.Haiku-app_server {\n"
			"\tlaunch /system/servers/app_server\n"
			"\tif not file_exists /system/apps/unlock_volume\n"
			"}\n"
			"job x-vnd.Haiku-home_unlock {\n"
			"\tlaunch /system/apps/unlock_volume\n"
			"\tif file_exists /system/apps/unlock_volume\n"
			"\trequires x-vnd.Haiku-app_server\n"
			"\twait_for_exit\n"
			"\ton initial_volumes_mounted\n"
			"}\n"
			"job x-vnd.Haiku-autologin-unlocked {\n"
			"\tlaunch /system/bin/autologin\n"
			"\tif file_exists /system/apps/unlock_volume\n"
			"\trequires x-vnd.Haiku-home_unlock\n"
			"}\n"
			"job x-vnd.Haiku-autologin {\n"
			"\tlaunch /system/bin/autologin\n"
			"\tif not file_exists /system/apps/unlock_volume\n"
			"}\n", jobs);
		CPPUNIT_ASSERT_EQUAL(B_OK, status);
		CPPUNIT_ASSERT_EQUAL(2, (int)jobs.CountNames(B_ANY_TYPE));
		CPPUNIT_ASSERT_EQUAL(2, (int)_ArrayCount(jobs, "service"));
		CPPUNIT_ASSERT_EQUAL(3, (int)_ArrayCount(jobs, "job"));

		BMessage appServer;
		CPPUNIT_ASSERT_EQUAL(B_OK, jobs.FindMessage("service", &appServer));
		CPPUNIT_ASSERT_EQUAL(BString("x-vnd.Haiku-app_server"),
			BString(appServer.GetString("name")));
		CPPUNIT_ASSERT_EQUAL(BString("/system/servers/app_server"),
			BString(appServer.GetString("launch")));
		CPPUNIT_ASSERT(!appServer.HasMessage("on"));

		BMessage appServerCondition;
		CPPUNIT_ASSERT_EQUAL(B_OK, appServer.FindMessage("if",
			&appServerCondition));
		BMessage appServerFileExists;
		CPPUNIT_ASSERT_EQUAL(B_OK, appServerCondition.FindMessage(
			"file_exists", &appServerFileExists));
		CPPUNIT_ASSERT_EQUAL(BString("/system/apps/unlock_volume"),
			BString(appServerFileExists.GetString("args")));

		BMessage fallbackAppServer;
		CPPUNIT_ASSERT_EQUAL(B_OK, jobs.FindMessage("service", 1,
			&fallbackAppServer));
		CPPUNIT_ASSERT_EQUAL(BString("x-vnd.Haiku-app_server"),
			BString(fallbackAppServer.GetString("name")));
		CPPUNIT_ASSERT_EQUAL(BString("/system/servers/app_server"),
			BString(fallbackAppServer.GetString("launch")));
		CPPUNIT_ASSERT(!fallbackAppServer.HasMessage("on"));

		BMessage fallbackCondition;
		CPPUNIT_ASSERT_EQUAL(B_OK, fallbackAppServer.FindMessage("if",
			&fallbackCondition));
		BMessage fallbackNot;
		CPPUNIT_ASSERT_EQUAL(B_OK, fallbackCondition.FindMessage("not",
			&fallbackNot));
		BMessage fallbackFileExists;
		CPPUNIT_ASSERT_EQUAL(B_OK, fallbackNot.FindMessage("file_exists",
			&fallbackFileExists));
		CPPUNIT_ASSERT_EQUAL(BString("/system/apps/unlock_volume"),
			BString(fallbackFileExists.GetString("args")));

		BMessage job;
		CPPUNIT_ASSERT_EQUAL(B_OK, jobs.FindMessage("job", 0, &job));
		CPPUNIT_ASSERT_EQUAL(BString("x-vnd.Haiku-home_unlock"),
			BString(job.GetString("name")));
		CPPUNIT_ASSERT_EQUAL(BString("/system/apps/unlock_volume"),
			BString(job.GetString("launch")));
		CPPUNIT_ASSERT_EQUAL(BString("x-vnd.Haiku-app_server"),
			BString(job.GetString("requires")));
		CPPUNIT_ASSERT(job.GetBool("wait_for_exit"));

		BMessage condition;
		CPPUNIT_ASSERT_EQUAL(B_OK, job.FindMessage("if", &condition));

		BMessage fileExists;
		CPPUNIT_ASSERT_EQUAL(B_OK, condition.FindMessage("file_exists",
			&fileExists));
		CPPUNIT_ASSERT_EQUAL(BString("/system/apps/unlock_volume"),
			BString(fileExists.GetString("args")));

		BMessage event;
		CPPUNIT_ASSERT_EQUAL(B_OK, job.FindMessage("on", &event));
		CPPUNIT_ASSERT(event.HasMessage("initial_volumes_mounted"));

		BMessage unlockedAutologin;
		CPPUNIT_ASSERT_EQUAL(B_OK, jobs.FindMessage("job", 1,
			&unlockedAutologin));
		CPPUNIT_ASSERT_EQUAL(BString("x-vnd.Haiku-autologin-unlocked"),
			BString(unlockedAutologin.GetString("name")));
		CPPUNIT_ASSERT_EQUAL(BString("/system/bin/autologin"),
			BString(unlockedAutologin.GetString("launch")));
		CPPUNIT_ASSERT_EQUAL(BString("x-vnd.Haiku-home_unlock"),
			BString(unlockedAutologin.GetString("requires")));

		BMessage fallbackAutologin;
		CPPUNIT_ASSERT_EQUAL(B_OK, jobs.FindMessage("job", 2,
			&fallbackAutologin));
		CPPUNIT_ASSERT_EQUAL(BString("x-vnd.Haiku-autologin"),
			BString(fallbackAutologin.GetString("name")));
		CPPUNIT_ASSERT(!fallbackAutologin.HasString("requires"));
	}
};


CPPUNIT_TEST_SUITE_NAMED_REGISTRATION(SettingsParserTest, getTestSuiteName());
