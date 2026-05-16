/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#ifndef ENCRYPTED_HOME_ADD_ON_H
#define ENCRYPTED_HOME_ADD_ON_H


#include <DiskSystemAddOn.h>


class EncryptedHomeAddOn : public BDiskSystemAddOn {
public:
								EncryptedHomeAddOn();

	virtual	status_t			CreatePartitionHandle(
									BMutablePartition* partition,
									BPartitionHandle** handle);
	virtual	bool				CanInitialize(
									const BMutablePartition* partition);
	virtual	status_t			ValidateInitialize(
									const BMutablePartition* partition,
									BString* name, const char* parameters);
	virtual	status_t			Initialize(BMutablePartition* partition,
									const char* name, const char* parameters,
									BPartitionHandle** handle);
};


class EncryptedHomePartitionHandle : public BPartitionHandle {
public:
								EncryptedHomePartitionHandle(
									BMutablePartition* partition);

	virtual	uint32				SupportedOperations(uint32 mask);
};


#endif	// ENCRYPTED_HOME_ADD_ON_H
