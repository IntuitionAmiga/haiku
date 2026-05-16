/*
 * Copyright 2026, Haiku, Inc. All Rights Reserved.
 * Distributed under the terms of the MIT License.
 */


#include "EncryptedHomeAddOn.h"

#include <encrypted_home_disk_system.h>

#include <new>

#include <List.h>


using namespace BPrivate::EncryptedHome;
using std::nothrow;


EncryptedHomeAddOn::EncryptedHomeAddOn()
	:
	BDiskSystemAddOn(kEncryptedHomeDiskSystemPrettyName)
{
}


status_t
EncryptedHomeAddOn::CreatePartitionHandle(BMutablePartition* partition,
	BPartitionHandle** _handle)
{
	if (partition == NULL || _handle == NULL)
		return B_BAD_VALUE;

	EncryptedHomePartitionHandle* handle
		= new(nothrow) EncryptedHomePartitionHandle(partition);
	if (handle == NULL)
		return B_NO_MEMORY;

	*_handle = handle;
	return B_OK;
}


bool
EncryptedHomeAddOn::CanInitialize(const BMutablePartition* partition)
{
	(void)partition;

	return EncryptedHomeSupportsInitializing();
}


status_t
EncryptedHomeAddOn::ValidateInitialize(const BMutablePartition* partition,
	BString* name, const char* parameters)
{
	(void)partition;
	(void)name;
	(void)parameters;

	return EncryptedHomeValidateInitialize();
}


status_t
EncryptedHomeAddOn::Initialize(BMutablePartition* partition, const char* name,
	const char* parameters, BPartitionHandle** _handle)
{
	(void)partition;
	(void)name;
	(void)parameters;
	(void)_handle;

	return EncryptedHomeValidateInitialize();
}


EncryptedHomePartitionHandle::EncryptedHomePartitionHandle(
	BMutablePartition* partition)
	:
	BPartitionHandle(partition)
{
}


uint32
EncryptedHomePartitionHandle::SupportedOperations(uint32 mask)
{
	(void)mask;

	return 0;
}


status_t
get_disk_system_add_ons(BList* addOns)
{
	if (addOns == NULL)
		return B_BAD_VALUE;

	EncryptedHomeAddOn* addOn = new(nothrow) EncryptedHomeAddOn;
	if (addOn == NULL)
		return B_NO_MEMORY;

	if (!addOns->AddItem(addOn)) {
		delete addOn;
		return B_NO_MEMORY;
	}

	return B_OK;
}
