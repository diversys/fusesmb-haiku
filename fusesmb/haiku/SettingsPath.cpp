/*
 * Copyright 2017 Julian Harnath <julian.harnath@rwth-aachen.de>
 * All rights reserved. Distributed under the terms of the MIT license.
 */

#include "support.h"

#include <Directory.h>
#include <FindDirectory.h>
#include <Path.h>

#include <string.h>


int
create_settings_dir()
{
	BPath path;
	status_t status = find_directory(B_USER_SETTINGS_DIRECTORY, &path);
	if (status != B_OK)
		return -1;

	BDirectory directory(path.Path());
	if (directory.InitCheck() != B_OK)
		return -1;

	if (directory.Contains("fusesmb")) {
		// Settings directory already exists
		return 0;
	}

	status = path.Append("fusesmb");
	if (status != B_OK)
		return -1;

	status = create_directory(path.Path(), 0777);
	return status == B_OK;
}


void
get_path_in_settings_dir(char* outBuffer, size_t outBufferSize,
	const char* fileName)
{
	if (outBufferSize < 1)
		return;
	outBuffer[0] = '\0';

	BPath path;
	status_t status = find_directory(B_USER_SETTINGS_DIRECTORY, &path);
	if (status != B_OK)
		return;

	status = path.Append("fusesmb");
	if (status != B_OK)
		return;

	status = path.Append(fileName);
	if (status != B_OK)
		return;

	strlcpy(outBuffer, path.Path(), outBufferSize);
}
