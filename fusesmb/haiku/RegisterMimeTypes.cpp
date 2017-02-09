/*
 * Copyright 2017 Julian Harnath <julian.harnath@rwth-aachen.de>
 * All rights reserved. Distributed under the terms of the MIT license.
 */

#include "support.h"

#include <Application.h>
#include <MimeType.h>
#include <Path.h>
#include <Resources.h>
#include <kernel/image.h>

#include <stdio.h>
#include <string.h>


const char* kWorkgroupFolderMimeType = "application/x-vnd.haiku-smb-workgroup";
const char* kServerFolderMimeType = "application/x-vnd.haiku-smb-server";
const char* kShareFolderMimeType = "application/x-vnd.haiku-smb-share";


static void
_register_mime_type(const char* name, const char* iconResourceName,
	const char* shortDescription, const char* longDescription)
{
	BMimeType mimeType(name);
	if (mimeType.InitCheck() != B_OK) {
		fprintf(stderr, "Failed to initialize MIME type '%s'\n", name);
		return;
	}

	if (mimeType.IsInstalled())
		return;

	status_t status = mimeType.Install();
	if (status != B_OK) {
		fprintf(stderr, "Failed to install MIME type '%s'\n", name);
		return;
	}

	image_info info;
	int32 cookie = 0;
	bool found = false;
	while (get_next_image_info(0, &cookie, &info) == B_OK) {
		if (info.type == B_ADD_ON_IMAGE) {
			BPath addOnPath(info.name);
			if (addOnPath.InitCheck() != B_OK) {
				fprintf(stderr, "Failed to initialize BPath\n");
				return;
			}
			if (strcmp(addOnPath.Leaf(), "fusesmb") == 0) {
				found = true;
				break;
			}
		}
	}
	if (!found) {
		fprintf(stderr, "Could not find fusesmb image\n");
		return;
	}

	BFile addOnFile(info.name, B_READ_ONLY);
	BResources resources(&addOnFile);
	size_t iconSize = 0;
	const void* icon = resources.LoadResource('VICN', iconResourceName,
		&iconSize);
	if (icon == NULL) {
		fprintf(stderr, "Failed to load icon '%s'\n", iconResourceName);
		return;
	}
	status = mimeType.SetIcon((const uint8*)icon, iconSize);
	if (status != B_OK) {
		fprintf(stderr, "Failed to set icon for MIME type '%s'\n", name);
		return;
	}

	status = mimeType.SetShortDescription(shortDescription);
	if (status != B_OK) {
		fprintf(stderr, "Failed to set short description for MIME type '%s'\n",
			name);
		return;
	}

	status = mimeType.SetLongDescription(longDescription);
	if (status != B_OK) {
		fprintf(stderr, "Failed to set long description for MIME type '%s'\n",
			name);
		return;
	}
}


void
register_mime_types()
{
	_register_mime_type(kWorkgroupFolderMimeType,
						"WorkgroupIcon",
						"SMB Workgroup",
						"A workgroup in SMB networking");
	_register_mime_type(kServerFolderMimeType,
						"ServerIcon",
						"SMB Server",
						"A server offering SMB networking services");
	_register_mime_type(kShareFolderMimeType,
						"ShareIcon",
						"SMB Share",
						"A network shared folder offered by an SMB server");
}
