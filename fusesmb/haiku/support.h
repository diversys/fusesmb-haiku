/*
 * Copyright 2017 Julian Harnath <julian.harnath@rwth-aachen.de>
 * All rights reserved. Distributed under the terms of the MIT license.
 */

/* C interface for Haiku support functionality used inside fusesmb
   (settings path, dialog box for entering auth data, ...)
*/

#ifndef HAIKU_SUPPORT_H
#define HAIKU_SUPPORT_H

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


// Settings
int create_settings_dir();
void get_path_in_settings_dir(char* outBuffer, size_t outBufferSize,
	const char* fileName);


// Authentication
void get_authentication(const char* server, const char* share,
	char* workgroup, int workgroupMaxLength,
	char* username, int usernameMaxLength,
	char* password, int passwordMaxLength);

int show_authentication_request(const char* path);


// MIME types
void register_mime_types();

extern const char* kWorkgroupFolderMimeType;
extern const char* kServerFolderMimeType;
extern const char* kShareFolderMimeType;


#ifdef __cplusplus
} // extern "C"
#endif


#endif // HAIKU_SUPPORT_H
