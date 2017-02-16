/*
 * Copyright 2017 Julian Harnath <julian.harnath@rwth-aachen.de>
 * All rights reserved. Distributed under the terms of the MIT license.
 */

#include "Settings.h"

#include <Directory.h>
#include <Entry.h>
#include <File.h>
#include <FindDirectory.h>
#include <Path.h>
#include <String.h>

#include "../fusesmb/configfile.h"


using namespace FuseSmb;


Settings::Settings()
	:
	fIsEnabled(false),
	fScanInterval(0),
	fShowHiddenShares(false)
{
	Refresh();
}


bool
Settings::IsEnabled()
{
	return fIsEnabled;
}


uint32
Settings::ScanInterval()
{
	return fScanInterval;
}


bool
Settings::ShowHiddenShares()
{
	return fShowHiddenShares;
}


void
Settings::SetEnabled(bool enabled)
{
	fIsEnabled = enabled;
}


void
Settings::SetScanInterval(uint32 interval)
{
	fScanInterval = interval;
}


void
Settings::SetShowHiddenShares(bool showHiddenShares)
{
	fShowHiddenShares = showHiddenShares;
}


void
Settings::Refresh()
{
	bool success = _ReadFuseSmbConf();
	if (!success) {
		_SetDefaults();
		_WriteFuseSmbConf();
	}

	BDirectory* launchDirectory = _GetLaunchDaemonDataDirectory();
	fIsEnabled = launchDirectory->Contains("fusesmb");
	delete launchDirectory;
}


void
Settings::Commit()
{
	_WriteFuseSmbConf();
	_UpdateLaunchDaemonJob();
}


void
Settings::_SetDefaults()
{
	fScanInterval = kDefaultScanInterval;
	fShowHiddenShares = false;
}


bool
Settings::_ReadFuseSmbConf()
{
	BPath settingsPath;
	status_t status = find_directory(B_USER_SETTINGS_DIRECTORY, &settingsPath);
	if (status != B_OK)
		return false;
	settingsPath.Append("fusesmb/fusesmb.conf");

	config_t config;
	int configStatus = config_init(&config, settingsPath.Path());
	if (configStatus != 0)
		return false;

	int showHiddenValue = 0;
	configStatus = config_read_bool(&config, "global", "showhiddenshares",
		&showHiddenValue);
	if (configStatus != 0) {
		config_free(&config);
		return false;
	}

	int intervalValue = 0;
	configStatus = config_read_int(&config, "global", "interval",
		&intervalValue);
	if (configStatus != 0) {
		config_free(&config);
		return false;
	}

	fScanInterval = intervalValue;
	fShowHiddenShares = showHiddenValue == 1;

	config_free(&config);
	return true;
}


void
Settings::_WriteFuseSmbConf()
{
	BPath settingsPath;
	status_t status = find_directory(B_USER_SETTINGS_DIRECTORY, &settingsPath);
	if (status != B_OK)
		return;

	BDirectory settingsDirectory(settingsPath.Path());
	if (settingsDirectory.InitCheck() != B_OK)
		return;

	BDirectory fusesmbDirectory(&settingsDirectory, "fusesmb");
	if (fusesmbDirectory.InitCheck() != B_OK) {
		status = settingsDirectory.CreateDirectory("fusesmb",
			&fusesmbDirectory);
		if (status != B_OK)
			return;
	}

	BFile settingsFile;
	status = fusesmbDirectory.CreateFile("fusesmb.conf", &settingsFile);
	if (status == B_OK) {
		BString settings(
			"; Written by FuseSMB Network preferences\n"
			"\n"
			"[global]\n"
			"timeout = 60\n");
		settings << "showhiddenshares = ";
		if (fShowHiddenShares)
			settings << "true\n";
		else
			settings << "false\n";
		settings << "interval = " << fScanInterval << "\n";
		settingsFile.Write(settings.String(), settings.Length());
	}
	settingsFile.SetPermissions(S_IRUSR | S_IWUSR);
}


void
Settings::_UpdateLaunchDaemonJob()
{
	BDirectory* launchDirectory = _GetLaunchDaemonDataDirectory();
	if (fIsEnabled) {
		if (launchDirectory->Contains("fusesmb")) {
			delete launchDirectory;
			return;
		}

		BFile jobFile;
		status_t status = launchDirectory->CreateFile("fusesmb", &jobFile);
		if (status == B_OK) {
			char jobDescription[] =
				"job fusesmb-start {\n"
				"\tlaunch /bin/sh "
				"/bin/fusesmb-control.sh start\n"
				"}\n";
			jobFile.Write(&jobDescription[0], sizeof(jobDescription) - 1);
		}
	} else {
		if (!launchDirectory->Contains("fusesmb")) {
			delete launchDirectory;
			return;
		}

		BEntry jobFileEntry;
		status_t status = launchDirectory->FindEntry("fusesmb", &jobFileEntry);
		if (status == B_OK)
			jobFileEntry.Remove();
	}

	delete launchDirectory;
}


BDirectory*
Settings::_GetLaunchDaemonDataDirectory()
{
	BPath dataPath;
	status_t status = find_directory(B_USER_NONPACKAGED_DATA_DIRECTORY,
		&dataPath);
	if (status != B_OK)
		return NULL;
	BDirectory dataDirectory(dataPath.Path());
	if (dataDirectory.InitCheck() != B_OK)
		return NULL;

	BDirectory* launchDirectory = new BDirectory(&dataDirectory, "launch");
	if (launchDirectory->InitCheck() != B_OK) {
		status = dataDirectory.CreateDirectory("launch", launchDirectory);
		if (status != B_OK)
			return NULL;
	}

	return launchDirectory;
}
