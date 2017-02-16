/*
 * Copyright 2017 Julian Harnath <julian.harnath@rwth-aachen.de>
 * All rights reserved. Distributed under the terms of the MIT license.
 */

#ifndef FUSE_SMB_SETTINGS_LIST_ITEM_H
#define FUSE_SMB_SETTINGS_LIST_ITEM_H

#include "ServiceListItem.h"

#include "Settings.h"


namespace FuseSmb {


class SettingsListItem : public ServiceListItem {
public:
	SettingsListItem(const char* name, const char* label,
		const BNetworkSettings& networkSettings)
		:
		ServiceListItem(name, label, networkSettings)
	{
		Settings settings;
		fEnabled = settings.IsEnabled();
	}

	virtual bool IsEnabled()
	{
		return fEnabled;
	}

	void SetEnabled(bool enabled)
	{
		fEnabled = enabled;
		SettingsUpdated(BNetworkSettings::kMsgServiceSettingsUpdated);
	}

private:
	bool fEnabled;
};


} // namespace FuseSmb


#endif // FUSE_SMB_SETTINGS_LIST_ITEM_H
