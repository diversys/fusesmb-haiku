/*
 * Copyright 2017 Julian Harnath <julian.harnath@rwth-aachen.de>
 * All rights reserved. Distributed under the terms of the MIT license.
 */

#ifndef FUSE_SMB_SETTINGS_ITEM_H
#define FUSE_SMB_SETTINGS_ITEM_H

#include <NetworkSettingsAddOn.h>
#include <NetworkSettings.h>

#include "Settings.h"


namespace FuseSmb {


class SettingsListItem;
class SettingsView;


class SettingsItem : public BNetworkKit::BNetworkSettingsItem {
public:
								SettingsItem(
									BNetworkKit::BNetworkSettings&
									networkSettings);
	virtual						~SettingsItem();

	virtual	BNetworkKit::BNetworkSettingsType
								Type() const;

	virtual	BListItem*			ListItem();
	virtual	BView*				View();

	virtual	bool				IsRevertable();
	virtual	status_t			Revert();

private:
			Settings			fSettings;
			SettingsListItem*	fListItem;
			SettingsView*		fView;
};


} // namespace FuseSmb


#endif // FUSE_SMB_SETTINGS_ITEM_H
