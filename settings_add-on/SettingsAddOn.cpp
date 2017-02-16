/*
 * Copyright 2017 Julian Harnath <julian.harnath@rwth-aachen.de>
 * All rights reserved. Distributed under the terms of the MIT license.
 */

#include <NetworkSettingsAddOn.h>

#include "SettingsItem.h"


using namespace BNetworkKit;


namespace FuseSmb {


class SettingsAddOn : public BNetworkSettingsAddOn {
public:
	SettingsAddOn(image_id image, BNetworkSettings& settings)
		:
		BNetworkSettingsAddOn(image, settings)
	{
	}

	virtual ~SettingsAddOn()
	{
	}

	virtual BNetworkSettingsItem* CreateNextItem(uint32& cookie)
	{
		if (cookie == 0) {
			cookie++;
			return new SettingsItem(Settings());
		}
		return NULL;
	}
};


} // namespace FuseSmb


extern "C"
BNetworkSettingsAddOn*
instantiate_network_settings_add_on(image_id image, BNetworkSettings& settings)
{
	return new FuseSmb::SettingsAddOn(image, settings);
}
