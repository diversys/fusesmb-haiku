/*
 * Copyright 2017 Julian Harnath <julian.harnath@rwth-aachen.de>
 * All rights reserved. Distributed under the terms of the MIT license.
 */

#include "SettingsItem.h"

#include <Catalog.h>

#include "SettingsListItem.h"
#include "SettingsView.h"


#undef  B_TRANSLATION_CONTEXT
#define B_TRANSLATION_CONTEXT "FuseSmbSettingsAddOn"


using namespace BNetworkKit;
using namespace FuseSmb;


SettingsItem::SettingsItem(BNetworkSettings& networkSettings)
	:
	fListItem(new SettingsListItem("fusesmb", B_TRANSLATE("SMB client"),
		networkSettings)),
	fView(new SettingsView(&fSettings, fListItem))
{
}


SettingsItem::~SettingsItem()
{
}


BNetworkSettingsType
SettingsItem::Type() const
{
	return B_NETWORK_SETTINGS_TYPE_SERVICE;
}


BListItem*
SettingsItem::ListItem()
{
	return fListItem;
}


BView*
SettingsItem::View()
{
	return fView;
}


bool
SettingsItem::IsRevertable()
{
	return fView->IsRevertable();
}


status_t
SettingsItem::Revert()
{
	return fView->Revert();
}
