/*
 * Copyright 2017 Julian Harnath <julian.harnath@rwth-aachen.de>
 * All rights reserved. Distributed under the terms of the MIT license.
 */

#include "SettingsView.h"

#include <Alert.h>
#include <Button.h>
#include <Catalog.h>
#include <CheckBox.h>
#include <Directory.h>
#include <LayoutBuilder.h>
#include <Slider.h>
#include <String.h>
#include <StringView.h>
#include <TextView.h>

#include <kernel/fs_volume.h>

#include <stdlib.h>

#include "Settings.h"
#include "SettingsListItem.h"


#undef  B_TRANSLATION_CONTEXT
#define B_TRANSLATION_CONTEXT "FuseSmbSettingsAddOn"


static const char* kMountPointName = "SMB Network";


using namespace FuseSmb;


SettingsView::SettingsView(Settings* settings, SettingsListItem* listItem)
	:
	BView("FuseSmbSettings", 0),
	fSettings(settings),
	fSettingsListItem(listItem),
	fActivationButton(NULL),
	fShowHiddenCheckbox(NULL),
	fScanIntervalSlider(NULL),
	fScanIntervalValueLabel(NULL),
	fScanNowButton(NULL),
	fApplyButton(NULL)
{
	BStringView* headerLabel = new BStringView(NULL,
		B_TRANSLATE("SMB client"));
	headerLabel->SetFont(be_bold_font);
	BTextView* descriptionLabel = _CreateLabel("Description",
		B_TRANSLATE("The SMB client allows access to shared files and folders "
			"using the Server Message Block (SMB) protocol. One version of "
			"the protocol is also known as Common Internet File System "
			"(CIFS)."), false);

	fActivationButton = new BButton(
		"Activation", "",
		new BMessage(kMsgActivationChanged));

	fShowHiddenCheckbox = new BCheckBox("ShowHidden",
		B_TRANSLATE("Show hidden shares"),
		new BMessage(kMsgShowHiddenSharesChanged));

	fScanIntervalLabel = _CreateLabel("ScanInterval",
		B_TRANSLATE("Scan network for SMB shares every:"), true);
	BString intervalValueText("mmm ");
		// "mmm" gives us enough room for 3 digits
	intervalValueText << B_TRANSLATE("minutes");
	fScanIntervalValueLabel = _CreateLabel("ScanIntervalValue",
		intervalValueText.String(), true);
	fScanIntervalValueLabel->SetAlignment(B_ALIGN_RIGHT);

	fScanIntervalSlider = new BSlider("ScanInterval",
		NULL, NULL, kMinScanInterval, kMaxScanInterval,
		B_HORIZONTAL);
	fScanIntervalSlider->SetModificationMessage(
		new BMessage(kMsgScanIntervalChanged));
	BString minLabel;
	minLabel << kMinScanInterval << " ";
	if (kMinScanInterval == 1)
		minLabel << B_TRANSLATE("minute");
	else
		minLabel << B_TRANSLATE("minutes");
	BString maxLabel;
	maxLabel << kMaxScanInterval << " " << B_TRANSLATE("minutes");
	fScanIntervalSlider->SetLimitLabels(minLabel.String(), maxLabel.String());

	fScanNowButton = new BButton(
		"ScanNow", B_TRANSLATE("Scan now"),
		new BMessage(kMsgScanNow));

	fApplyButton = new BButton(
		"Apply", B_TRANSLATE("Apply"),
		new BMessage(kMsgApply));

	BLayoutBuilder::Group<>(this, B_VERTICAL, 10)
		.Add(headerLabel)
		.Add(descriptionLabel)
		.AddGroup(B_HORIZONTAL, 10)
			.AddGlue()
			.Add(fActivationButton)
			.End()
		.AddStrut(5)
		.Add(fShowHiddenCheckbox)
		.AddGroup(B_HORIZONTAL, 10)
			.Add(fScanIntervalLabel)
			.Add(fScanIntervalValueLabel)
			.End()
		.Add(fScanIntervalSlider)
		.AddGroup(B_HORIZONTAL, 10)
			.AddGlue()
			.Add(fScanNowButton)
			.Add(fApplyButton)
			.End()
		.AddGlue()
		.End();
}


SettingsView::~SettingsView()
{
}


void
SettingsView::AttachedToWindow()
{
	fActivationButton->SetTarget(this);
	fShowHiddenCheckbox->SetTarget(this);
	fScanIntervalSlider->SetTarget(this);
	fScanNowButton->SetTarget(this);
	fApplyButton->SetTarget(this);

	_Refresh();
}


void
SettingsView::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgActivationChanged:
		{
			bool enabled = !fSettings->IsEnabled();
			fSettings->SetEnabled(enabled);
			fSettings->Commit();
			_UpdateControlsEnabled();
			bool success = _UpdateMountState();
			if (!success) {
				// Roll back
				enabled = !enabled;
				fSettings->SetEnabled(enabled);
				fSettings->Commit();
				_UpdateControlsEnabled();
			}
			break;
		}

		case kMsgShowHiddenSharesChanged:
			fSettings->SetShowHiddenShares(
				fShowHiddenCheckbox->Value() == B_CONTROL_ON);
			fApplyButton->SetEnabled(true);
			break;

		case kMsgScanIntervalChanged:
			_ScanIntervalChanged();
			fSettings->SetScanInterval(fScanIntervalSlider->Value());
			fApplyButton->SetEnabled(true);
			break;

		case kMsgScanNow:
			_ScanNow();
			break;

		case kMsgApply:
			fSettings->Commit();
			fApplyButton->SetEnabled(false);
			break;

		default:
			BView::MessageReceived(message);
			break;
	}
}


bool
SettingsView::IsRevertable()
{
	return false;
}


status_t
SettingsView::Revert()
{
	return B_UNSUPPORTED;
}


BTextView*
SettingsView::_CreateLabel(const char* name, const char* text, bool singleLine)
{
	BTextView* label = new BTextView(name);
	label->SetText(text);
	label->MakeEditable(false);
	label->SetViewUIColor(B_PANEL_BACKGROUND_COLOR);
	if (singleLine)
		label->SetExplicitMinSize(BSize(StringWidth(text) + 1, B_SIZE_UNSET));
	return label;
}


void
SettingsView::_Refresh()
{
	fShowHiddenCheckbox->SetValue(fSettings->ShowHiddenShares());
	fScanIntervalSlider->SetValue(fSettings->ScanInterval());
	_ScanIntervalChanged();
	_UpdateControlsEnabled();
}


void
SettingsView::_UpdateControlsEnabled()
{
	bool enabled = fSettings->IsEnabled();

	fShowHiddenCheckbox->SetEnabled(enabled);
	fScanIntervalSlider->SetEnabled(enabled);
	fScanNowButton->SetEnabled(enabled);
	fApplyButton->SetEnabled(false);

	if (enabled) {
		fActivationButton->SetLabel(B_TRANSLATE("Disable"));
		rgb_color enabledColor = ui_color(B_PANEL_TEXT_COLOR);
		fScanIntervalLabel->SetFontAndColor(be_plain_font, B_FONT_ALL,
			&enabledColor);
		fScanIntervalValueLabel->SetFontAndColor(be_plain_font, B_FONT_ALL,
			&enabledColor);
	} else {
		fActivationButton->SetLabel(B_TRANSLATE("Enable"));
		rgb_color disabledColor = tint_color(
			ui_color(B_PANEL_BACKGROUND_COLOR), B_DISABLED_LABEL_TINT);
		fScanIntervalLabel->SetFontAndColor(be_plain_font, B_FONT_ALL,
			&disabledColor);
		fScanIntervalValueLabel->SetFontAndColor(be_plain_font, B_FONT_ALL,
			&disabledColor);
	}

	fSettingsListItem->SetEnabled(enabled);
}


bool
SettingsView::_UpdateMountState()
{
	// Start/stop fusesmb
	BDirectory root("/");
	status_t status = root.InitCheck();
	if (status != B_OK) {
		_ShowError(B_TRANSLATE("Failed to open root directory"), status);
		return false;
	}

	BEntry mountPointEntry;
	root.FindEntry(kMountPointName, &mountPointEntry);

	if (fSettings->IsEnabled()) {
		if (!mountPointEntry.Exists()) {
			status = root.CreateDirectory(kMountPointName, NULL);
			if (status != B_OK) {
				_ShowError(B_TRANSLATE(
					"Failed to create mount point directory"), status);
				return false;
			}
		}

		BString mountPath("/");
		mountPath << kMountPointName;
		dev_t device = fs_mount_volume(mountPath.String(), NULL, "userlandfs",
			0, "fusesmb");
		if (device < B_OK) {
			_ShowError(B_TRANSLATE("Failed to mount FuseSMB filesystem"),
				device);
			return false;
		}
	} else {
		if (!mountPointEntry.Exists())
			return true;

		// Errors below will still return true to continue with disabling
		// FuseSMB in launch daemon, so even if it fails now, it's at least
		// disabled on next boot.

		BString mountPath("/");
		mountPath << kMountPointName;
		status = fs_unmount_volume(mountPath.String(), 0);
		if (status != B_OK) {
			_ShowError(B_TRANSLATE("Failed to unmount FuseSMB filesystem"),
				status);
			return true;
		}

		status = mountPointEntry.Remove();
		if (status != B_OK) {
			_ShowError(B_TRANSLATE(
				"Failed to remove mount point directory"), status);
			return true;
		}
	}

	return true;
}


void
SettingsView::_ScanIntervalChanged()
{
	int32 interval = fScanIntervalSlider->Value();
	BString text;
	text << interval << " ";
	if (interval == 1)
		text << B_TRANSLATE("minute");
	else
		text << B_TRANSLATE("minutes");
	fScanIntervalValueLabel->SetText(text);
}


void
SettingsView::_ScanNow()
{
	system("fusesmb-scan");
}


void
SettingsView::_ShowError(const char* message, status_t errorCode)
{
	BString errorMessage(message);
	errorMessage << ":\n" << strerror(errorCode);
	BAlert* alert = new BAlert("Error", errorMessage.String(),
			B_TRANSLATE("OK"), NULL, NULL,
			B_WIDTH_AS_USUAL, B_WARNING_ALERT);
	alert->Go();
}
