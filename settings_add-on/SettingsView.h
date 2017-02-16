/*
 * Copyright 2017 Julian Harnath <julian.harnath@rwth-aachen.de>
 * All rights reserved. Distributed under the terms of the MIT license.
 */

#ifndef FUSE_SMB_SETTINGS_VIEW_H
#define FUSE_SMB_SETTINGS_VIEW_H

#include <View.h>


class BButton;
class BCheckBox;
class BSlider;
class BTextView;


namespace FuseSmb {


class Settings;
class SettingsListItem;


class SettingsView : public BView {
public:
								SettingsView(Settings* settings,
									SettingsListItem* listItem);
	virtual						~SettingsView();

	virtual	void				AttachedToWindow();
	virtual	void				MessageReceived(BMessage* message);

			bool				IsRevertable();
			status_t			Revert();

private:
			BTextView*			_CreateLabel(const char* name,
									const char* text, bool singleLine);
			void				_Refresh();
			void				_UpdateControlsEnabled();
			bool				_UpdateMountState();
			void				_ScanIntervalChanged();
			void				_ScanNow();

			void				_ShowError(const char* message,
									status_t errorCode);

private:
	enum {
		kMsgActivationChanged = 1,
		kMsgShowHiddenSharesChanged,
		kMsgScanIntervalChanged,
		kMsgScanNow,
		kMsgApply
	};

	enum {
		kMinScanInterval = 1,
		kMaxScanInterval = 120
	};

private:
			Settings*			fSettings;
			SettingsListItem*	fSettingsListItem;

			BButton*			fActivationButton;
			BCheckBox*			fShowHiddenCheckbox;
			BSlider*			fScanIntervalSlider;
			BTextView*			fScanIntervalLabel;
			BTextView*			fScanIntervalValueLabel;
			BButton*			fScanNowButton;
			BButton*			fApplyButton;
};


} // namespace FuseSmb


#endif // FUSE_SMB_SETTINGS_VIEW_H
