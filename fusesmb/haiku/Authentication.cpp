/*
 * Copyright 2017 Julian Harnath <julian.harnath@rwth-aachen.de>
 * All rights reserved. Distributed under the terms of the MIT license.
 */

#include "support.h"

#include <Alert.h>
#include <Button.h>
#include <Catalog.h>
#include <CheckBox.h>
#include <KeyStore.h>
#include <LayoutBuilder.h>
#include <Path.h>
#include <SeparatorView.h>
#include <String.h>
#include <StringView.h>
#include <TextControl.h>
#include <Window.h>

#include <map>
#include <sstream>
#include <string>


#undef  B_TRANSLATION_CONTEXT
#define B_TRANSLATION_CONTEXT "FuseSmbAuthenticationRequester"

static const char* kKeyRing = "FuseSMB";


class CredentialStore {
private:
	struct Credential {
		BString fUsername;
		BString fPassword;
	};
	typedef std::map<std::string, Credential> CredentialMap;

public:
	CredentialStore()
	{
		ReadFromKeyStore();
	}

	~CredentialStore()
	{
	}

	void Add(const BString& server, const BString& share,
		const BString& username, const BString& password, bool saveInKeyStore)
	{
		Credential credential;
		credential.fUsername = username;
		credential.fPassword = password;

		std::stringstream addressStream;
		addressStream << "//" << server.String();
		if (share.Length() > 0)
			addressStream << "/" << share.String();
		std::string address = addressStream.str();

		fCredentials[address] = credential;

		if (saveInKeyStore) {
			printf("saveInKeyStore\n");
			BKeyStore keyStore;
			keyStore.AddKeyring(kKeyRing);
			BPasswordKey key(password.String(), B_KEY_PURPOSE_NETWORK,
				username, address.c_str());
			status_t status = keyStore.AddKey(kKeyRing, key);
			if (status != B_OK) {
				BAlert* alert = new BAlert(B_TRANSLATE("Error"),
					B_TRANSLATE("Failed to store login in key store."),
					B_TRANSLATE("OK"), NULL, NULL,
					B_WIDTH_AS_USUAL, B_WARNING_ALERT);
				alert->Go();
			}
		}
	}

	bool Get(const char* server, const char* share, char* outUsername,
		int usernameMaxLength, char* outPassword, int passwordMaxLength)
	{
		outUsername[0] = '\0';
		outPassword[0] = '\0';

		std::stringstream addressStream;
		addressStream << "//" << server;
		std::string addressServer = addressStream.str();
		addressStream << "/" << share;
		std::string addressServerAndShare = addressStream.str();

		CredentialMap::iterator it = fCredentials.find(addressServerAndShare);
		if (it == fCredentials.end()) {
			// Try again without share name, maybe we have a server-wide
			// login stored
			it = fCredentials.find(addressServer);
			if (it == fCredentials.end())
				return false;
		}

		strlcpy(outUsername, it->second.fUsername.String(), usernameMaxLength);
		strlcpy(outPassword, it->second.fPassword.String(), passwordMaxLength);

		return true;
	}

	void Clear()
	{
		fCredentials.clear();
	}

	void ReadFromKeyStore()
	{
		BKeyStore keyStore;
		BPasswordKey key;
		uint32 cookie = 0;
		for (;;) {
			status_t status = keyStore.GetNextKey(kKeyRing,
				B_KEY_TYPE_PASSWORD, B_KEY_PURPOSE_NETWORK,
				cookie, key);
			if (status != B_OK)
				return;

			Credential credential;
			credential.fUsername = key.Identifier();
			credential.fPassword = key.Password();
			fCredentials[key.SecondaryIdentifier()] = credential;

			printf("read from keystore %s/%s/%s\n", key.Identifier(), key.SecondaryIdentifier(),
				key.Password());
		}
	}

private:
	CredentialMap	fCredentials;
};


class AuthenticationRequester : public BWindow {
private:
	enum {
		kMsgLoginButton = 1,
		kMsgCancelButton
	};

public:
	struct Result {
		bool fLoginPressed;
		BString fUsername;
		BString fPassword;
		bool fLoginSaveRequested;
		bool fLoginForServer;
	};

public:
	AuthenticationRequester()
		:
		BWindow(BRect(0, 0, 1, 1),
			B_TRANSLATE("Login required"),
			B_MODAL_WINDOW,
			B_NOT_RESIZABLE | B_AUTO_UPDATE_SIZE_LIMITS),
		fLoginPressed(false)
	{
		fLoginButton = new BButton("Login", B_TRANSLATE("Login"),
			new BMessage(kMsgLoginButton));
		fCancelButton = new BButton("Cancel", B_TRANSLATE("Cancel"),
			new BMessage(kMsgCancelButton));

		fUsernameTextControl = new BTextControl("Username", NULL, NULL, NULL);
		fPasswordTextControl = new BTextControl("Password", NULL, NULL, NULL);
		fPasswordTextControl->TextView()->HideTyping(true);

		fSaveLoginCheckBox = new BCheckBox("SaveLogin",
			B_TRANSLATE("Remember login data"), NULL);
		fServerLoginCheckBox = new BCheckBox("ServerLogin",
			B_TRANSLATE("Use login for all shares on this server"), NULL);

		fWaitForUserSem = create_sem(0, "user input wait");
	}

	virtual ~AuthenticationRequester()
	{
		delete_sem(fWaitForUserSem);
	}

	virtual bool QuitRequested()
	{
		release_sem(fWaitForUserSem);
		return false;
	}

	virtual void MessageReceived(BMessage* message)
	{
		switch (message->what) {
			case kMsgLoginButton:
				fLoginPressed = true;
				release_sem(fWaitForUserSem);
				break;

			case kMsgCancelButton:
				release_sem(fWaitForUserSem);
				break;

			default:
				BWindow::MessageReceived(message);
				break;
		}
	}

	Result Run(const char* path)
	{
		BStringView* textView = new BStringView(NULL,
			B_TRANSLATE("Login required to access:"));

		BString fullPath = "/";
		fullPath << path;
		BStringView* pathView = new BStringView(NULL, fullPath);
		pathView->SetAlignment(B_ALIGN_CENTER);

		BStringView* usernameLabel = new BStringView(NULL,
			B_TRANSLATE("User name:"));
		BStringView* passwordLabel = new BStringView(NULL,
			B_TRANSLATE("Password:"));

		BLayoutBuilder::Group<>(this, B_VERTICAL, 5)
			.SetInsets(15)
			.Add(textView)
			.Add(pathView)
			.AddStrut(2)
			.Add(new BSeparatorView(B_HORIZONTAL))
			.AddStrut(2)
			.AddGrid(5, 5)
				.Add(usernameLabel,        0, 0)
				.Add(fUsernameTextControl, 1, 0)
				.Add(passwordLabel,        0, 1)
				.Add(fPasswordTextControl, 1, 1)
				.End()
			.Add(fServerLoginCheckBox)
			.Add(fSaveLoginCheckBox)
			.AddGroup(B_HORIZONTAL)
				.AddGlue()
				.Add(fCancelButton)
				.Add(fLoginButton)
				.End()
			.End();

		SetDefaultButton(fLoginButton);
		fUsernameTextControl->MakeFocus();
		CenterOnScreen();

		Show();
		acquire_sem(fWaitForUserSem);

		Lock();

		Result result;
		result.fUsername = fUsernameTextControl->Text();
		result.fPassword = fPasswordTextControl->Text();
		result.fLoginSaveRequested =
			fSaveLoginCheckBox->Value() == B_CONTROL_ON;
		result.fLoginForServer =
			fServerLoginCheckBox->Value() == B_CONTROL_ON;
		result.fLoginPressed = fLoginPressed;

		Quit();

		return result;
	}

private:
	BButton*		fLoginButton;
	BButton*		fCancelButton;
	BTextControl*	fUsernameTextControl;
	BTextControl*	fPasswordTextControl;
	BCheckBox*		fSaveLoginCheckBox;
	BCheckBox*		fServerLoginCheckBox;

	BString			fPathString;
	bool			fLoginPressed;
	sem_id			fWaitForUserSem;
};


CredentialStore gCredentialStore;


void
get_authentication(const char* server, const char* share,
	char*, int,
	char* username, int usernameMaxLength,
	char* password, int passwordMaxLength)
{
	if (usernameMaxLength < 1 || passwordMaxLength < 1)
		return;
	gCredentialStore.Get(server, share, username, usernameMaxLength,
		password, passwordMaxLength);
}


int
show_authentication_request(const char* path)
{
	AuthenticationRequester* authRequester = new AuthenticationRequester();
	AuthenticationRequester::Result result = authRequester->Run(path);
	if (!result.fLoginPressed) {
		// User pressed cancel
		return -1;
	}

	// Path format is /WORKGROUP/SERVER/SHARE
	// The /SHARE part might not be there when getting authentication
	// for a whole server.
	// We need to extract the SERVER and, if present, SHARE parts.

	// Get last two elements of the path
	BPath thePath(path);
	BString temp1(thePath.Leaf());
		// temp1 now holds either SHARE or SERVER

	status_t status = thePath.GetParent(&thePath);
	if (status != B_OK)
		return -1;
	BString temp2(thePath.Leaf());
		// temp2 now holds either SERVER or WORKGROUP

	status = thePath.GetParent(&thePath);
	if (status != B_OK)
		return -1;

	BString server;
	BString share;
	if (BString(thePath.Leaf()) == "/") {
		// Path empty now - that means there was no SHARE part
		server = temp1;
		share = "";
	} else {
		server = temp2;
		share = temp1;
	}

	if (result.fLoginForServer)
		share = "";

	gCredentialStore.Add(
		server,
		share,
		result.fUsername,
		result.fPassword,
		result.fLoginSaveRequested);

	return 0;
}
