/*
 * Copyright 2017 Julian Harnath <julian.harnath@rwth-aachen.de>
 * All rights reserved. Distributed under the terms of the MIT license.
 */

#ifndef FUSE_SMB_SETTINGS_H
#define FUSE_SMB_SETTINGS_H

#include <SupportDefs.h>


class BDirectory;


namespace FuseSmb {


class Settings {
public:
								Settings();

			bool				IsEnabled();
			uint32				ScanInterval();
			bool				ShowHiddenShares();

			void				SetEnabled(bool enabled);
			void				SetScanInterval(uint32 interval);
			void				SetShowHiddenShares(bool showHiddenShares);

			void				Refresh();
			void				Commit();

private:
			void				_SetDefaults();
			bool				_ReadFuseSmbConf();
			void				_WriteFuseSmbConf();
			void				_UpdateLaunchDaemonJob();
			BDirectory*			_GetLaunchDaemonDataDirectory();

private:
	enum {
		kDefaultScanInterval = 15
	};

private:
			bool				fIsEnabled;
			uint32				fScanInterval;
			bool				fShowHiddenShares;
};


} // namespace FuseSmb


#endif // FUSE_SMB_SETTINGS_H
