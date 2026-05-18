/*
 * Copyright 2009-2010, Stephan Aßmus <superstippi@gmx.de>
 * Copyright 2005, Jérôme DUVAL
 *  All rights reserved. Distributed under the terms of the MIT License.
 */
#ifndef INSTALLER_WINDOW_H
#define INSTALLER_WINDOW_H


#include <String.h>
#include <Window.h>


namespace BPrivate {
	class PaneSwitch;
};
using namespace BPrivate;

class BButton;
#ifdef ENCRYPTED_HOME_AVAILABLE
class BCheckBox;
#endif
class BLayoutItem;
class BGroupView;
class BMenu;
class BMenuField;
class BMenuItem;
class BStatusBar;
class BStringView;
#ifdef ENCRYPTED_HOME_AVAILABLE
class BTextControl;
#endif
class BTextView;
class PackagesView;
class WorkerThread;

enum InstallStatus {
	kReadyForInstall,
	kInstalling,
	kFinished,
	kCancelled
};


class InstallerWindow : public BWindow {
public:
								InstallerWindow();
	virtual						~InstallerWindow();

	virtual	void				MessageReceived(BMessage* message);
	virtual	bool				QuitRequested();
private:
			void				_ShowOptionalPackages();
			void				_LaunchDriveSetup();
			void				_LaunchBootManager();
			void				_DisableInterface(bool disable);
			void				_ScanPartitions();
			void				_UpdateControls();
			void				_PublishPackages();
			void				_SetStatusMessage(const char* text);

			void				_SetCopyEngineCancelSemaphore(sem_id id,
									bool alreadyLocked = false);
			void				_QuitCopyEngine(bool askUser);

	static	int					_ComparePackages(const void* firstArg,
									const void* secondArg);

			BGroupView*			fLogoGroup;
			BTextView*			fStatusView;
			BMenu*				fSrcMenu;
			BMenu*				fDestMenu;
#ifdef ENCRYPTED_HOME_AVAILABLE
			BMenu*				fHomeMenu;
#endif
			BMenuField*			fSrcMenuField;
			BMenuField*			fDestMenuField;
#ifdef ENCRYPTED_HOME_AVAILABLE
			BMenuField*			fHomeMenuField;
#endif

			PaneSwitch*			fPackagesSwitch;
			PackagesView*		fPackagesView;
			BStringView*		fSizeView;
#ifdef ENCRYPTED_HOME_AVAILABLE
			BCheckBox*			fEncryptHomeCheckBox;
			BTextControl*		fPassphraseControl;
			BTextControl*		fPassphraseConfirmControl;
#endif

			BStatusBar*			fProgressBar;

			BLayoutItem*		fPkgSwitchLayoutItem;
			BLayoutItem*		fPackagesLayoutItem;
			BLayoutItem*		fSizeViewLayoutItem;
			BLayoutItem*		fProgressLayoutItem;

			BButton*			fBeginButton;
			BButton*			fLaunchDriveSetupButton;
			BMenuItem*			fLaunchBootManagerItem;
			BMenuItem*			fMakeBootableItem;
			BMenu*				fEFILoaderMenu;

			bool				fEncouragedToSetupPartitions;

			bool				fDriveSetupLaunched;
			bool				fBootManagerLaunched;
			InstallStatus		fInstallStatus;

			WorkerThread*		fWorkerThread;
			BString				fLastStatus;
			sem_id				fCopyEngineCancelSemaphore;
};


#endif // INSTALLER_WINDOW_H
