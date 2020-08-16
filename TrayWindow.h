#pragma once
#include <Windows.h>
#include <shellapi.h>
#include <tchar.h>
#include <psapi.h>
#include <strsafe.h>
#include <optional>
#include "resource.h"

extern "C" IMAGE_DOS_HEADER __ImageBase;

const TCHAR gPipeName[] = _T("\\\\.\\pipe\\GPG_SSH_BRIDGE_SOCK");

winrt::hstring GetModuleName() {
	TCHAR fName[MAX_PATH];
	if (!GetModuleBaseName(GetCurrentProcess(), nullptr, fName, MAX_PATH)) {
		return winrt::hstring{};
	}
	return winrt::to_hstring(fName);
}

static winrt::hstring __MODULENAME = GetModuleName();

struct TrayWindow
{
	TrayWindow();

	bool forceClose(winrt::hstring err) const;

	~TrayWindow();

private:
	enum : UINT {
		TRAY_UID = 555,

		WM_CALLBACK_MSG = WM_USER + 1,
		WM_ERROR_CLOSE,

		IDM_QUIT = 0
	};

	HWND hWnd = nullptr;
	std::optional<winrt::hstring> err = std::nullopt;
	NOTIFYICONDATA nid{};
	HMENU menu = nullptr;
	bool lastDblClick = false;
	winrt::Windows::ApplicationModel::DataTransfer::DataPackage pipeName;

	static LRESULT WINAPI WndProc(HWND const window, UINT const message, WPARAM const wparam, LPARAM const lparam) noexcept;

	void showMenu();
};


inline TrayWindow::TrayWindow() {
	// Register window class.
	WNDCLASSEX wcls{};
	wcls.cbSize = sizeof(wcls);
	wcls.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
	wcls.hInstance = reinterpret_cast<HINSTANCE>(&__ImageBase);
	wcls.lpszClassName = _T("SystrayGpgBridgeClass");
	wcls.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
	wcls.lpfnWndProc = WndProc;
	auto clsA = RegisterClassEx(&wcls);
	winrt::check_pointer(reinterpret_cast<LPCTSTR>(clsA));

	// Create Window.
	hWnd = CreateWindowEx(WS_EX_LEFT, reinterpret_cast<LPCTSTR>(clsA), _T("GpgSshBridgeTray"), WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		nullptr, nullptr, wcls.hInstance, this);
	winrt::check_pointer(hWnd);

	ShowWindow(hWnd, SW_HIDE);
	UpdateWindow(hWnd);

	// Add icon to tray.
	nid.cbSize = sizeof(nid);
	nid.hWnd = hWnd;
	nid.uID = TRAY_UID;
	nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
	nid.uCallbackMessage = WM_CALLBACK_MSG;
	StringCchCopy(nid.szTip, sizeof(nid.szTip) / sizeof(*(nid.szTip)), _T("gpg-agent bridge for ssh"));
	nid.hIcon = LoadIcon(wcls.hInstance, MAKEINTRESOURCE(IDI_TRAYICON));
	winrt::check_bool(Shell_NotifyIcon(NIM_ADD, &nid));

	// Create a menu.
	menu = CreatePopupMenu();
	winrt::check_pointer(menu);
	auto mii = MENUITEMINFO{};
	mii.cbSize = sizeof(mii);
	mii.fMask = MIIM_FTYPE | MIIM_STATE | MIIM_STRING | MIIM_ID;
	mii.fType = MFT_STRING;
	mii.fState = MFS_ENABLED;
	mii.wID = IDM_QUIT;
	mii.dwTypeData = (LPTSTR)_T("Quit");
	winrt::check_bool(InsertMenuItem(menu, 0, true, &mii));

	// set pipeName.
	pipeName.SetText(gPipeName);
}

inline bool TrayWindow::forceClose(winrt::hstring errorString) const
{
	auto errHStr = winrt::detach_abi(errorString);
	SendMessage(hWnd, WM_ERROR_CLOSE, (WPARAM)(errHStr), 0);
	auto n = GetLastError();
	if (n) { //failed
		winrt::attach_abi(errorString, errHStr);
	}
	SetLastError(n);

	return !n;
}

inline LRESULT __stdcall TrayWindow::WndProc(HWND const window, UINT const message, WPARAM const wparam, LPARAM const lparam) noexcept {
	if (message == WM_NCCREATE) {
		auto cs = reinterpret_cast<CREATESTRUCT*>(lparam);
		auto cur = static_cast<TrayWindow*>(cs->lpCreateParams);
		WINRT_ASSERT(cur);
		SetWindowLongPtr(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cur));
		return true;
	}
	auto getThis = [window]() {
		auto cur = reinterpret_cast<TrayWindow*>(GetWindowLongPtr(window, GWLP_USERDATA));
		WINRT_ASSERT(cur);
		return cur;
	};
	static UINT taskbarRestart;
	switch (message) {
	case WM_CREATE:
		taskbarRestart = RegisterWindowMessage((TEXT("TaskbarCreated")));
		return 0;
	case WM_ERROR_CLOSE:
	{
		winrt::hstring e;
		winrt::attach_abi(e, (HSTRING)wparam);
		getThis()->err = e;
	}
	DestroyWindow(window);
	return 0;
	case WM_DESTROY:
	{
		auto thisObj = getThis();
		Shell_NotifyIcon(NIM_DELETE, &(thisObj->nid));
		thisObj->hWnd = nullptr;
		int n = 0;
		if (thisObj->err) {
			winrt::hstring text = __MODULENAME + _T(":\n  ") + *(thisObj->err);
			MessageBoxW(nullptr, text.data(), L"Error", MB_OK | MB_ICONERROR | MB_TASKMODAL | MB_TOPMOST);
			n = 1;
		}
		PostQuitMessage(n);
	}
	return 0;
	case WM_ENDSESSION:
		Shell_NotifyIcon(NIM_DELETE, &(getThis()->nid));
		return 0;
	case WM_CALLBACK_MSG:
		switch (lparam) {
		case WM_LBUTTONDBLCLK:
			getThis()->lastDblClick = true;
			break;
		case WM_LBUTTONUP:
		{
			auto thisObj = getThis();
			if (thisObj->lastDblClick) {
				winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(thisObj->pipeName);
			}
			thisObj->lastDblClick = false;
		}
		break;
		case WM_RBUTTONUP:
			getThis()->showMenu();
		}
		return 0;
	case WM_COMMAND:
		switch (LOWORD(wparam)) {
		case IDM_QUIT:
			PostMessage(window, WM_CLOSE, 0, 0);
			break;
		}
		return 0;
	default:
		if (message == taskbarRestart) {
			winrt::check_bool(Shell_NotifyIcon(NIM_ADD, &(getThis()->nid)));
		}
		break;
	}
	return DefWindowProc(window, message, wparam, lparam);
}

inline TrayWindow::~TrayWindow()
{
	DestroyMenu(menu);
	if (hWnd) {
		Shell_NotifyIcon(NIM_DELETE, &nid);
		DestroyWindow(hWnd);
	}
}

inline void TrayWindow::showMenu() {
	POINT pos;
	GetCursorPos(&pos);
	SetForegroundWindow(hWnd);
	TrackPopupMenu(menu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pos.x, pos.y, 0, hWnd, nullptr);
}
