#include "pch.h"
#include <DispatcherQueue.h>
#include <Windows.h>
#include <string_view>

#include "helper.h"
#include "TrayWindow.h"
#include "PipeServer.h"

using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Networking;
using namespace Windows::Storage;
using namespace Windows::Storage::Streams;
using namespace Windows::System;
using namespace std::chrono_literals;

const UINT AGENT_MAX_MESSAGE_LENGTH = 8192;

static std::string_view inline rtrim(const std::string_view& s) {
	return s.substr(0, std::find_if(s.rbegin(), s.rend(), [](int ch) {
		return !std::isspace(ch);
		}).base() - s.begin());
}

IBuffer ReadPipe(HANDLE hIn)
{
	constexpr auto RBUFSIZE = 4096U;
	BYTE BUF[RBUFSIZE];
	DWORD nRead;
	DataWriter writer;
	for (;;) {
		auto status = ReadFile(hIn, BUF, RBUFSIZE, &nRead, nullptr);
		if (!status || nRead == 0) {
			break;
		}
		writer.WriteBytes(array_view(BUF, BUF + nRead));
	}

	CloseHandle(hIn);
	return writer.DetachBuffer();
}

IAsyncAction WritePipe(HANDLE hOut, const std::string& buf)
{
	co_await winrt::resume_background();

	DWORD nWrite;
	WriteFile(hOut, buf.data(), (DWORD)buf.size(), &nWrite, nullptr);
	CloseHandle(hOut);

	co_return;
}

IAsyncOperation<IBuffer> GetProcessOutput(LPCTSTR cmdline, const std::optional<std::string> input = std::nullopt)
{
	DWORD err = 0;
	DWORD retCode = 0;
	IBuffer buf{ nullptr };
	SECURITY_ATTRIBUTES saAttr{};
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	co_await winrt::resume_background();

	HANDLE hChild_STDOUT_Rd, hChild_STDOUT_Wr;
	check_bool(CreatePipeEx(&hChild_STDOUT_Rd, &hChild_STDOUT_Wr, &saAttr, 0, TRUE));

	HANDLE hChild_STDIN_Rd, hChild_STDIN_Wr;
	if (input && !CreatePipeEx(&hChild_STDIN_Rd, &hChild_STDIN_Wr, &saAttr, 0, TRUE)) {
		err = GetLastError();
		CloseHandle(hChild_STDOUT_Wr);
		CloseHandle(hChild_STDOUT_Rd);
		check_win32(err);
	}

	// Writable cmdline for CreateProcess.
	LPTSTR cmd = _tcsdup(cmdline);

	STARTUPINFO si{};
	PROCESS_INFORMATION pi{};

	// Ensure the STDOUTRd/STDINWr is not inherited by child process.
	if (!SetHandleInformation(hChild_STDOUT_Rd, HANDLE_FLAG_INHERIT, 0)
		|| (input && !SetHandleInformation(hChild_STDIN_Wr, HANDLE_FLAG_INHERIT, 0))) {
		goto closePipeExitL;
	}

	si.cb = sizeof(si);
	si.hStdOutput = hChild_STDOUT_Wr;
	if (input) {
		si.hStdInput = hChild_STDIN_Rd;
	}
	si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	if (CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
		// Close stdout write end.
		CloseHandle(hChild_STDOUT_Wr);

		IAsyncAction writer{ nullptr };
		if (input) {
			// Close stdin read end.
			CloseHandle(hChild_STDIN_Rd);
			writer = WritePipe(hChild_STDIN_Wr, *input);
		}
		// Returns when child closes its stdout/exits.
		buf = ReadPipe(hChild_STDOUT_Rd);

		// Wait for the process to exit.
		co_await resume_on_signal(pi.hProcess);

		// writer should have finished sice child is done and closed its stdin.
		if (input) {
			writer.get();
		}

		if (!GetExitCodeProcess(pi.hProcess, &retCode)) {
			err = GetLastError();
		}
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	else {
	closePipeExitL:
		err = GetLastError();
		CloseHandle(hChild_STDOUT_Wr);
		CloseHandle(hChild_STDOUT_Rd);
		if (input) {
			CloseHandle(hChild_STDIN_Wr);
			CloseHandle(hChild_STDIN_Rd);
		}
	}

	// If any 
	if (err || retCode) {
		buf = nullptr;
	}
	free(cmd);
	check_win32(err);
	co_return buf;
}

IAsyncOperation<bool> VerifyAgentConf()
{
	auto iBuf = co_await GetProcessOutput(_T("gpgconf --list-options gpg-agent"));
	if (!iBuf) {
		co_return false;
	}

	bool puttyEnabled = false;
	auto puttyOption = "enable-putty-support";

	size_t next;
	std::string_view s((char*)iBuf.data(), iBuf.Length());
	while ((next = s.find('\n')) != std::string_view::npos) {
		auto l = s.substr(0, next);
		if (!l.compare(0, min(l.size(), strlen(puttyOption)), puttyOption)) {
			if (size_t val_pos = l.rfind(':'); val_pos != std::string_view::npos) {
				auto s_val = l.substr(val_pos + 1);
				int val = 0;
				if (auto [p, ec] = std::from_chars(s_val.data(), s_val.data() + s_val.size(), val);
					ec == std::errc()) {
					puttyEnabled = (val > 0);
				}
			}
			break;
		}
		s = s.substr(next + 1);
	}

	if (!puttyEnabled) {
		co_return
			co_await GetProcessOutput(_T("gpgconf --change-options gpg-agent"), "enable-putty-support:0:1") &&
			co_await GetProcessOutput(_T("gpgconf --kill gpg-agent"));
	}

	co_return true;
}

IAsyncAction KeepAgentLive(const TrayWindow& w, DispatcherQueue queue)
{
	co_await queue;

	for (;;) {
		// Read the socket information.
		std::string svc;
		BYTE cookie[16]{ 0 };

		auto canStart{ co_await VerifyAgentConf() };
		if (!canStart) {
			co_await queue;
			w.forceClose(to_hstring("Failed to verify gpg-agent configuration.\nPlease make sure you have GnuPG installed and available in PATH"));
			break;
		}
		else {
			if (!FindWindow(_T("Pageant"), _T("Pageant")) && !(co_await GetProcessOutput(_T("gpgconf --launch gpg-agent")))) {
				co_await queue;
				w.forceClose(to_hstring("Failed to start gpg-agent. Exiting."));
				break;
			}
		}

		// Read svc port and cookie.
		{
			auto agent_path = co_await GetProcessOutput(_T("gpgconf --list-dir agent-socket"));
			if (!agent_path) {
				co_await 1s;
				continue;
			}
			auto file = co_await StorageFile::GetFileFromPathAsync(
				to_hstring(rtrim(std::string_view((char*)agent_path.data(), agent_path.Length())))
			);
			auto iBuf = co_await FileIO::ReadBufferAsync(file);
			array_view buf(iBuf.data(), iBuf.data() + iBuf.Length());
			auto nlinePos = std::find(buf.begin(), buf.end(), '\n');
			if (buf.end() - nlinePos <= 16) {
				co_await 1s;
				continue;
			}
			svc.assign(buf.begin(), nlinePos);
			std::copy_n(nlinePos + 1, 16, cookie);
		}

		// Monitor the socket.
		Sockets::StreamSocket gpgSocket;
		try {
			gpgSocket.Control().KeepAlive(true);
			co_await gpgSocket.ConnectAsync(HostName(L"localhost"), to_hstring(svc));

			Buffer buf{ 4096 };
			std::copy_n(cookie, 16, buf.data());
			buf.Length(16);

			co_await gpgSocket.OutputStream().WriteAsync(buf);
			while (1) {
				co_await gpgSocket.InputStream().ReadAsync(buf, buf.Capacity(), InputStreamOptions::Partial);
			}
		}
		catch (...)
		{
			continue;
		}
	}
	co_return;
}

DispatcherQueueController CreateDispatcherQueueController()
{
	DispatcherQueueOptions options
	{
		sizeof(DispatcherQueueOptions),
		DQTYPE_THREAD_CURRENT,
		DQTAT_COM_STA
	};

	ABI::Windows::System::IDispatcherQueueController* ptr{};
	check_hresult(CreateDispatcherQueueController(options, &ptr));
	return { ptr, take_ownership_from_abi };
}

int WINAPI wWinMain(_In_ HINSTANCE, _In_opt_ HINSTANCE, _In_ PWSTR, _In_ int)
{
	HANDLE hAppMutex = nullptr;
	MSG msg;
	int retCode = 0;

	// Single instance of application per session.
	if ((hAppMutex = CreateMutex(nullptr, TRUE, _T("ssh-gpg-bridge-MUTEX"))) == nullptr ||
		GetLastError() == ERROR_ALREADY_EXISTS) {
		winrt::hstring text = __MODULENAME + _T(":\n  ") +
			L"Another instance is already running.\n\nSet SSH_AUTH_SOCK to " + to_hstring(gPipeName).data();
		MessageBoxW(nullptr, text.data(), L"Error", MB_OK | MB_ICONERROR | MB_TOPMOST);

		return -1;
	}

	try {
		auto trayWnd = TrayWindow();
		auto controller{ CreateDispatcherQueueController() };
		auto monitorAgent{ KeepAgentLive(trayWnd, controller.DispatcherQueue()) };
		PipeServer server(gPipeName);
		if (!server.Start()) {
			throw std::runtime_error("Failed to start Named pipeserver.");
		}
		auto onExit = concurrency::create_task([&]() {
			auto eStatus = server.Wait();
			if (!eStatus) {
				trayWnd.forceClose(eStatus.message());
			}

			return;
			});

		BOOL bRet;
		while ((bRet = GetMessage(&msg, NULL, 0, 0)) != 0)
		{
			if (bRet == -1)
			{
				throw_last_error();
			}
			else
			{
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}
		retCode = (int)msg.wParam;

		monitorAgent.Cancel();
		server.Stop();
		onExit.get();
	}
	catch (hresult_error& e) {
		while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE));
		retCode = 2;
		MessageBoxW(nullptr, e.message().data(), L"Exception", MB_OK | MB_ICONERROR | MB_TOPMOST);
	}
	catch (std::exception& e) {
		while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE));
		retCode = 2;
		MessageBoxA(nullptr, e.what(), "Exception", MB_OK | MB_ICONERROR | MB_TOPMOST);
	}

	ReleaseMutex(hAppMutex);
	return retCode;
}
