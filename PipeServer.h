#pragma once
#include <Windows.h>
#include <ppl.h>
#include <ppltasks.h>
#include <agents.h>
#include <atomic>
#include <exception>
#include <vector>

namespace _detail {
	const ULONG_PTR PUTTY_IPC_MAGIC = 0x804e50ba;

	const std::vector<BYTE> FAILURE_RESPONSE{ '\0', '\0', '\0', '\1', '\5' };

	const UINT AGENT_MAX_MESSAGE_LENGTH = 8192;

	struct PageantHandler {
		PageantHandler();

		static HWND GetPageantWindow();

		std::vector<BYTE> sendPageant(BYTE* msg, DWORD size);

		~PageantHandler();

	private:
		PTOKEN_USER pUser = nullptr;
		PSECURITY_DESCRIPTOR pSd = nullptr;
		SECURITY_ATTRIBUTES sa{};
		std::atomic_int64_t counter = 0;
	};
}

class PipeServer : _detail::PageantHandler {
	enum class OpCode {
		OP_READ,
		OP_WRITE,
		OP_CONNECT,
	};

	struct IocpContext : OVERLAPPED {
		OpCode op;
		concurrency::event done;
		DWORD nbytesTransferred;
		DWORD err;
	};
public:
	enum class ExitCode {
		SUCCESS = 0,
		ERROR_PIPE_IN_USE,
		ERROR_RESOURCE_UNAVAILABLE,
		ERROR_SERVER_NOT_STARTED,
		ERROR_PROCESSING,
	};
	class ExitStatus {
		ExitCode c;
		winrt::hstring msg;

		ExitStatus(ExitCode code) : c(code) {
			auto s = to_string(code);
			msg = winrt::hstring(s, (uint32_t)std::wcslen(s));
		}

		ExitStatus(ExitCode code, winrt::hstring msg) : c(code), msg(msg) {}

		static constexpr const wchar_t* to_string(ExitCode c) {
			switch (c) {
			case ExitCode::SUCCESS:
				return L"Server exited without error";
				break;
			case ExitCode::ERROR_PIPE_IN_USE:
				return L"Pipe is already in use by another process";
			case ExitCode::ERROR_RESOURCE_UNAVAILABLE:
				return L"Resource unavailable";
			case ExitCode::ERROR_SERVER_NOT_STARTED:
				return L"Server has not been started";
			case ExitCode::ERROR_PROCESSING:
				return L"Internal error in processing loop";
			default:
				_ASSERT_EXPR(false, "Unreachable code path");
				return 0;
			}

		}

		friend class PipeServer;

	public:
		ExitStatus() : ExitStatus(ExitCode::SUCCESS) {}

		wchar_t const* message() const;

		ExitCode code() const;

		operator bool() const {
			return c == ExitCode::SUCCESS;
		}
	};

	class PipeInstance {
		HANDLE h;
		std::shared_ptr<concurrency::event> eClose;

		PipeInstance(HANDLE h, const std::shared_ptr<concurrency::event>& eClose);

		friend class PipeServer;
	public:
		PipeInstance(const PipeInstance&) = delete;

		std::pair<DWORD, std::optional<winrt::hresult_error>> Read(BYTE* buf, DWORD nbytesToRead);

		std::pair<DWORD, std::optional<winrt::hresult_error>> Write(BYTE* buf, DWORD nbytesToWrite);

		void Close();

		~PipeInstance();
	};

	PipeServer(LPCTSTR pipeName);

	PipeServer(const PipeServer&) = delete;

	bool Start();

	void Stop();

	// Blocking wait till exit.
	ExitStatus Wait();

	~PipeServer();

private:
	LPCTSTR m_pipeName;
	HANDLE m_iocp;

	concurrency::reader_writer_lock runLock;

	concurrency::overwrite_buffer<ExitStatus> status;

	std::shared_ptr<concurrency::event> eClose;
	concurrency::task<ExitStatus> waiter;
	concurrency::task<void> processor;
	concurrency::task_group tasks;

	std::shared_ptr<PipeServer::PipeInstance> Accept();

	bool IsClosed();

	template<typename ... Args>
	void Stop(Args&& ... args);

	concurrency::task<void> Process();
};
