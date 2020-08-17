#include "pch.h"
#include "PipeServer.h"
#include <tchar.h>

namespace _detail {
	PageantHandler::PageantHandler() {
		HANDLE hToken;
		DWORD tkLength = 0;
		winrt::check_bool(OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken));
		GetTokenInformation(hToken, TokenUser, (LPVOID)pUser, 0, &tkLength);
		pUser = (PTOKEN_USER)LocalAlloc(LPTR, tkLength);
		WINRT_ASSERT(pUser != nullptr);
		winrt::check_bool(GetTokenInformation(hToken, TokenUser, (LPVOID)pUser, tkLength, &tkLength));
		pSd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
		WINRT_ASSERT(pSd != nullptr);
		winrt::check_bool(InitializeSecurityDescriptor(pSd, SECURITY_DESCRIPTOR_REVISION));
		winrt::check_bool(SetSecurityDescriptorOwner(pSd, pUser->User.Sid, false));
		sa.nLength = sizeof(sa);
		sa.lpSecurityDescriptor = pSd;
		sa.bInheritHandle = true;
	}

	HWND PageantHandler::GetPageantWindow() {
		HWND hwnd = nullptr;
		for (auto i = 0; i < 20; i++) {
			hwnd = FindWindow(_T("Pageant"), _T("Pageant"));
			if (!hwnd) {
				concurrency::wait(500);
				continue;
			}
		}
		return hwnd;
	}

	std::vector<BYTE> PageantHandler::sendPageant(BYTE* msg, DWORD size) {
		std::vector<unsigned char> result = FAILURE_RESPONSE;
		auto n = counter.fetch_add(1);
		std::string name = "Pagent-bridge" + std::to_string(n);
		HANDLE hMmap = CreateFileMappingA(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, AGENT_MAX_MESSAGE_LENGTH, name.c_str());
		if (hMmap == nullptr) {
			return result;
		}
		auto mem = (BYTE*)MapViewOfFile(hMmap, FILE_MAP_WRITE, 0, 0, 0);
		if (mem == nullptr) {
			CloseHandle(hMmap);
			return result;
		}
		std::copy(msg, msg + size, mem);
		COPYDATASTRUCT cds{};
		cds.dwData = PUTTY_IPC_MAGIC;
		cds.cbData = (DWORD)(name.length() + 1);
		cds.lpData = (LPVOID)name.c_str();
		auto hwnd = GetPageantWindow();
		concurrency::Context::Oversubscribe(true);
		if (hwnd && SendMessage(hwnd, WM_COPYDATA, 0, (LPARAM)&cds)) {
			uint32_t len = mem[0] << 24 | mem[1] << 16 | mem[2] << 8 | mem[3];
			len += 4;
			if (len <= AGENT_MAX_MESSAGE_LENGTH) {
				result.assign(mem, mem + len);
			}
		}
		concurrency::Context::Oversubscribe(false);
		UnmapViewOfFile(mem);
		CloseHandle(hMmap);
		return result;
	}

	PageantHandler::~PageantHandler() {
		LocalFree(pUser);
		LocalFree(pSd);
	}
}

inline PipeServer::PipeInstance::PipeInstance(HANDLE h, const std::shared_ptr<concurrency::event>& eClose) : h(h), eClose(eClose) {}

std::pair<DWORD, std::optional<winrt::hresult_error>> PipeServer::PipeInstance::Read(BYTE* buf, DWORD nbytesToRead) {
	auto ret = std::make_pair<DWORD, std::optional<winrt::hresult_error>>(0, std::nullopt);
	IocpContext ctx{};
	ctx.op = OpCode::OP_READ;
	concurrency::event* events[2] = { &ctx.done, eClose.get() };
	for (;;) {
		auto bSuccess = ReadFile(h, buf + ret.first, nbytesToRead - ret.first, nullptr, (LPOVERLAPPED)&ctx);
		if (!bSuccess) {
			auto e = GetLastError();
			if (e != ERROR_IO_PENDING) {
				ret.second = winrt::hresult_error(HRESULT_FROM_WIN32(e));
				break;
			}
		}
		auto nIdx = concurrency::event::wait_for_multiple(events, 2, false);
		if (nIdx != 0) {
			CancelIoEx(h, (LPOVERLAPPED)&ctx);
			ctx.done.wait();
		}
		ret.first += ctx.nbytesTransferred;
		if (ctx.err) {
			ret.second = winrt::hresult_error(HRESULT_FROM_WIN32(ctx.err));
			break;
		}
		else if (ret.first == nbytesToRead) {
			break;
		}
		ctx.done.reset();
	}

	return ret;
}

std::pair<DWORD, std::optional<winrt::hresult_error>> PipeServer::PipeInstance::Write(BYTE* buf, DWORD nbytesToWrite) {
	auto ret = std::make_pair<DWORD, std::optional<winrt::hresult_error>>(0, std::nullopt);
	IocpContext ctx{};
	ctx.op = OpCode::OP_WRITE;
	concurrency::event* events[2] = { &ctx.done, eClose.get() };
	for (;;) {
		auto bSuccess = WriteFile(h, buf + ret.first, nbytesToWrite - ret.first, nullptr, static_cast<LPOVERLAPPED>(&ctx));
		if (!bSuccess) {
			auto e = GetLastError();
			if (e != ERROR_IO_PENDING) {
				ret.second = winrt::hresult_error(HRESULT_FROM_WIN32(e));
				break;
			}
		}
		auto nIdx = concurrency::event::wait_for_multiple(events, 2, false);
		if (nIdx != 0) {
			CancelIoEx(h, (LPOVERLAPPED)&ctx);
			ctx.done.wait();
		}
		ret.first += ctx.nbytesTransferred;
		if (ctx.err) {
			ret.second = winrt::hresult_error(HRESULT_FROM_WIN32(ctx.err));
			break;
		}
		else if (ret.first == nbytesToWrite) {
			break;
		}
		ctx.done.reset();
	}

	return ret;
}

void PipeServer::PipeInstance::Close() {
	if (h != INVALID_HANDLE_VALUE) {
		DisconnectNamedPipe(h);
		CloseHandle(h);
		h = INVALID_HANDLE_VALUE;
	}
}

inline PipeServer::PipeInstance::~PipeInstance() {
	Close();
}

PipeServer::PipeServer(LPCTSTR pipeName) :
	m_pipeName(pipeName),
	eClose(std::make_shared<concurrency::event>()),
	waiter(concurrency::task_from_result(PipeServer::ExitStatus(ExitCode::ERROR_SERVER_NOT_STARTED)))
{
	m_iocp = winrt::check_pointer(CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0));
	concurrency::send(status, PipeServer::ExitStatus(ExitCode::SUCCESS));
}

bool PipeServer::Start() {
	concurrency::reader_writer_lock::scoped_lock exL(runLock);
	if (!waiter.is_done()) {
		return false;
	}

	eClose->reset();
	processor = Process();
	tasks.run([&]() {
		for (;;) {
			if (IsClosed()) {
				break;
			}
			auto pInst = Accept();
			if (pInst) {
				tasks.run([pInst, this]() {
					BYTE buf[_detail::AGENT_MAX_MESSAGE_LENGTH];
					for (;;) {
						auto ret = pInst->Read(buf, 4);
						if (ret.second) {
							break;
						}
						uint32_t len = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
						if (len > _detail::AGENT_MAX_MESSAGE_LENGTH - 4) {
							break;
						}
						ret = pInst->Read(buf + 4, len);
						if (ret.second) {
							break;
						}
						auto res = sendPageant(buf, len + 4);
						ret = pInst->Write(res.data(), (DWORD)res.size());
						if (ret.second) {
							break;
						}
					}
					});
			}
		}
		});
	waiter = concurrency::create_task([&] {
		bool hasException = false;
		eClose->wait();
		// wait for all tasks to end.
		try {
			tasks.wait();
		}
		catch (...) { hasException = true; }

		// post special packet to stop processor task and wait.
		// Important: we do this after all tasks have been finished since completion loop signals the tasks(see ctx.done).
		PostQueuedCompletionStatus(m_iocp, 0, 0, 0);
		try {
			processor.wait();
		}
		catch (...) { hasException = true; }

		if (hasException) {
			concurrency::send(status,
				ExitStatus(ExitCode::ERROR_PROCESSING,
					winrt::to_hstring("Internal exception in tasks while waiting")));
		}
		return concurrency::receive(status);
		});

	return true;
}

void PipeServer::Stop() {
	concurrency::reader_writer_lock::scoped_lock_read rL(runLock);
	eClose->set();
}

PipeServer::ExitStatus PipeServer::Wait() {
	concurrency::reader_writer_lock::scoped_lock_read rL(runLock);
	return waiter.get();
}

PipeServer::~PipeServer() {
	try {
		Stop();
		Wait();
	}
	catch (...) {}
	CloseHandle(m_iocp);
}

inline bool PipeServer::IsClosed() {
	return !eClose->wait(0);
}

std::shared_ptr<PipeServer::PipeInstance> PipeServer::Accept() {
	auto hPipe = CreateNamedPipe(m_pipeName,
		PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		1,
		_detail::AGENT_MAX_MESSAGE_LENGTH,
		0,
		nullptr);
	if (hPipe == INVALID_HANDLE_VALUE) {
		return nullptr;
	}
	if (GetLastError() == ERROR_ACCESS_DENIED) {
		Stop(ExitCode::ERROR_PIPE_IN_USE);
		return nullptr;
	}
	if (!CreateIoCompletionPort(hPipe, m_iocp, (ULONG_PTR)hPipe, 0)) {
		CloseHandle(hPipe);
		return nullptr;
	}
	IocpContext ctx{};
	ctx.op = OpCode::OP_CONNECT;
	auto c = ConnectNamedPipe(hPipe, static_cast<LPOVERLAPPED>(&ctx));
	auto e = GetLastError();
	if (c || (e != ERROR_IO_PENDING && e != ERROR_PIPE_CONNECTED)) {
		CloseHandle(hPipe);
		return nullptr;
	}
	if (e == ERROR_IO_PENDING) {
		concurrency::event* events[2] = { &ctx.done, eClose.get() };
		auto nIdx = concurrency::event::wait_for_multiple(events, 2, false);
		if (nIdx != 0) {
			CancelIoEx(hPipe, (LPOVERLAPPED)&ctx);
			ctx.done.wait();
		}
		if (ctx.err) {
			CloseHandle(hPipe);
			return nullptr;
		}
	}
	return std::shared_ptr<PipeInstance>(new PipeInstance(hPipe, eClose));
}

template<typename ... Args>
inline void PipeServer::Stop(Args&& ... args) {
	concurrency::reader_writer_lock::scoped_lock_read rL(runLock);
	concurrency::send(status, ExitStatus(std::forward<Args>(args)...));
	eClose->set();
}

concurrency::task<void> PipeServer::Process() {
	return concurrency::create_task([&]() {
		DWORD nbytesTransferred;
		ULONG_PTR completionKey;
		IocpContext* ctx = nullptr;
		DWORD err = 0;
		concurrency::Context::Oversubscribe(true);
		for (;;) {
			auto bSuccess = GetQueuedCompletionStatus(m_iocp, &nbytesTransferred, &completionKey, (LPOVERLAPPED*)&ctx, INFINITE);
			err = GetLastError();
			if (!bSuccess && !ctx) {
				break;
			}
			if (0 == nbytesTransferred && 0 == completionKey && 0 == ctx)
			{
				// Special packet to stop processing.
				break;
			}
			if (ctx) {
				switch (ctx->op) {
				case OpCode::OP_CONNECT:
					ctx->err = err;
					ctx->done.set();
					break;
				case OpCode::OP_READ:
					ctx->nbytesTransferred = nbytesTransferred;
					if (err == ERROR_MORE_DATA) {
						ctx->err = 0;
					}
					else {
						ctx->err = err;
					}
					ctx->done.set();
					break;
				case OpCode::OP_WRITE:
					ctx->nbytesTransferred = nbytesTransferred;
					ctx->err = err;
					ctx->done.set();
					break;
				default:
					_ASSERT_EXPR(FALSE, "ctx is potentially uninitialized");
					break;
				}
			}
		}
		concurrency::Context::Oversubscribe(false);

		// signal stop condition with error.
		if (err) {
			Stop(ExitCode::ERROR_PROCESSING,
				winrt::to_hstring("GetQueuedCompletionStatus failed with error: ") + winrt::hresult_error(HRESULT_FROM_WIN32(err)).message());
		}
		});
}

PipeServer::ExitCode PipeServer::ExitStatus::code() const
{
	return c;
}

wchar_t const* PipeServer::ExitStatus::message() const
{
	return msg.c_str();
}
