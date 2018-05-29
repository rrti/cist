#include <cstdint>
#include <cstring>

#include <new> // set_new_handler
#include <vector>

#include <windows.h>
#include <process.h>
#include <imagehlp.h>
#include <signal.h>

#include "crash_handler.hpp"
#include "threading.hpp"


#ifdef _MSC_VER
#define SYMLENGTH 4096
#endif

#define MAX_FRAMES 1024
#define LOG_RAW_LINE(fmt, ...) do {         \
	fprintf(stderr, fmt, ##__VA_ARGS__);    \
	fprintf(stderr, "\n"              );    \
	fprintf(log_file, fmt, ##__VA_ARGS__);  \
	fprintf(log_file, "\n"              );  \
} while (false)


namespace crash_handler {
	// NOTE:
	//   printing while a thread is suspended still performs allocations,
	//   which are highly likely to cause deadlocks unless we buffer all
	//   relevant information and only print it after resuming
	struct t_stacktrace_line {
		int type;

		DWORD dw_mod_addr;
		#ifdef _MSC_VER
		DWORD line_num;
		DWORD64 pc_offset;

		char file_name[MAX_PATH];
		char sym_name[SYMLENGTH];
		#endif
		char mod_name[MAX_PATH];
	};

	static std::vector<t_stacktrace_line> stacktrace_lines;


	static CRITICAL_SECTION stack_lock;

	static bool imghlp_dll_inited = false;


	static const char* ADDR_FMTS[2] = {
		"\t(%d) %s:%u %s [0x%08llX]",
		"\t(%d) %s [0x%08lX]"
	};
	static const char* ERR_FMT =
		"Process has crashed:\n  %s.\n\n"
		"A stacktrace has been written to:\n  %s";

	static FILE* log_file = nullptr;




	static const char* exception_name(DWORD exception_code) {
		switch (exception_code) {
			case EXCEPTION_ACCESS_VIOLATION:         return "Access violation";
			case EXCEPTION_DATATYPE_MISALIGNMENT:    return "Datatype misalignment";
			case EXCEPTION_BREAKPOINT:               return "Breakpoint";
			case EXCEPTION_SINGLE_STEP:              return "Single step";
			case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "Array bounds exceeded";
			case EXCEPTION_FLT_DENORMAL_OPERAND:     return "Float denormal operand";
			case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "Float divide by zero";
			case EXCEPTION_FLT_INEXACT_RESULT:       return "Float inexact result";
			case EXCEPTION_FLT_INVALID_OPERATION:    return "Float invalid operation";
			case EXCEPTION_FLT_OVERFLOW:             return "Float overflow";
			case EXCEPTION_FLT_STACK_CHECK:          return "Float stack check";
			case EXCEPTION_FLT_UNDERFLOW:            return "Float underflow";
			case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "Integer divide by zero";
			case EXCEPTION_INT_OVERFLOW:             return "Integer overflow";
			case EXCEPTION_PRIV_INSTRUCTION:         return "Privileged instruction";
			case EXCEPTION_IN_PAGE_ERROR:            return "In page error";
			case EXCEPTION_ILLEGAL_INSTRUCTION:      return "Illegal instruction";
			case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "Noncontinuable exception";
			case EXCEPTION_STACK_OVERFLOW:           return "Stack overflow";
			case EXCEPTION_INVALID_DISPOSITION:      return "Invalid disposition";
			case EXCEPTION_GUARD_PAGE:               return "Guard page";
			case EXCEPTION_INVALID_HANDLE:           return "Invalid handle";
		}

		return "Unknown exception";
	}



	bool init_imghlp_dll() {
		if (imghlp_dll_inited)
			return true;

		char user_search_path[8];

		user_search_path[0] = '.';
		user_search_path[1] = '\0';

		// insert IMAGEHLP.DLL into process
		if (SymInitialize(GetCurrentProcess(), user_search_path, TRUE)) {
			SymSetOptions(SYMOPT_LOAD_LINES);
			return (imghlp_dll_inited = true);
		}

		SymCleanup(GetCurrentProcess());
		return false;
	}



	// callback for SymEnumerateModules
	#if _MSC_VER >= 1500
	static BOOL CALLBACK enum_modules(PCSTR mod_name, ULONG dll_base, PVOID user_ctx) {
		LOG_RAW_LINE("0x%08lx\t%s", dll_base, mod_name);
		return TRUE;
	}
	#else
	static BOOL CALLBACK enum_modules(LPSTR mod_name, DWORD dll_base, PVOID user_ctx) {
		LOG_RAW_LINE("0x%08lx\t%s", dll_base, mod_name);
		return TRUE;
	}
	#endif



	inline static void stacktrace_inline(const char* thread_name, LPEXCEPTION_POINTERS e, HANDLE thread_handle = INVALID_HANDLE_VALUE) {
		STACKFRAME64 frame;
		CONTEXT context;
		HANDLE thread = thread_handle;

		const HANDLE cur_process = GetCurrentProcess();
		const HANDLE cur_thread = GetCurrentThread();

		DWORD64  dw_mod_base = 0;
		DWORD64  dw_mod_addr = 0;
		DWORD   machine_type = 0;

		const bool wd_thread = (thread_handle != INVALID_HANDLE_VALUE);

		int num_frames = 0;
		char mod_name[MAX_PATH];

		const void* initial_pc;
		const void* initial_sp;
		const void* initial_fp;

		ZeroMemory(&frame, sizeof(frame));
		ZeroMemory(&context, sizeof(CONTEXT));
		memset(mod_name, 0, sizeof(mod_name));
		memset(stacktrace_lines.data(), 0, stacktrace_lines.size() * sizeof(t_stacktrace_line));
		assert(log_file != nullptr);

		// NOTE: this line is parsed by the stacktrans script
		if (thread_name != nullptr) {
			LOG_RAW_LINE("Stacktrace (thread %s):", thread_name);
		} else {
			LOG_RAW_LINE("Stacktrace:");
		}

		if (e != nullptr) {
			// reached when an exception occurs
			context = *e->ContextRecord;
			thread = cur_thread;
		} else if (wd_thread) {
			// suspend thread; it might be in an infinite loop
			context.ContextFlags = CONTEXT_FULL;

			// assert(!CompareObjectHandles(thread_handle, cur_thread));

			if (thread_handle == cur_thread) {
				// should never happen
				LOG_RAW_LINE("\t[attempted to suspend hang-detector thread]");
				return;
			}

			if (SuspendThread(thread_handle) == -1) {
				LOG_RAW_LINE("\t[failed to suspend thread]");
				return;
			}

			if (GetThreadContext(thread_handle, &context) == 0) {
				ResumeThread(thread_handle);
				LOG_RAW_LINE("\t[failed to get thread context]");
				return;
			}
		} else {
			// fallback; get context directly from CPU-registers
	#ifdef _M_IX86
			context.ContextFlags = CONTEXT_CONTROL;

	#ifdef _MSC_VER
			// MSVC
			__asm {
				call func;
				func: pop eax;
				mov [context.Eip], eax;
				mov [context.Ebp], ebp;
				mov [context.Esp], esp;
			}
	#else
			// GCC
			DWORD eip, esp, ebp;
			__asm__ __volatile__ ("call func; func: pop %%eax; mov %%eax, %0;" : "=m" (eip) : : "%eax" );
			__asm__ __volatile__ ("mov %%ebp, %0;" : "=m" (ebp) : : );
			__asm__ __volatile__ ("mov %%esp, %0;" : "=m" (esp) : : );

			context.Eip = eip;
			context.Ebp = ebp;
			context.Esp = esp;
	#endif

	#else
			RtlCaptureContext(&context);
	#endif
			thread = cur_thread;
		}


		{
			// retrieve program-counter and starting stack-frame address
			#ifdef _M_IX86
			machine_type = IMAGE_FILE_MACHINE_I386;
			frame.AddrPC.Offset = context.Eip;
			frame.AddrStack.Offset = context.Esp;
			frame.AddrFrame.Offset = context.Ebp;
			#elif _M_X64
			machine_type = IMAGE_FILE_MACHINE_AMD64;
			frame.AddrPC.Offset = context.Rip;
			frame.AddrStack.Offset = context.Rsp;
			frame.AddrFrame.Offset = context.Rsp;
			#else
			#error "CrashHandler: Unsupported platform"
			#endif

			frame.AddrPC.Mode = AddrModeFlat;
			frame.AddrStack.Mode = AddrModeFlat;
			frame.AddrFrame.Mode = AddrModeFlat;

			initial_pc = reinterpret_cast<const void*>(frame.AddrPC.Offset);
			initial_sp = reinterpret_cast<const void*>(frame.AddrStack.Offset);
			initial_fp = reinterpret_cast<const void*>(frame.AddrFrame.Offset);
		}


		while (StackWalk64(machine_type, cur_process, thread, &frame, &context, nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) {
			#if 0
			if (frame.AddrFrame.Offset == 0)
				break;
			#endif
			if (num_frames >= MAX_FRAMES)
				break;


			if ((dw_mod_base = SymGetModuleBase64(cur_process, frame.AddrPC.Offset)) != 0) {
				GetModuleFileName((HINSTANCE) dw_mod_base, mod_name, MAX_PATH);
			} else {
				strcpy(mod_name, "Unknown");
			}


			t_stacktrace_line& stl = stacktrace_lines[num_frames];

	#ifdef _MSC_VER
			char symbuf[sizeof(SYMBOL_INFO) + SYMLENGTH];

			PSYMBOL_INFO pSym = reinterpret_cast<SYMBOL_INFO*>(symbuf);
			pSym->SizeOfStruct = sizeof(SYMBOL_INFO);
			pSym->MaxNameLen = SYMLENGTH;

			// check if we have symbols, only works on VC (mingw doesn't have a compatible file format)
			if (SymFromAddr(cur_process, frame.AddrPC.Offset, nullptr, pSym)) {
				IMAGEHLP_LINE64 line = {0};
				line.SizeOfStruct = sizeof(line);

				DWORD displacement;
				SymGetLineFromAddr64(GetCurrentProcess(), frame.AddrPC.Offset, &displacement, &line);

				stl.type = 0;
				strncpy(stl.file_name, (line.FileName != nullptr)? line.FileName : "<unknown>", MAX_PATH);
				stl.line_num = line.LineNumber;
				strncpy(stl.sym_name, pSym->Name, SYMLENGTH);
				stl.pc_offset = frame.AddrPC.Offset;
			} else
	#endif
			{
				// this is the code path taken on MinGW, and MSVC if no debugging syms are found
				// for the .exe we need the absolute address while for DLLs we need the module's
				// internal/relative address
				if (strstr(mod_name, ".exe") != nullptr) {
					dw_mod_addr = frame.AddrPC.Offset;
				} else {
					dw_mod_addr = frame.AddrPC.Offset - dw_mod_base;
				}

				stl.type = 1;
				strncpy(stl.mod_name, mod_name, MAX_PATH);
				stl.dw_mod_addr = dw_mod_addr;
			}

			++num_frames;
		}


		if (wd_thread)
			ResumeThread(thread_handle);

		// log initial context
		LOG_RAW_LINE("\t[ProgCtr=%p StackPtr=%p FramePtr=%p]", initial_pc, initial_sp, initial_fp);

		for (int i = 0; i < num_frames; ++i) {
			const t_stacktrace_line& stl = stacktrace_lines[i];

			switch (stl.type) {
				#ifdef _MSC_VER
				case 0: {
					LOG_RAW_LINE(ADDR_FMTS[stl.type], i, stl.file_name, stl.line_num, stl.sym_name, stl.pc_offset);
				} break;
				#endif
				case 1: {
					LOG_RAW_LINE(ADDR_FMTS[stl.type], i, stl.mod_name, stl.dw_mod_addr);
				} break;
				default: {
					assert(false);
				} break;
			}
		}
	}


	// internally called, lock should already be held
	static void stacktrace(const char* thread_name, LPEXCEPTION_POINTERS e, HANDLE thread_handle) {
		stacktrace_inline(thread_name, e, thread_handle);
	}

	// externally called
	void stacktrace(threading::native_thread_handle thread_handle, const char* thread_name) {
		// caller has to prepare
		// EnterCriticalSection(&stack_lock);
		stacktrace_inline(thread_name, nullptr, thread_handle);
		// caller has to cleanup
		// LeaveCriticalSection(&stack_lock);
	}



	void prepare_stacktrace() {
		EnterCriticalSection(&stack_lock);
		init_imghlp_dll();

		// sidestep any kind of hidden allocation which might cause a deadlock
		log_file = fopen("log_file.txt", "w");

		// Record list of loaded DLLs.
		LOG_RAW_LINE("DLL information:");
		SymEnumerateModules(GetCurrentProcess(), (PSYM_ENUMMODULES_CALLBACK) enum_modules, nullptr);
	}

	void cleanup_stacktrace() {
		// remove IMAGEHLP.DLL from process
		SymCleanup(GetCurrentProcess());
		img_hlp_inited = false;

		LeaveCriticalSection(&stack_lock);
	}

	void output_stacktrace() {
		prepare_stacktrace();
		stacktrace(nullptr, nullptr, INVALID_HANDLE_VALUE);
		cleanup_stacktrace();
	}



	static void new_handler() {
		output_stacktrace();
	}

	static void sigabrt_handler(int signal) {
		output_stacktrace();
	}




	/** Called by windows if an exception happens. */
	LONG CALLBACK exception_handler(LPEXCEPTION_POINTERS e) {
		// prologue; disable registered sinks (info-console, ...)
		LOG_RAW_LINE("Process has crashed.");
		prepare_stacktrace();

		const char* err_str = exception_name(e->ExceptionRecord->ExceptionCode);
		char err_buf[2048];

		LOG_RAW_LINE("Exception: %s (0x%08lx)", err_str, e->ExceptionRecord->ExceptionCode);
		LOG_RAW_LINE("Exception Address: 0x%p", (PVOID) e->ExceptionRecord->ExceptionAddress);

		// print trace inline: avoids modifying the stack which might confuse
		// StackWalk when using the context record passed to exception_handler
		stacktrace_inline(nullptr, e);
		cleanup_stacktrace();

		// only the first crash is of any real interest
		crash_handler::remove();

		// inform user about the exception
		snprintf(err_buf, sizeof(err_buf), ERR_FMT, err_str, "log_file.txt");
		LOG_RAW_LINE("%s", err_buf);

		// this seems to silently close the application
		return EXCEPTION_EXECUTE_HANDLER;

		// this triggers the microsoft "application has crashed" error dialog
		//return EXCEPTION_CONTINUE_SEARCH;

		// in practice, 100% CPU usage but no continuation of execution
		// (tested segmentation fault and division by zero)
		//return EXCEPTION_CONTINUE_EXECUTION;
	}



	void install() {
		InitializeCriticalSection(&stack_lock);

		SetUnhandledExceptionFilter(exception_handler);
		signal(SIGABRT, sigabrt_handler);
		std::set_new_handler(new_handler);

		// pre-allocate since doing so after a bad_alloc exception can fail
		// MAX_FRAMES * sizeof(t_stacktrace_line) is too big for the stack
		stacktrace_lines.resize(MAX_FRAMES);
	}

	void remove() {
		SetUnhandledExceptionFilter(nullptr);
		signal(SIGABRT, SIG_DFL);
		std::set_new_handler(nullptr);

		DeleteCriticalSection(&stack_lock);
	}
};

