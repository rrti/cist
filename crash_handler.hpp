#ifndef CIST_CRASH_HANDLER_HDR
#define CIST_CRASH_HANDLER_HDR

#include "threading.hpp"

namespace crash_handler {
	void install();
	void remove();

	void stacktrace(threading::native_thread_handle thread_handle, const char* thread_name);
	void prepare_stacktrace();
	void cleanup_stacktrace();
	
#ifndef WIN32
	// needed to pass the ucontext_t in thread_controls to thread_unwind (and hence to libunwind)
	void suspended_stacktrace(threading::thread_controls* ctls, const char* thread_name);
#else
	bool init_image_hlp_dll();
#endif

	void output_stacktrace();
}

#endif

