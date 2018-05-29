#include "threading.hpp"

#include <cassert>
#include <cinttypes>
#include <cstring> // memset
#include <functional>
#include <memory>

#if (defined(WIN32))
	#include <windows.h>
#else
	#if defined(__USE_GNU)
		#include <sys/prctl.h>
	#endif
	// #include <sched.h>
	#include <unistd.h> // syscall
	#include <sys/syscall.h> // SYS_*
#endif




#if (!defined(WIN32))
// no glibc wrapper for this
static int get_tid() { return (syscall(SYS_gettid)); }

// requires at least a 2.6 kernel to access the file /proc/<pid>/task/<tid>/status
static threading::linux_thread_state get_linux_thread_state(int tid) {
	char file_name[64];
	char state_str[64];
	char flags_str[64];
	char trs_line[1024];

	snprintf(file_name, 64, "/proc/%d/task/%d/status", getpid(), tid);

	FILE* file = fopen(file_name, "r");

	if (file == nullptr)
		return threading::LTS_UNKNOWN;

	fgets(trs_line, sizeof(trs_line), file); // first line is not needed
	fgets(trs_line, sizeof(trs_line), file); // second line contains thread running state
	fclose(file);
	sscanf(state_str, "State: %s", flags_str);

	switch (flags_str[0]) {
		case 'R': return threading::LTS_RUNNING;
		case 'S': return threading::LTS_SLEEP;
		case 'D': return threading::LTS_DISK_SLEEP;
		case 'T': return threading::LTS_STOPPED;
		case 'W': return threading::LTS_PAGING;
		case 'Z': return threading::LTS_ZOMBIE;
	}

	return threading::LTS_UNKNOWN;
}

static void thread_sigusr1_handler(int signum, siginfo_t* info, void* ctxt) {
	(void) signum;
	(void) info;
	(void) ctxt;

	int err = 0;

	// fill in ucontext_t structure before locking, allows stack-walking
	if ((err = getcontext(&(threading::thread_ctrls->ucontext))) != 0) {
		printf("[%s] error \"%s\" getting thread context within suspend signal handler", __func__, strerror(err));
		return;
	}

	// assert(threading::thread_ctrls->suspend_mutex.locked());
	threading::thread_ctrls->is_running.store(false);

	{
		threading::thread_ctrls->suspend_mutex.lock();
		threading::thread_ctrls->is_running.store(true);
		threading::thread_ctrls->suspend_mutex.unlock();
	}
}

static bool set_thread_signal_handler() {
	int err = 0;

	sigset_t sig_set;
	sigemptyset(&sig_set);
	sigaddset(&sig_set, SIGUSR1);

	if ((err = pthread_sigmask(SIG_UNBLOCK, &sig_set, nullptr)) != 0) {
		printf("[%s] error \"%s\" while setting new pthread's signal mask", __func__, strerror(err));
		return false;
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof(struct sigaction));

	sa.sa_sigaction = thread_sigusr1_handler;
	sa.sa_flags |= SA_SIGINFO;

	return (sigaction(SIGUSR1, &sa, nullptr) == 0);
}
#endif




namespace threading {
	thread_local std::shared_ptr<threading::thread_controls> thread_ctrls;

	native_thread_handle get_current_thread_handle() {
		#if (defined(WIN32))
		// get_current_thread_handle() just returns a pseudo handle
		// we need to translate this to an absolute handle valid in
		// our watchdog thread
		native_thread_handle thread_handle;
		::DuplicateHandle(::GetCurrentProcess(), ::get_current_thread_handle(), ::GetCurrentProcess(), &thread_handle, 0, TRUE, DUPLICATE_SAME_ACCESS);
		return thread_handle;
		#else
		return pthread_self();
		#endif
	}

	native_thread_id get_current_thread_id() {
		#if (defined(WIN32))
		return ::get_current_thread_id();
		#else
		return pthread_self();
		#endif
	}




	thread_controls::thread_controls() {
		#if (!defined(WIN32))
		memset(&ucontext, 0, sizeof(ucontext_t));
		#endif
	}

	suspend_result thread_controls::suspend() {
		// return an error if the running flag is false.
		if (!is_running.load())
			return threading::THREADERR_NOT_RUNNING;

		suspend_mutex.lock();

		// send SIGUSR1 to thread to trigger its handler
		if (pthread_kill(handle, SIGUSR1) != 0)
			return threading::THREADERR_MISC;

		// need some kind of guarantee that the stalled thread is suspended before returing, spinwait
		// (could be avoided by creating *another* thread inside suspended_stacktrace itself to check
		// that the stalled thread has been suspended and perform the trace there)
		linux_thread_state tstate;

		// 40 attempts * 0.025s = 1 sec max.
		constexpr int MAX_ATTEMPTS = 40;
		for (int a = 0; a < MAX_ATTEMPTS; a++) {
			if ((tstate = get_linux_thread_state(thread_id)) == LTS_SLEEP)
				break;
		}

		return threading::THREADERR_NONE;
	}

	suspend_result thread_controls::resume() {
		suspend_mutex.unlock();
		return threading::THREADERR_NONE;
	}




	void set_current_thread_controls() {
		#if (!defined(WIN32))
		assert(thread_ctrls.get() == nullptr);

		// installing new thread_controls object, also install signal handler
		if (!set_thread_signal_handler())
			return;

		{
			thread_ctrls.reset(new threading::thread_controls());

			thread_ctrls->handle = get_current_thread_handle();
			thread_ctrls->thread_id = get_tid();
			thread_ctrls->is_running.store(true);
		}
		#endif
	}

	#if (!defined(WIN32))
	// entry point for wrapped pthread; allows registering signal handlers
	// specific to that thread and, enables suspend/resume functionality
	void thread_start(
		std::function<void()> task_func,
		std::shared_ptr<thread_controls>* out_ctrls,
		thread_controls* tmp_ctrls
	) {
		// install the SIGUSR1 handler
		set_current_thread_controls();

		assert(thread_ctrls.get() != nullptr);

		if (out_ctrls != nullptr)
			*out_ctrls = thread_ctrls;

		{
			// lock the thread object so that users can't suspend/resume yet
			tmp_ctrls->suspend_mutex.lock();

			// fully initialized, notify the condition variable
			// thread's parent will unblock in whatever function
			// created this thread
			tmp_ctrls->initialize_cond.notify_all();

			// thread should be ready to run its task now
			tmp_ctrls->suspend_mutex.unlock();
		}

		task_func();

		// change the thread's running state to false
		thread_ctrls->suspend_mutex.lock();
		thread_ctrls->is_running.store(false);
		thread_ctrls->suspend_mutex.unlock();
	}
	#endif

	void set_thread_name(const char* name) {
		#if (defined(__USE_GNU) && !defined(WIN32))
		// alternative: pthread_setname_np(pthread_self(), name);
		prctl(PR_SET_NAME, name, 0, 0, 0);
		#elif _MSC_VER
		constexpr DWORD MS_VC_EXCEPTION = 0x406D1388;

		#pragma pack(push, 8)
		struct THREADNAME_INFO {
			DWORD dw_type;      // must be 0x1000
			LPCSTR sz_name;     // pointer to name (in user address-space)
			DWORD dw_thread_id; // thread ID (-1 := caller thread)
			DWORD dw_flags;     // reserved for future use, must be zero
		};
		#pragma pack(pop)

		THREADNAME_INFO tn_info;
		tn_info.dw_type = 0x1000;
		tn_info.sz_name = name;
		tn_info.dw_thread_id = (DWORD) -1;
		tn_info.dw_flags = 0;

		__try {
			RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*) &tn_info);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}
		#endif
	}




	std::shared_ptr<thread_controls> get_current_thread_controls() {
		// if there is no object registered, need to return an "empty" shared_ptr
		if (thread_ctrls.get() == nullptr)
			return std::shared_ptr<thread_controls>();

		return thread_ctrls;
	}

	std::thread create_controlled_thread(std::function<void()> task_func, std::shared_ptr<threading::thread_controls>* pp_ctrls) {
		#if (!defined(WIN32))
		// only used as locking mechanism, not installed by thread
		threading::thread_controls tmp_ctrls;

		std::unique_lock<std::mutex> lock(tmp_ctrls.suspend_mutex);
		std::thread local_thread(std::bind(threading::thread_start, task_func, pp_ctrls, &tmp_ctrls));

		// wait so that we know the thread is running and fully initialized before returning
		tmp_ctrls.initialize_cond.wait(lock);
		#else
		std::thread local_thread(task_func);
		#endif

		return local_thread;
	}
}

