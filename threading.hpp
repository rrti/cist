#ifndef CIST_THREADING_HDR
#define CIST_THREADING_HDR

#ifndef WIN32
#include <pthread.h>
#include <semaphore.h>
#include <ucontext.h>
#endif

#include <atomic>
#include <cinttypes>
#include <functional>

#include <condition_variable>
#include <mutex>
#include <thread>


namespace threading {
	class thread_controls;

	extern thread_local std::shared_ptr<threading::thread_controls> thread_ctrls;

	#ifdef WIN32
	typedef DWORD     native_thread_id;
	typedef HANDLE    native_thread_handle;
	#else
	typedef pthread_t native_thread_id;
	typedef pthread_t native_thread_handle;
	#endif

	native_thread_handle get_current_thread_handle();
	native_thread_id get_current_thread_id();

	enum suspend_result {
		THREADERR_NONE,
		THREADERR_NOT_RUNNING,
		THREADERR_MISC
	};
	enum linux_thread_state {
		LTS_RUNNING,
		LTS_SLEEP,
		LTS_DISK_SLEEP,
		LTS_STOPPED,
		LTS_PAGING,
		LTS_ZOMBIE,
		LTS_UNKNOWN
	};


	// creates a new thread whose entry-function is wrapped by some boilerplate code that allows for suspend/resume
	// suspend/resume controls are exposed via the thread_controls object that is optionally provided by the caller
	// and initialized by the thread; thread is guaranteed to be in a running and initialized state when this returns
	std::thread create_controlled_thread(std::function<void()> task_func, std::shared_ptr<threading::thread_controls>* pp_thread_ctrls = nullptr);

	std::shared_ptr<thread_controls> get_current_thread_controls();


	#ifndef WIN32
	void set_current_thread_controls();
	#else
	static void set_current_thread_controls() {}
	#endif


	// provides suspend/resume functionality for threads
	class thread_controls {
	public:
		thread_controls();

		suspend_result suspend();
		suspend_result resume();

		native_thread_handle handle{0};

		std::atomic<bool> is_running{false};
		#ifndef WIN32
		std::mutex suspend_mutex;
		std::condition_variable initialize_cond;

		ucontext_t ucontext;
		pid_t thread_id;
		#endif
	};

	bool native_thread_ids_equal(const native_thread_id a, const native_thread_id b) {
		// NB:
		//   pthread implementations may choose to define a thread ID as a structure
		//   on Linux it always seems to be an integer type, Windows versions do use
		//   structs
		// return pthread_equal(a, b);
		return (a == b);
	}

	void set_thread_name(const char* name);
}

#endif

