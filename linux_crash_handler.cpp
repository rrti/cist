#include <cassert>
#include <cinttypes> // uintptr_t
#include <cstring> // strnlen
#include <cstdlib>
#include <cstdio>

#include <string>
#include <sstream>

#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <new>

#include <signal.h>
#include <execinfo.h>

#include <unistd.h> // {R,F}_OK
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h> // getrlimits

#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <dlfcn.h>

#include "crash_handler.hpp"
#include "threading.hpp"


#define ADDR2LINE "addr2line"
#define LOG_RAW_LINE(fmt, ...) do {         \
	fprintf(stderr, fmt, ##__VA_ARGS__);    \
	fprintf(stderr, "\n"              );    \
	fprintf(log_file, fmt, ##__VA_ARGS__);  \
	fprintf(log_file, "\n"              );  \
} while (false)


static constexpr int MAX_STACKTRACE_DEPTH = 100;
static const char* INVALID_LINE_INDICATOR = "#####";
static constexpr uintptr_t INVALID_ADDR_INDICATOR = 0xFFFFFFFF;

static __thread int THREAD_SIGNAL_REENTRANCE_CTR = 0;

struct t_stack_entry {
	std::string fileline;
	std::string funcname;
	std::string fileline_abbrev;
	std::string funcname_abbrev;
	bool inlined = true;
};

struct t_stack_frame {
	int                   level = 0;      // level in the original unwinding (inlined functions share the same level as their "caller")
	void*                 ip = nullptr;   // instruction pointer from libunwind or backtrace()
	std::string           mangled;        // mangled name retrieved from libunwind (not printed, memoized for debugging)
	std::string           symbol;         // backtrace_symbols output
	uintptr_t             addr = 0;       // translated address / load address for OS X
	std::string           path;           // translated library or module path
	std::vector<t_stack_entry> entries;   // function names and lines (possibly several inlined) retrieved from addr2line
};

typedef std::vector<t_stack_frame> t_stack_trace;



namespace util {
	const char* signal_to_string(int signal) {
		switch (signal) {
			case SIGSEGV: { return " (SIGSEGV)"; } break;
			case SIGILL : { return " (SIGILL)" ; } break;
			case SIGPIPE: { return " (SIGPIPE)"; } break;
			case SIGIO  : { return " (SIGIO)"  ; } break;
			case SIGABRT: { return " (SIGABRT)"; } break;
			case SIGFPE : { return " (SIGFPE)" ; } break;
			case SIGBUS : { return " (SIGBUS)" ; } break;
			default     : {                      } break;
		}

		return "";
	}
}

namespace filesys {
	std::string get_directory(const std::string& path);
}
namespace platform {
	std::string get_process_executable_file() {
		char file[512];
		const int ret = readlink("/proc/self/exe", file, sizeof(file) - 1);

		if (ret >= 0) {
			file[ret] = '\0';
			return file;
		}

		return "";
	}
	std::string get_process_executable_path() { return (filesys::get_directory(get_process_executable_file())); }
	std::string get_process_working_dir() {
		char path[1024];

		if (getcwd(path, sizeof(path)) != nullptr)
			return path;

		return "";
	}
};

namespace filesys {
	#define PS_WIN32 '\\'
	#define PS_POSIX '/'

	#ifdef _WIN32
	#define PS_NATIVE PS_WIN32
	#else
	#define PS_NATIVE PS_POSIX
	#endif


	std::string strip_trailing_slashes(const std::string& path);

	bool file_exists(const std::string& file) {
		struct stat info;
		return ((stat(file.c_str(), &info) == 0 && !S_ISDIR(info.st_mode)));
	}

	bool dir_exists(const std::string& dir) {
		struct stat info;
		return ((stat(strip_trailing_slashes(dir).c_str(), &info) == 0 && S_ISDIR(info.st_mode)));
	}

	bool is_readable_file(const std::string& file) {
		// exclude directories
		if (!file_exists(file))
			return false;

		return (access(file.c_str(), R_OK | F_OK) == 0);
	}


	bool is_path_separator(char c) { return ((c == PS_WIN32) || (c == PS_POSIX)); }
	bool is_native_path_separator(char c) { return (c == PS_NATIVE); }
	bool has_trailing_path_separator(const std::string& path) {
		return (!path.empty() && is_native_path_separator(path.at(path.size() - 1)));
	}


	std::string remove_quotes(const std::string& str) {
		if (str[0] == '"' && str[str.length() - 1] == '"')
			return str.substr(1, str.length() - 2);

		return str;
	}


	std::string get_directory(const std::string& path) {
		const size_t s = path.find_last_of("\\/");

		if (s != std::string::npos)
			return path.substr(0, s + 1);

		return "";
	}

	std::string get_filename(const std::string& path) {
		const size_t s = path.find_last_of("\\/");

		if (s != std::string::npos)
			return path.substr(s + 1);

		return path;
	}


	std::string strip_trailing_slashes(const std::string& path) {
		size_t len = path.length();

		while (len > 0) {
			if (!is_path_separator(path[len - 1]))
				break;

			--len;
		}

		return (path.substr(0, len));
	}

	std::string add_trailing_path_separator(const std::string& path) {
		if (path.empty())
			return (path + "." + PS_NATIVE);
		if (!has_trailing_path_separator(path))
			return (path + PS_NATIVE);

		return path;
	}

	std::string create_absolute_path(const std::string& relative_path) {
		if (relative_path.empty())
			return relative_path;

		std::string absolute_path = std::move(remove_quotes(relative_path));

		if (absolute_path.empty() || absolute_path[0] != '/') {
			// remove initial "./"
			if (absolute_path.find("./") == 0)
				absolute_path = absolute_path.substr(2);

			absolute_path = add_trailing_path_separator(platform::get_process_executable_path()) + absolute_path;
		}

		if (!file_exists(absolute_path))
			return relative_path;

		return absolute_path;
	}
}




// returns an absolute existing path to a file that contains debug-symbols
// precedence (top entries considered first):
// 1. <bin-path>/<bin-file><bin-extension>.dbg
// 2. <bin-path>/<bin-file>.dbg
// 3. <debug-path><bin-path>/<bin-file><bin-extension>
// 4. <bin-path>/<bin-file><bin-extension> (== input)
//
// examples:
// - "./process" -> "/usr/bin/process"
// - "./process" -> "/usr/bin/process.dbg"
// - "/usr/bin/process" "/usr/lib/debug/usr/bin/process"
// - "/usr/bin/process-dedicated" -> "/usr/lib/debug/usr/bin/process-dedicated"
// - "/usr/lib/process/lib.so" -> "/usr/lib/debug/usr/lib/process/lib.so"
//
static std::string locate_symbol_file(const std::string& binary_file) {
	std::string symbol_file;

	static const std::string debug_path = "/usr/lib/debug"; // debian

	const std::string bin_path = filesys::get_directory(binary_file);
	const std::string bin_file = filesys::get_filename(binary_file);
	// const std::string binExt  = filesys::get_extension(binary_file);

	if (filesys::is_readable_file(symbol_file = bin_path + bin_file + ".dbg"))
		return symbol_file;

	if (filesys::is_readable_file(symbol_file = debug_path + bin_path + bin_file))
		return symbol_file;

	return binary_file;
}


static bool have_addr2line() {
	static int i = -1;

	if (i == -1) {
		FILE* f = popen(ADDR2LINE " --help", "r");

		if ((i = (f == nullptr)) == 1)
			return false;

		pclose(f);
	}

	return (i == 0);
}

static const char* read_pipe(FILE* file, char* line, int maxLength) {
	const char* res = fgets(line, maxLength, file);

	if (res == nullptr) {
        line[0] = 0;
		return res;
	}

	const size_t sz = strnlen(line, maxLength);

	// exclude the line-ending
	if (line[sz - 1] == '\n')
		line[sz - 1] = 0;

    return res;
}

// converts a string containing a hexadecimal value to a decimal value with the size of a pointer, e.g. 0xfa -> 26
static uintptr_t hex_to_int(const char* hexStr) {
	static_assert(sizeof(unsigned long int) == sizeof(uintptr_t), "");
	unsigned long int value = 0;
	sscanf(hexStr, "%lx", &value);
	return (uintptr_t) value;
}

// consumes (and frees) the lines produced by backtrace_symbols
static void extract_symbols(char** lines, t_stack_trace& stacktrace) {
	int l = 0;
	auto fit = stacktrace.begin();

	while (fit != stacktrace.end()) {
		if (strncmp(lines[l], "[(nil)]", 20) != 0) {
			fit->symbol = lines[l];
			fit++;
		} else {
			// preserve ordering of remaining symbols
			fit = stacktrace.erase(fit);
		}

		l++;
	}

	free(lines);
}

static int common_string_length(const std::string& str1, const std::string& str2) {
	const size_t m = std::min(str1.length(), str2.length());
	size_t n = 0;

	while (n < m && str1[n] == str2[n]) {
		n++;
	}

	return n;
}




static std::unordered_map<std::string, uintptr_t> find_base_memory_addresses(const t_stack_trace& stacktrace) {
	// store all paths which we have to find
	std::unordered_set<std::string> unmatched_paths;
	std::unordered_map<std::string, uintptr_t> base_mem_addr_paths;

	base_mem_addr_paths.reserve(stacktrace.size());
	unmatched_paths.reserve(base_mem_addr_paths.size());

	for (const t_stack_frame& sf: stacktrace) {
		base_mem_addr_paths[sf.path] = 0;
	}

	// pair<std::string, uintptr_t>
	for (const auto& addr_pair: base_mem_addr_paths) {
		unmatched_paths.insert(addr_pair.first);
	}

	// /proc/self/maps contains the base addresses for all loaded dynamic
	// libs of the current process + other stuff (which does not interest
	// us)
	FILE* maps_file = fopen("/proc/self/maps", "rb");

	if (maps_file == nullptr)
		return base_mem_addr_paths;

	// format of /proc/self/maps:
	// (column names)  address           perms offset  dev   inode      pathname
	// (example 32bit) 08048000-08056000 r-xp 00000000 03:0c 64593      /usr/sbin/gpm
	// (example 64bit) ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0   [vsyscall]
	unsigned long int mem_start_addr = 0;
	unsigned long int bin_addr_offset = 0;

	char bin_path_name[512];
	char bin_addr_line[512];

	// read and parse all lines
	while (!unmatched_paths.empty() && (fgets(bin_addr_line, sizeof(bin_addr_line) - 1, maps_file) != nullptr)) {
		if (sscanf(bin_addr_line, "%lx-%*x %*s %lx %*s %*u %s", &mem_start_addr, &bin_addr_offset, bin_path_name) != 3)
			continue;

		if (bin_addr_offset != 0)
			continue;

		// start of binary's memory space
		std::string matching_path;

		// go through all paths of binaries involved in the stacktrace
		// for each, check if the current line contains this binary
		for (const std::string& unmatched_path: unmatched_paths) {
			if (unmatched_path == bin_path_name) {
				matching_path = unmatched_path;
				break;
			}
		}

		if (matching_path.empty())
			continue;

		base_mem_addr_paths[matching_path] = mem_start_addr;
		unmatched_paths.erase(matching_path);
	}

	fclose(maps_file);
	return base_mem_addr_paths;
}



// extracts the library/binary paths from the output of backtrace_symbols()
// example lines:
//
//   ./process() [0x84b7b5]
//   /usr/lib/libc.so.6(+0x33b20) [0x7fc022c68b20]
//   /usr/lib/libstdc++.so.6(_ZN9__gnu_cxx27__verbose_terminate_handlerEv+0x16d) [0x7fc023553fcd]
//
static std::string extract_path(const std::string& line) {
	size_t end = line.find_last_of('(');

	if (end == std::string::npos) {
		// if there is only a memory address, get rid of the ' ' before the '['
		end = line.find_last_of('[');
		end -= ((end != std::string::npos) && (end > 0));
	}

	if (end == std::string::npos)
		return INVALID_LINE_INDICATOR;

	return (line.substr(0, end - 0));
}

// extracts the debug addresses from backtrace_symbols() output
// example lines:
//
// ./process() [0x84b7b5]
// /usr/lib/libc.so.6(abort+0x16a) [0x7fc022c69e6a]
// /usr/lib/libstdc++.so.6(+0x5eea1) [0x7fc023551ea1]
//
static uintptr_t extract_addr(const t_stack_frame& frame) {
	uintptr_t addr = INVALID_ADDR_INDICATOR;
	const std::string& line = frame.symbol;

	size_t begin = line.find_last_of('[');
	size_t end = std::string::npos;

	if (begin != std::string::npos)
		end = line.find_last_of(']');

	if ((begin != std::string::npos) && (end != std::string::npos))
		addr = hex_to_int(line.substr(begin + 1, end - begin - 1).c_str());

	begin = line.find_last_of('(');
	end = line.find_last_of(')');

	if ((end - begin) == 1)
		return addr;

	Dl_info info;

	if (dladdr(frame.ip, &info) != 0)
		return ((uintptr_t) frame.ip - (uintptr_t) info.dli_fbase);

	return addr;
}



// translates module and address information from backtrace symbols into a vector of t_stack_frame objects
// each with its own set of entries representing the function call and any inlined functions for that call
static void translate_stacktrace(t_stack_trace& stacktrace) {
	// extract important data from backtrace_symbols' output
	for (t_stack_frame& sf: stacktrace) {
		const std::string rel_path = extract_path(sf.symbol);
		const std::string abs_path = filesys::create_absolute_path(rel_path);

		// prepare for addr2line()
		sf.path = abs_path;
		sf.addr = extract_addr(sf);
	}

	// check if addr2line is available
	assert(have_addr2line());


	std::string       exec_command_string;
	std::stringstream exec_command_buffer;

	// detect base memory-addresses of all libs (in the running process) found in stacktrace
	std::unordered_map<std::string, uintptr_t> base_mem_addr_paths = find_base_memory_addresses(stacktrace);
	std::deque<size_t> stack_frame_indices;


	// finally translate it; nested s.t. the outer loop covers
	// all the entries for one library (fewer addr2line calls)
	for (const auto& base_mem_addr_pair: base_mem_addr_paths) {
		const std::string& module_path = base_mem_addr_pair.first;
		const std::string& symbol_file = locate_symbol_file(module_path);

		{
			stack_frame_indices.clear();
			exec_command_string.clear();
			exec_command_buffer.str("");

			exec_command_buffer << ADDR2LINE;
			exec_command_buffer << " -i -a -f -C";
			exec_command_buffer << " --exe=\"" << symbol_file << "\"";

			// add requested addresses that should be translated by addr2line to buffer
			for (size_t i = 0, n = stacktrace.size(); i < n; i++) {
				const t_stack_frame& sf = stacktrace[i];

				if (sf.path != module_path)
					continue;

				exec_command_buffer << " " << std::hex << sf.addr;
				stack_frame_indices.push_back(i);
			}

			// hide error output from process's pipe
			exec_command_buffer << " 2>/dev/null";

			exec_command_string = std::move(exec_command_buffer.str());
		}

		FILE* cmd_output_pipe = popen(exec_command_string.c_str(), "r");

		// execute addr2line, read stdout via pipe and write to log
		if (cmd_output_pipe == nullptr)
			continue;


		char line_buf[2048] = {0};
		char line_ctr = 0;

		t_stack_frame* stack_frame = &stacktrace[stack_frame_indices.front()];
		t_stack_entry stack_entry;

		while (read_pipe(cmd_output_pipe, line_buf, sizeof(line_buf)) != nullptr) {
			if (line_buf[0] == '0' && line_buf[1] == 'x') {
				line_ctr = 0;

				if (!stack_frame->entries.empty()) {
					stack_frame->entries.back().inlined = false;
				} else {
					stack_frame->entries.reserve(8);
				}

				// new address encountered; switch to corresponding frame
				if (!stack_frame_indices.empty()) {
					stack_frame = &stacktrace[stack_frame_indices.front()];
					stack_frame_indices.pop_front();
				}

				uintptr_t parsedAddr = 0;
				uintptr_t stackAddr = stack_frame->addr;

				if (sscanf(line_buf, "0x%lx", &parsedAddr) != 1 || parsedAddr != stackAddr)
					break;
			}

			// consecutive pairs of lines after an address form an entry
			switch (line_ctr) {
				case 0: {
					line_ctr = 1;
				} break;
				case 1: {
					stack_entry.funcname = line_buf;
					stack_entry.funcname = stack_entry.funcname.substr(0, stack_entry.funcname.rfind(" (discriminator"));
					line_ctr = 2;
				} break;
				case 2: {
					stack_entry.fileline = line_buf;
					stack_frame->entries.push_back(stack_entry);

					// minor hack; store an <fileline, address> entry as well
					snprintf(line_buf, sizeof(line_buf), "0x%lx", stack_frame->addr);

					stack_entry.funcname = stack_entry.fileline;
					stack_entry.fileline = line_buf;
					stack_frame->entries.push_back(stack_entry);

					// next line can be either an address or a function-name
					line_ctr = 1;
				} break;
				default: {
					assert(false);
				} break;
			}
		}

		pclose(cmd_output_pipe);
	}
}


static void log_stacktrace(t_stack_trace& stacktrace) {
	size_t col_file_line = 0;

	const std::string exe_path = platform::get_process_executable_path();
	const std::string cwd_path = platform::get_process_working_dir();

	for (t_stack_frame& sf: stacktrace) {
		for (t_stack_entry& se: sf.entries) {
			std::string fileline = se.fileline;

			// case "??:?" and ":?"; print raw backtrace_symbol
			if (fileline[1] == '?')
				fileline = sf.symbol;

			se.fileline_abbrev = fileline;
			se.funcname_abbrev = se.funcname;

			size_t abbrev_start_idx = 0;

			if (fileline[0] == '/') {
				// see if we can shorten the file/line bit by removing the common path, i.e. one char for first '/'
				if ((abbrev_start_idx = common_string_length(fileline, exe_path)) > 1) {
					se.fileline_abbrev = std::string(".../") + fileline.substr(abbrev_start_idx, std::string::npos);
				} else if ((abbrev_start_idx = common_string_length(fileline, cwd_path)) > 1) {
					se.fileline_abbrev = std::string("./") + fileline.substr(abbrev_start_idx, std::string::npos);
				}
			}

			col_file_line = std::max(col_file_line, se.fileline_abbrev.length());
		}
	}

	// print out the translated trace
	for (const t_stack_frame& sf: stacktrace) {
		for (const t_stack_entry& se: sf.entries) {
			if (se.inlined) {
				fprintf(stderr, "  <%02u> %*s  %s\n", sf.level, int(col_file_line), se.fileline_abbrev.c_str(), se.funcname_abbrev.c_str());
			} else {
				fprintf(stderr, "[%02u]   %*s  %s\n", sf.level, int(col_file_line), se.fileline_abbrev.c_str(), se.funcname_abbrev.c_str());
			}
		}
	}
}




static void forced_exit_5s() {
	std::this_thread::sleep_for(std::chrono::seconds(5));
	std::exit(-1);
}

static void forced_exit_10s() {
	std::this_thread::sleep_for(std::chrono::seconds(10));
	#if defined(__GNUC__)
	std::_Exit(-1);
	#else
	std::quick_exit(-1);
	#endif
}


typedef struct sigaction sigaction_t;
typedef void (*sigact_handler_t)(int, siginfo_t*, void*);

static sigaction_t& get_sig_action(sigact_handler_t sigact_handler) {
	static sigaction_t sa;

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);

	if (sigact_handler == nullptr) {
		// the default signal handler uses the old sa_handler interface, so just identify this case with sigact_handler == null
		sa.sa_handler = SIG_DFL;
	} else {
		sa.sa_flags |= SA_SIGINFO;
		sa.sa_sigaction = sigact_handler;
	}

	return sa;
}



namespace crash_handler {
	static FILE* log_file = nullptr;

	// obtain (untranslated) symbols using a ucontext_t structure, called by {halted,suspended}_stacktrace
	static int thread_unwind(ucontext_t* uc, void** iparray, t_stack_trace& stacktrace) {
		assert(iparray != nullptr);

		unw_cursor_t cursor;

#if (defined(__arm__) || defined(__APPLE__))
		// ucontext_t and unw_context_t are not aliases here
		unw_context_t thisctx;
		unw_getcontext(&thisctx);
#else
		// effective ucontext_t; use unw_getcontext locally if
		// <uc> is not supplied (e.g. inside signal handlers)
		ucontext_t thisctx;

		if (uc == nullptr) {
			unw_getcontext(&thisctx);
			uc = &thisctx;
		}
#endif


		char proc_buffer[1024];

		stacktrace.clear();
		stacktrace.reserve(MAX_STACKTRACE_DEPTH);
		#if 0
		// documentation seems to indicate that uc_link contains a pointer to a "successor"
		// ctx that is to be resumed after the current one, as expected in a signal handler
		// in practice, Linux seems to re-use the existing thread context so this approach
		// does not work?
		while (uc->uc_link != nullptr) {
			uc = uc->uc_link;
		}
		#endif

#if (defined(__arm__) || defined(__APPLE__))
		const int err = unw_init_local(&cursor, &thisctx);
#else
		const int err = unw_init_local(&cursor, uc);
#endif

		if (err != 0)
			return 0;

		for (int i = 0; i < MAX_STACKTRACE_DEPTH && unw_step(&cursor); i++) {
			unw_word_t ip;
			unw_word_t offp;
			unw_get_reg(&cursor, UNW_REG_IP, &ip);

			stacktrace.emplace_back();
			t_stack_frame& frame = stacktrace.back();

			frame.ip = (iparray[i] = reinterpret_cast<void*>(ip));
			frame.level = i;

			if (!unw_get_proc_name(&cursor, proc_buffer, sizeof(proc_buffer) - 1, &offp)) {
				frame.mangled = std::string(proc_buffer);
			} else {
				frame.mangled = std::string("UNW_ENOINFO");
			}
		}

		return (int(stacktrace.size()));
	}



	// internal
	static void stacktrace(pthread_t* thread_ptr = nullptr, const char* thread_name = nullptr) {
		(void) thread_ptr;
		(void) thread_name;

		if (thread_name != nullptr) {
			LOG_RAW_LINE("Stacktrace (thread %s):", thread_name);
		} else {
			LOG_RAW_LINE("Stacktrace:");
		}

		t_stack_trace stacktrace;

		{
			void* iparray[MAX_STACKTRACE_DEPTH];

			// get untranslated stacktrace symbols
			const int num_lines = thread_unwind(nullptr, iparray, stacktrace);

			assert(num_lines <= MAX_STACKTRACE_DEPTH);

			// give them meaningful names
			extract_symbols(backtrace_symbols(iparray, num_lines), stacktrace);
		}

		if (stacktrace.empty())
			return;

		// translate it
		translate_stacktrace(stacktrace);
		log_stacktrace(stacktrace);
	}


	// TODO:
	//   use gdb's libthread_db to get stacktraces of all threads
	//   (custom thread_backtrace() only works on the main thread)
	void stacktrace(threading::native_thread_handle thread_handle, const char* thread_name) {
		if (threading::get_current_thread_handle() != thread_handle)
			return;

		prepare_stacktrace();
		stacktrace(&thread_handle, thread_name);
		cleanup_stacktrace();
	}


    void suspended_stacktrace(threading::thread_controls* ctls, const char* thread_name) {
        assert(ctls != nullptr);
        assert(ctls->handle != 0);
        assert(thread_name[0] != 0);

       t_stack_trace stacktrace;

        {
            void* iparray[MAX_STACKTRACE_DEPTH];

	        // get untranslated stacktrace symbols
			ctls->suspend();
			const int num_lines = thread_unwind(&ctls->ucontext, iparray, stacktrace);
			ctls->resume();

			assert(num_lines <= MAX_STACKTRACE_DEPTH);

			// give them meaningful names
            extract_symbols(backtrace_symbols(iparray, num_lines), stacktrace);
        }

        if (stacktrace.empty())
            return;

        // translate symbols into code line numbers
		translate_stacktrace(stacktrace);

        // print out the translated stacktrace
		log_stacktrace(stacktrace);
    }

	// used by SIGSEGV / SIGILL / SIGFPE / etc signal handlers
	//
	// thread is usually in a halted state, but signal handler
	// can provide siginfo_t and ucontext_t structures to help
	// produce the trace using libunwind
    void halted_stacktrace(siginfo_t* siginfo, ucontext_t* ucontext) {
        assert(siginfo != nullptr);
        assert(ucontext != nullptr);

        t_stack_trace stacktrace;

        {
            void* iparray[MAX_STACKTRACE_DEPTH];

	        // get untranslated stacktrace symbols
            const int num_lines = thread_unwind(nullptr, iparray, stacktrace);

			assert(num_lines <= MAX_STACKTRACE_DEPTH);

			// give them meaningful names
            extract_symbols(backtrace_symbols(iparray, num_lines), stacktrace);
        }

        if (stacktrace.empty())
            return;

        translate_stacktrace(stacktrace);

        // print out the translated stacktrace, ignoring the frames that occur inside
		// the signal handler (before its line in the trace) which are likely padding
		// or just garbage
        log_stacktrace(stacktrace);
    }



	void prepare_stacktrace() {}
	void cleanup_stacktrace() {}



	void handle_signal(int signal, siginfo_t* siginfo, void* pctx) {
		if (signal == SIGINT) {
			// caught SIGINT (ctrl+c = kill), abort after 5 seconds
			std::thread(std::bind(&forced_exit_5s));
			std::thread(std::bind(&forced_exit_10s));
			return;
		}

		// turn off handling for this signal temporarily in order to disable recursive events (e.g. SIGSEGV)
		if ((++THREAD_SIGNAL_REENTRANCE_CTR) >= 2) {
			sigaction_t& sa = get_sig_action(nullptr);
			sigaction(signal, &sa, nullptr);
		}

		ucontext_t* uctx = reinterpret_cast<ucontext_t*> (pctx);

		// append the signal name (no OS function to map signum to signame)
		const char* error = util::signal_to_string(signal);

		// FPE and ABRT cause endless loops, process never gets past the trigger-instr
		const bool fatal_signal = (signal == SIGSEGV) || (signal == SIGILL) || (signal == SIGPIPE) || (signal == SIGFPE) || (signal == SIGABRT) || (signal == SIGBUS);
		const bool keep_running = !fatal_signal;


		fprintf(stderr, "[%s] caught signal %s\n", __func__, error);

		// print stacktrace
		prepare_stacktrace();
		halted_stacktrace(siginfo, uctx);
		cleanup_stacktrace();

		// exit if we cought a critical signal; don't handle any further signals when exiting
		if (!keep_running)
			remove();

		// re-enable signal handling for this signal
		if (THREAD_SIGNAL_REENTRANCE_CTR >= 2) {
			sigaction_t& sa = get_sig_action(&handle_signal);
			sigaction(signal, &sa, nullptr);
		}
	}

	void output_stacktrace() {
		prepare_stacktrace();
		stacktrace(nullptr);
		cleanup_stacktrace();
	}

	void new_handler() {
		output_stacktrace();
	}


	void install() {
		// if core dumps are enabled, do not install any signal handler
		// see /proc/sys/kernel/core_pattern where these get written to
		struct rlimit limits;
		if ((getrlimit(RLIMIT_CORE, &limits) == 0) && (limits.rlim_cur > 0))
			return;

		const sigaction_t& sa = get_sig_action(&handle_signal);

		sigaction(SIGSEGV, &sa, nullptr);   // segmentation fault
		sigaction(SIGILL,  &sa, nullptr);   // illegal instruction
		sigaction(SIGPIPE, &sa, nullptr);   // network error
		sigaction(SIGIO,   &sa, nullptr);   // ?
		sigaction(SIGFPE,  &sa, nullptr);   // DIV0, etc
		sigaction(SIGABRT, &sa, nullptr);
		sigaction(SIGINT,  &sa, nullptr);
		sigaction(SIGBUS,  &sa, nullptr);   // EXC_BAD_ACCESS (mach exception) is translated to SIGBUS on MacOS

		std::set_new_handler(new_handler);  // std::bad_alloc ("failed to allocate memory")
	}

	void remove() {
		// const sigaction_t& sa = get_sig_action(SIG_DFL);
		const sigaction_t& sa = get_sig_action(nullptr);

		sigaction(SIGSEGV, &sa, nullptr);
		sigaction(SIGILL,  &sa, nullptr);
		sigaction(SIGPIPE, &sa, nullptr);
		sigaction(SIGIO,   &sa, nullptr);
		sigaction(SIGFPE,  &sa, nullptr);
		sigaction(SIGABRT, &sa, nullptr);
		sigaction(SIGINT,  &sa, nullptr);
		sigaction(SIGBUS,  &sa, nullptr);

		std::set_new_handler(nullptr);
	}
}

