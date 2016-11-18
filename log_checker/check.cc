#include <algorithm>
#include <atomic>
#include <cctype>
#include <ctime>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <mutex>
#include <regex>
#include <string>
#include <thread>
#include <unordered_map>

#define DATAFILE "log.dat"
#define LOG_LOCATION "/srv/logs/access.log"
#ifndef THREAD_COUNT
#define THREAD_COUNT 2
#endif

// Large File Support // 500
static constexpr uint64_t LFS  = (50 * (1024 * 1024));

// C++14 abuse, nothing more. Move along.
template<class T> constexpr T one = T(1);

struct ipInfo {
    ipInfo(std::tm time, std::string page_accessed, std::string browser_version)
        : time(std::move(time)), page_accessed(std::move(page_accessed)),
          browser_version(std::move(browser_version)){}
    std::tm time;
    std::string page_accessed;
    std::string browser_version;
};

static std::unordered_map<std::string, std::vector<ipInfo>> log_ips;
static std::mutex insert_lock;

static std::time_t start_time, read_time_start, read_time_end;
static clock_t start;
static uint64_t log_size;
static std::atomic<uint64_t> bytes_read_total;
static std::atomic<long long int> iterations;
static std::condition_variable cv;
static std::mutex cv_m;
static bool thread_ready = false;
static std::mutex print_lock;

static struct _progops {
    bool want_stats;
    std::vector<std::string> log_files;
} progops;

static char *
timediff(time_t seconds)
{
    static char buf[512];
    unsigned long days, hours, minutes;

    days     = seconds / 86400;
    seconds %= 86400;
    hours    = seconds / 3600;
    hours   %= 3600;
    minutes  = seconds / 60;
    minutes %= 60;
    seconds %= 60;

    snprintf(buf, sizeof(buf), "%lu day%s, %lu:%02lu:%02lu",
             days, (days == 1) ? "" : "s", hours, minutes, (unsigned long) seconds);

    return buf;
}

static std::time_t
time_remaining()
{
    std::size_t rate = bytes_read_total / std::max((time(nullptr) - read_time_start), one<std::time_t>);

    if (!rate)
        return 0;

    std::size_t remaining_bytes = log_size - bytes_read_total;
    std::time_t remaining_seconds = remaining_bytes / rate;
    return remaining_seconds;
}

static void
read_log_stats()
{
    const std::time_t curtime = time(nullptr);

    std::time_t end_parse_time = read_time_end ? read_time_end : curtime;
    std::size_t rate = iterations / std::max((end_parse_time - read_time_start), one<std::time_t>);

    std::cout << "\nFinished reading log file\n";
    std::cout << "Rate        : " << rate << " lines per second\n";
    std::cout << "Parsing time: " << timediff(curtime - read_time_start) << "    " << std::endl;
}

void
display_parse_thread_data(const unsigned th, const std::size_t rate,
                          const char *const time, const float bytes,
                          const uint64_t startchunk, const uint64_t endchunk)
{
    std::lock_guard<std::mutex> l(print_lock); // Lock the thread so we can write to the screen

    // Go back to the top so we can rewrite in our block
    for (unsigned ii{}; ii < 7 + (th * 7); ++ii)
        std::cout << "\033[F\r";

    // Lambda function to turn bytes in to mega bytes
    auto btomb = [](const auto value) { return ((value / 1024.) / 1024.); };

    std::cout << "Thread #" << th + 1 << "\n";
    std::cout << "Start chunk                : " << startchunk << "\n";
    std::cout << "End chunk                  : " << endchunk << "\n";
    std::cout << "Current rate               : " << std::setw(6) << std::fixed << std::setprecision(2) << btomb(rate)  << " MiB per second" << "\n";
    std::cout << "Remaining parsing time     : " << time << "\n";
    std::cout << "Remaining bytes            : " << std::setw(6) << std::fixed << std::setprecision(2) << btomb(bytes) << " MiB" << "\n";

    // Reset our block
    for (unsigned ii{}; ii < 1 + (th * 7); ++ii)
        std::cout << "\n";

    std::cout << std::flush;
}

void
read_logs_thread(const uint64_t startpos, const uint64_t endpos,
                 const unsigned screen_line, const uint64_t splitsize)
{
    uint64_t bytes_read{}; // Bytes read in this thread
    std::ifstream file(LOG_LOCATION);
    std::string line;
    // nginx has the connection IP at the beginning
    // so we will only need the first match.
    std::regex ip_regex("(\\d{1,3}(\\.\\d{1,3}){3})");
    std::regex date_regex("(\\[\\d\\w+\\/\\w+\\/\\d{4}\\:.*\\])");
    std::regex page_regex("\"\\w+\\s(\\/[^?\\s]*)");
    std::regex vers_regex("\"[^\"]+\"[^\"]+\"[^\"]+\"[^\"]+\"([^\"]+)\"");

    file.clear();
    file.seekg(startpos); // Go to the position to start reading from

    const std::time_t thread_start_time = time(nullptr);

    // Read until we have read enough
    while (file.tellg() != -1 && !file.eof() && static_cast<uint64_t>(file.tellg()) < endpos) {
        std::smatch ip_match;     // Get the IP
        std::smatch date_match;   // Get the date
        std::smatch page_match;   // Get the page accessed
        std::smatch vers_match;   // Get the browser version
        std::getline(file, line); // Read the line

        bytes_read += line.size();
        bytes_read_total += line.size();

        // Refresh stats every 3000 lines
        if(++iterations % 3000 == 0) {
            // Generate stats then display
            std::size_t rate = bytes_read / std::max((time(nullptr) - thread_start_time), one<std::time_t>);
            std::size_t remaining_bytes = splitsize - bytes_read;
            std::time_t remaining_seconds = remaining_bytes / rate;

            display_parse_thread_data(screen_line, rate, timediff(remaining_seconds), remaining_bytes, startpos, endpos);
        }

        // SAVE THE LINES, KILL THE ANIMALS
        auto setregex = [&line](auto& match, const auto& regex) {
            return (std::regex_search(line, match, regex) == 0);
        };

        if (setregex(ip_match, ip_regex))     continue;
        if (setregex(date_match, date_regex)) continue;
        if (setregex(page_match, page_regex)) continue;
        if (setregex(vers_match, vers_regex)) continue;

        std::tm time;
        if ((strptime(std::string(date_match[0]).c_str(), "[%d/%b/%Y:%H:%M:%S %z]", &time)) == 0)
            continue;

        std::string ip(ip_match[0]);
        std::string page(page_match[1]);
        std::string version(vers_match[1]);

        // Insert the entry, making sure we have
        // exclusive access
        insert_lock.lock();
        log_ips[ip].emplace_back(std::move(time), std::move(page), std::move(version));
        insert_lock.unlock();
    }

    // Get the rate, and display 0 for remaining
    std::size_t rate = bytes_read / std::max((time(nullptr) - thread_start_time), one<std::time_t>);
    display_parse_thread_data(screen_line, rate, timediff(0), 0., startpos, endpos);
}

static void
stats_thread()
{
    std::unique_lock<std::mutex> lk(cv_m);

    while (true) {
        {
            // Lock our screen lock
            std::lock_guard<std::mutex> l(print_lock);

            for (unsigned ii{}; ii < 6 + (THREAD_COUNT * 7); ++ii)
                std::cout << "\033[F\r";

            std::cout << "CPU time used       : " << ((double) (clock() - start)) / CLOCKS_PER_SEC << "\n";
            std::cout << "Real world runtime  : " << timediff(time(nullptr) - start_time) << "\n";
            std::cout << "Parsing ETA         : " << timediff(time_remaining()) << "          \n";

            for (unsigned ii{}; ii < (THREAD_COUNT * 7) + 3; ++ii)
                std::cout << "\n";

            std::cout << std::flush;
        }

        // Wait for both threads to finish, if not, re-display
        // time stats.
        cv.wait_for(lk, std::chrono::seconds(1));
        if (thread_ready)
            return;
    }
}

static void
split_log()
{
    uint64_t startchunk{}, lengthchunk{}, endchunk{};
    const unsigned chunks = ((log_size - 1) / LFS);

    // Go through the amount of chunks that need to be iterated
    for (unsigned ii{}; ii < chunks + 1; ++ii) {
        std::vector<std::tuple<std::streampos, std::streampos>> splits;
        startchunk = LFS * ii;

        // If it's the last chunk, read until the last position
        if (ii == chunks)
            lengthchunk = log_size - startchunk;
        else
            lengthchunk = LFS;

        endchunk = startchunk + lengthchunk;

        if (log_size >= LFS)
            std::cout << "Chunk " << ii + 1 << "/" <<  chunks + 1 << "\n";

        // Get the splitting point in our chunk
        const uint64_t byte_split = lengthchunk / THREAD_COUNT;

        for (std::size_t jj{}; jj < THREAD_COUNT; ++jj) {
            const auto offset = byte_split * jj;
            const auto offch  = offset + startchunk;
            std::cout << "\n\n\n\n\n\n\n"; // Compensate for each thread line
            if (jj + 1 == THREAD_COUNT)
                splits.emplace_back(offch, endchunk);
            else
                splits.emplace_back(offch, byte_split + offch);
        }

        // Be considerate with flushing. It does cause some screen lag
        // and tearing so save it for our last instruction.
        std::cout << std::flush;

        std::vector<std::thread> readers;
        std::thread statthread(stats_thread);
        unsigned line{};

        for (const auto& p: splits) {
            readers.emplace_back([p, l=line++, byte_split]
            {
                read_logs_thread(std::get<0>(p), std::get<1>(p), l, byte_split);
            });
        }

        for (auto& t: readers) t.join();

        cv_m.lock();
        thread_ready = true;
        cv.notify_all();
        cv_m.unlock();

        statthread.join();

        thread_ready = false;

        if (ii < chunks) {
            for (unsigned jj{}; jj < 1 + (THREAD_COUNT * 7); ++jj)
                std::cout << "\033[F\r";
        }
    }
}

static void
read_logs()
{
    {
        std::ifstream file(LOG_LOCATION);

        std::cout << "Checking file size... " << std::flush;

        file.sync_with_stdio(false);
        file.seekg(0, std::ios::end);
        log_size = file.tellg();
    }

    std::cout << log_size << " bytes\n";

    if (log_size >= LFS)
        std::cout << "\n@@@ NOTICE: Large file detected! @@@\nSplitting files in to chunks...\n\n";

    std::cout << "Parsing logs...\n\nParsing Statistics:\n\n\n\n";

    read_time_start = time(nullptr);
    split_log();
    read_time_end = time(nullptr);

    read_log_stats();
}

static void
dump_memory()
{
    std::cout << "\nStoring memory in " << DATAFILE << "...\n" << std::endl;
    FILE *f = fopen(DATAFILE, "wb");
    std::size_t tmp;

    for(const auto& ii: log_ips) {
        const std::string& ip(ii.first);
        // Store the size of the IP in a variable
        tmp = ip.size();

        // Store the IP
        fwrite(&tmp, sizeof(tmp), 1, f);
        fwrite(ip.c_str(), tmp, 1, f);

        // Store the amount of elements in our ipinfo
        // vector
        tmp = ii.second.size();
        fwrite(&tmp, sizeof(tmp), 1, f);

        for(const auto& ipinfo: ii.second) {
            // Convert our time struct in to epoch time
            std::time_t ctime = mktime(const_cast<std::tm *>(&ipinfo.time));
            fwrite(&ctime, sizeof(ctime), 1, f);

            // Store the size of our page, the the page
            tmp = ipinfo.page_accessed.size();
            fwrite(&tmp, sizeof(tmp), 1, f);
            fwrite(ipinfo.page_accessed.c_str(), tmp, 1, f);

            // Store the size of our version, then the version
            tmp = ipinfo.browser_version.size();
            fwrite(&tmp, sizeof(tmp), 1, f);
            fwrite(ipinfo.browser_version.c_str(), tmp, 1, f);
        }
    }

    fclose(f);
}

static void
parse_logs()
{
    std::cout << "Checking " << log_ips.size() << " IP addresses...\n";
    // what do now??
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " /path/to/log.txt" << std::endl;
        exit(EXIT_SUCCESS);
    }

    for (ssize_t ii = 1; ii < argc; ++ii)
        progops.log_files.emplace_back(argv[ii]);

    // Hide the cursor
    std::cout << "\033[?25l" << std::endl;

    start = clock();
    start_time = time(nullptr);

    read_logs();
    dump_memory();
    parse_logs();

    // Un-hide the cursor
    std::cout << "\033[?25h" << std::endl;
    return 0;
}

// clang++-3.5 -std=c++14 -stdlib=libc++ -Wall -Wextra -Wpedantic -lpthread check.cc -o checklogs
