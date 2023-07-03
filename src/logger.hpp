#ifndef RESERV_LOGGER_H
#define RESERV_LOGGER_H

#include <atomic>
#include <iostream>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

namespace reServ {

// Enum - Log levels
enum class LogLevel { Info,
                      Warning,
                      Error };

// Struct to hold log information
struct LogEntry {
    LogLevel level;
    std::string message;
};

//
// Static, singleton Logger object that runs its own logging-thread
// (for now simply logging to the standard-output but "printLogEntry" could be virtual)
//
class Logger {
public:
    static Logger& instance() {
        // Instantiated on first use - Guaranteed to be destroyed
        static Logger instance;
        return instance;
    }

    void log(LogLevel level, const std::string& message) {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push({level, message});
    }

    ~Logger() {
        // Stop logging and wait for the logging thread to finish
        stopLogging = true;
        logThread.join();
    }

private:
    // Private ctor so no other object can be created
    Logger() : stopLogging(false) {
        // Start the logging thread
        logThread = std::thread(&Logger::processLogs, this);
    }

    // Delete copy-construcor and copy-assignment operator
    Logger(Logger const&) = delete;
    void operator=(Logger const&) = delete;

private:
    void processLogs() {
        while(!stopLogging) {
            try {
                // Sleep for a moment to allow for new items to be added
                std::this_thread::sleep_for(std::chrono::seconds(1));
                std::lock_guard<std::mutex> lock(queueMutex);
                if(!logQueue.empty()) {
                    const LogEntry entry = logQueue.front();
                    logQueue.pop();
                    printLogEntry(entry);
                }
            } catch(const std::exception& e) {
                // In case of logging error - fall back to console output
                std::lock_guard<std::mutex> lock(printMutex);
                std::cerr << e.what() << '\n';
            }
        }
    }

    void printLogEntry(const LogEntry& entry) {
        // Get current time
        auto currentTime = std::chrono::system_clock::now();
        std::time_t timestamp = std::chrono::system_clock::to_time_t(currentTime);

        // Convert timestamp to string (Remove newline character from the end of the string)
        std::string timeString = std::ctime(&timestamp);
        timeString = timeString.substr(0, timeString.size() - 1);

        // Print log entry to console
        std::string levelString;
        switch(entry.level) {
            case LogLevel::Info: levelString = "INFO"; break;
            case LogLevel::Warning: levelString = "WARNING"; break;
            case LogLevel::Error: levelString = "ERROR"; break;
            default: break;
        }
        std::lock_guard<std::mutex> lock(printMutex);
        std::cout << "[" << timeString << "][" << levelString << "]: " << entry.message << std::endl;
    }

private:
    std::queue<LogEntry> logQueue;
    std::atomic<bool> stopLogging;
    std::thread logThread;
    std::mutex printMutex;
    std::mutex queueMutex;
};

}  // namespace reServ

#endif
