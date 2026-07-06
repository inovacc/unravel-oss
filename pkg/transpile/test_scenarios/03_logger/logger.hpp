/*
 * logger.hpp - Thread-safe logging library
 * Inspired by spdlog / glog
 */
#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <chrono>
#include <ctime>
#include <functional>
#include <stdexcept>

namespace logging {

enum class Level {
    Debug = 0,
    Info  = 1,
    Warn  = 2,
    Error = 3,
    Fatal = 4
};

inline const char* level_to_string(Level level) {
    switch (level) {
        case Level::Debug: return "DEBUG";
        case Level::Info:  return "INFO";
        case Level::Warn:  return "WARN";
        case Level::Error: return "ERROR";
        case Level::Fatal: return "FATAL";
        default: return "UNKNOWN";
    }
}

struct LogRecord {
    Level       level;
    std::string message;
    std::string logger_name;
    std::string file;
    int         line;
    std::chrono::system_clock::time_point timestamp;

    LogRecord(Level lvl, const std::string& msg,
              const std::string& name = "",
              const std::string& f = "", int l = 0)
        : level(lvl), message(msg), logger_name(name),
          file(f), line(l),
          timestamp(std::chrono::system_clock::now()) {}
};

/* Abstract formatter */
class Formatter {
public:
    virtual ~Formatter() = default;
    virtual std::string format(const LogRecord& record) const = 0;
};

/* Default text formatter */
class TextFormatter : public Formatter {
public:
    std::string format(const LogRecord& record) const override {
        auto time_t = std::chrono::system_clock::to_time_t(record.timestamp);
        char timebuf[32];
        std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S",
                      std::localtime(&time_t));

        std::ostringstream oss;
        oss << "[" << timebuf << "] "
            << "[" << level_to_string(record.level) << "] ";

        if (!record.logger_name.empty())
            oss << "[" << record.logger_name << "] ";

        oss << record.message;

        if (!record.file.empty())
            oss << " (" << record.file << ":" << record.line << ")";

        return oss.str();
    }
};

/* JSON formatter */
class JsonFormatter : public Formatter {
public:
    std::string format(const LogRecord& record) const override {
        auto time_t = std::chrono::system_clock::to_time_t(record.timestamp);
        char timebuf[32];
        std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S",
                      std::localtime(&time_t));

        std::ostringstream oss;
        oss << "{\"time\":\"" << timebuf
            << "\",\"level\":\"" << level_to_string(record.level)
            << "\",\"msg\":\"" << escape_json(record.message) << "\"";

        if (!record.logger_name.empty())
            oss << ",\"logger\":\"" << record.logger_name << "\"";

        if (!record.file.empty())
            oss << ",\"file\":\"" << record.file
                << "\",\"line\":" << record.line;

        oss << "}";
        return oss.str();
    }

private:
    static std::string escape_json(const std::string& s) {
        std::string result;
        result.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '"':  result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n";  break;
                case '\t': result += "\\t";  break;
                default:   result += c;
            }
        }
        return result;
    }
};

/* Abstract sink (output destination) */
class Sink {
public:
    virtual ~Sink() = default;
    virtual void write(const std::string& formatted_msg) = 0;
    virtual void flush() = 0;

    void set_level(Level level) { min_level_ = level; }
    Level level() const { return min_level_; }

    bool should_log(Level level) const {
        return level >= min_level_;
    }

protected:
    Level min_level_ = Level::Debug;
};

/* Console sink (stdout/stderr) */
class ConsoleSink : public Sink {
public:
    explicit ConsoleSink(bool use_stderr = false)
        : stream_(use_stderr ? std::cerr : std::cout) {}

    void write(const std::string& msg) override {
        std::lock_guard<std::mutex> lock(mutex_);
        stream_ << msg << "\n";
    }

    void flush() override {
        std::lock_guard<std::mutex> lock(mutex_);
        stream_.flush();
    }

private:
    std::ostream& stream_;
    std::mutex mutex_;
};

/* File sink with rotation */
class FileSink : public Sink {
public:
    FileSink(const std::string& filename, size_t max_size = 10 * 1024 * 1024,
             int max_files = 5)
        : filename_(filename), max_size_(max_size), max_files_(max_files),
          current_size_(0) {
        file_.open(filename, std::ios::app);
        if (!file_.is_open())
            throw std::runtime_error("Cannot open log file: " + filename);

        /* Get current file size */
        file_.seekp(0, std::ios::end);
        current_size_ = static_cast<size_t>(file_.tellp());
    }

    ~FileSink() override {
        if (file_.is_open())
            file_.close();
    }

    void write(const std::string& msg) override {
        std::lock_guard<std::mutex> lock(mutex_);

        if (current_size_ + msg.size() > max_size_) {
            rotate();
        }

        file_ << msg << "\n";
        current_size_ += msg.size() + 1;
    }

    void flush() override {
        std::lock_guard<std::mutex> lock(mutex_);
        file_.flush();
    }

private:
    void rotate() {
        file_.close();

        /* Shift existing files: log.4 -> deleted, log.3 -> log.4, etc. */
        for (int i = max_files_ - 1; i > 0; i--) {
            std::string src = filename_ + "." + std::to_string(i);
            std::string dst = filename_ + "." + std::to_string(i + 1);
            std::rename(src.c_str(), dst.c_str());
        }

        std::rename(filename_.c_str(), (filename_ + ".1").c_str());
        file_.open(filename_, std::ios::trunc);
        current_size_ = 0;
    }

    std::string filename_;
    std::ofstream file_;
    std::mutex mutex_;
    size_t max_size_;
    int max_files_;
    size_t current_size_;
};

/* Callback sink for custom handlers */
class CallbackSink : public Sink {
public:
    using Callback = std::function<void(Level, const std::string&)>;

    explicit CallbackSink(Callback cb) : callback_(std::move(cb)) {}

    void write(const std::string& msg) override {
        if (callback_)
            callback_(Level::Info, msg);
    }

    void flush() override {}

private:
    Callback callback_;
};

/* The Logger class */
class Logger {
public:
    explicit Logger(const std::string& name = "")
        : name_(name), level_(Level::Debug),
          formatter_(std::make_unique<TextFormatter>()) {}

    /* Add a sink */
    void add_sink(std::shared_ptr<Sink> sink) {
        std::lock_guard<std::mutex> lock(mutex_);
        sinks_.push_back(std::move(sink));
    }

    /* Set minimum log level */
    void set_level(Level level) { level_ = level; }
    Level level() const { return level_; }

    /* Set formatter */
    void set_formatter(std::unique_ptr<Formatter> fmt) {
        std::lock_guard<std::mutex> lock(mutex_);
        formatter_ = std::move(fmt);
    }

    /* Log methods */
    void log(Level level, const std::string& msg,
             const std::string& file = "", int line = 0) {
        if (level < level_)
            return;

        LogRecord record(level, msg, name_, file, line);

        std::string formatted;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            formatted = formatter_->format(record);
        }

        for (auto& sink : sinks_) {
            if (sink->should_log(level))
                sink->write(formatted);
        }

        if (level == Level::Fatal) {
            flush();
            std::abort();
        }
    }

    void debug(const std::string& msg) { log(Level::Debug, msg); }
    void info(const std::string& msg)  { log(Level::Info, msg); }
    void warn(const std::string& msg)  { log(Level::Warn, msg); }
    void error(const std::string& msg) { log(Level::Error, msg); }

    void flush() {
        for (auto& sink : sinks_)
            sink->flush();
    }

    const std::string& name() const { return name_; }

private:
    std::string name_;
    Level level_;
    std::unique_ptr<Formatter> formatter_;
    std::vector<std::shared_ptr<Sink>> sinks_;
    std::mutex mutex_;
};

/* Logger registry (singleton) */
class Registry {
public:
    static Registry& instance() {
        static Registry registry;
        return registry;
    }

    std::shared_ptr<Logger> get(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = loggers_.find(name);
        if (it != loggers_.end())
            return it->second;

        auto logger = std::make_shared<Logger>(name);
        loggers_[name] = logger;
        return logger;
    }

    void set_default_level(Level level) {
        std::lock_guard<std::mutex> lock(mutex_);
        default_level_ = level;
    }

    void drop(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        loggers_.erase(name);
    }

    void drop_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        loggers_.clear();
    }

private:
    Registry() : default_level_(Level::Info) {}
    Registry(const Registry&) = delete;
    Registry& operator=(const Registry&) = delete;

    std::map<std::string, std::shared_ptr<Logger>> loggers_;
    std::mutex mutex_;
    Level default_level_;

    /* Need to include map */
    #include <map>
};

} // namespace logging

/* Convenience macros */
#define LOG_DEBUG(logger, msg) (logger)->log(logging::Level::Debug, msg, __FILE__, __LINE__)
#define LOG_INFO(logger, msg)  (logger)->log(logging::Level::Info, msg, __FILE__, __LINE__)
#define LOG_WARN(logger, msg)  (logger)->log(logging::Level::Warn, msg, __FILE__, __LINE__)
#define LOG_ERROR(logger, msg) (logger)->log(logging::Level::Error, msg, __FILE__, __LINE__)

#endif /* LOGGER_HPP */
