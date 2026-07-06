/*
 * main.cpp - Logger library demo
 * Shows: classes, inheritance, RAII, mutex, templates, smart pointers
 */
#include "logger.hpp"
#include <thread>
#include <atomic>

using namespace logging;

/* Custom filter sink: only passes messages containing a keyword */
class FilterSink : public Sink {
public:
    FilterSink(std::shared_ptr<Sink> inner, const std::string& keyword)
        : inner_(std::move(inner)), keyword_(keyword) {}

    void write(const std::string& msg) override {
        if (msg.find(keyword_) != std::string::npos) {
            inner_->write(msg);
        }
    }

    void flush() override {
        inner_->flush();
    }

private:
    std::shared_ptr<Sink> inner_;
    std::string keyword_;
};

/* Demonstrate multi-threaded logging */
void worker(std::shared_ptr<Logger> logger, int id, int count) {
    for (int i = 0; i < count; i++) {
        std::ostringstream oss;
        oss << "Worker " << id << " iteration " << i;
        logger->info(oss.str());
    }
}

int main() {
    /* Create logger with console + file sinks */
    auto logger = std::make_shared<Logger>("app");

    auto console = std::make_shared<ConsoleSink>();
    console->set_level(Level::Info);
    logger->add_sink(console);

    /* Error-only console sink on stderr */
    auto err_console = std::make_shared<ConsoleSink>(true);
    err_console->set_level(Level::Error);
    logger->add_sink(err_console);

    /* Callback sink: count messages */
    std::atomic<int> msg_count{0};
    auto counter = std::make_shared<CallbackSink>(
        [&msg_count](Level, const std::string&) {
            msg_count++;
        }
    );
    logger->add_sink(counter);

    /* Basic logging */
    logger->set_level(Level::Debug);
    logger->debug("Application starting");
    logger->info("Configuration loaded");
    logger->warn("Deprecated API in use");
    logger->error("Connection timeout after 30s");

    /* Use macros with file/line info */
    LOG_INFO(logger, "Starting worker threads");

    /* Multi-threaded logging */
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; i++) {
        threads.emplace_back(worker, logger, i, 5);
    }

    for (auto& t : threads) {
        t.join();
    }

    LOG_INFO(logger, "All workers complete");

    /* JSON formatter demo */
    auto json_logger = std::make_shared<Logger>("json");
    json_logger->set_formatter(std::make_unique<JsonFormatter>());
    json_logger->add_sink(std::make_shared<ConsoleSink>());

    json_logger->info("Structured log message");
    json_logger->warn("Something might be wrong");

    /* Registry demo */
    auto& registry = Registry::instance();
    auto db_logger = registry.get("database");
    db_logger->add_sink(console);
    db_logger->info("Connected to PostgreSQL");
    db_logger->info("Query executed in 15ms");

    /* Filter sink demo */
    auto filtered = std::make_shared<FilterSink>(console, "ERROR");
    auto filter_logger = std::make_shared<Logger>("filtered");
    filter_logger->add_sink(filtered);
    filter_logger->info("This will be filtered out");
    filter_logger->error("ERROR: this passes the filter");

    logger->flush();
    std::cout << "\nTotal messages logged: " << msg_count.load() << std::endl;

    return 0;
}
