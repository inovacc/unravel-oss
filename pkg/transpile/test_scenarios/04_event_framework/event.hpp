/*
 * event.hpp - Generic event-driven framework
 * Inspired by Boost.Signals2 / Qt signals
 *
 * Features: templates, CRTP, smart pointers, observer pattern,
 * type erasure, variadic templates, move semantics, RAII
 */
#ifndef EVENT_HPP
#define EVENT_HPP

#include <iostream>
#include <functional>
#include <vector>
#include <memory>
#include <mutex>
#include <algorithm>
#include <unordered_map>
#include <string>
#include <queue>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <typeindex>
#include <any>
#include <optional>
#include <chrono>

namespace event {

/* Unique connection ID */
using ConnectionId = uint64_t;

/* Base class for all events */
struct EventBase {
    virtual ~EventBase() = default;
    virtual std::type_index type() const = 0;
    virtual std::string name() const = 0;
};

/* Typed event with payload */
template<typename T>
struct Event : public EventBase {
    T data;

    explicit Event(T d) : data(std::move(d)) {}

    std::type_index type() const override {
        return std::type_index(typeid(T));
    }

    std::string name() const override {
        return typeid(T).name();
    }
};

/* Connection handle - RAII disconnect */
class Connection {
public:
    Connection() : id_(0), disconnect_fn_(nullptr) {}

    Connection(ConnectionId id, std::function<void()> disconnect)
        : id_(id), disconnect_fn_(std::move(disconnect)) {}

    ~Connection() = default;

    void disconnect() {
        if (disconnect_fn_) {
            disconnect_fn_();
            disconnect_fn_ = nullptr;
        }
    }

    ConnectionId id() const { return id_; }
    bool connected() const { return disconnect_fn_ != nullptr; }

private:
    ConnectionId id_;
    std::function<void()> disconnect_fn_;
};

/* Scoped connection - auto-disconnects on destruction */
class ScopedConnection {
public:
    ScopedConnection() = default;
    explicit ScopedConnection(Connection conn) : conn_(std::move(conn)) {}

    ~ScopedConnection() { conn_.disconnect(); }

    ScopedConnection(const ScopedConnection&) = delete;
    ScopedConnection& operator=(const ScopedConnection&) = delete;

    ScopedConnection(ScopedConnection&& other) noexcept
        : conn_(std::move(other.conn_)) {}

    ScopedConnection& operator=(ScopedConnection&& other) noexcept {
        if (this != &other) {
            conn_.disconnect();
            conn_ = std::move(other.conn_);
        }
        return *this;
    }

    Connection& get() { return conn_; }

private:
    Connection conn_;
};

/* Signal: type-safe event emitter with multiple subscribers */
template<typename... Args>
class Signal {
public:
    using SlotType = std::function<void(Args...)>;

    Signal() : next_id_(1) {}

    /* Connect a callback, returns connection handle */
    Connection connect(SlotType slot) {
        std::lock_guard<std::mutex> lock(mutex_);
        ConnectionId id = next_id_++;
        slots_[id] = std::move(slot);

        return Connection(id, [this, id]() {
            std::lock_guard<std::mutex> lock(mutex_);
            slots_.erase(id);
        });
    }

    /* Emit the signal, calling all connected slots */
    void emit(Args... args) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, slot] : slots_) {
            slot(args...);
        }
    }

    /* Operator() as emit alias */
    void operator()(Args... args) {
        emit(std::forward<Args>(args)...);
    }

    size_t slot_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return slots_.size();
    }

private:
    std::unordered_map<ConnectionId, SlotType> slots_;
    ConnectionId next_id_;
    mutable std::mutex mutex_;
};

/* Event bus: central pub/sub with type-erased handlers */
class EventBus {
public:
    template<typename T>
    Connection subscribe(std::function<void(const T&)> handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto type = std::type_index(typeid(T));
        ConnectionId id = next_id_++;

        handlers_[type].push_back({id, [handler](const std::any& event) {
            handler(std::any_cast<const T&>(event));
        }});

        return Connection(id, [this, type, id]() {
            std::lock_guard<std::mutex> lock(mutex_);
            auto& vec = handlers_[type];
            vec.erase(std::remove_if(vec.begin(), vec.end(),
                [id](const HandlerEntry& e) { return e.id == id; }),
                vec.end());
        });
    }

    template<typename T>
    void publish(const T& event) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto type = std::type_index(typeid(T));
        auto it = handlers_.find(type);
        if (it != handlers_.end()) {
            for (auto& entry : it->second) {
                entry.handler(event);
            }
        }
    }

    template<typename T, typename... Args>
    void publish(Args&&... args) {
        publish(T{std::forward<Args>(args)...});
    }

private:
    struct HandlerEntry {
        ConnectionId id;
        std::function<void(const std::any&)> handler;
    };

    std::unordered_map<std::type_index, std::vector<HandlerEntry>> handlers_;
    ConnectionId next_id_ = 1;
    std::mutex mutex_;
};

/* Async event queue with worker threads */
class EventQueue {
public:
    explicit EventQueue(size_t num_workers = 1)
        : running_(false), num_workers_(num_workers) {}

    ~EventQueue() {
        stop();
    }

    void start() {
        running_ = true;
        for (size_t i = 0; i < num_workers_; i++) {
            workers_.emplace_back([this]() { worker_loop(); });
        }
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            running_ = false;
        }
        cv_.notify_all();
        for (auto& t : workers_) {
            if (t.joinable())
                t.join();
        }
        workers_.clear();
    }

    void post(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            tasks_.push(std::move(task));
        }
        cv_.notify_one();
    }

    /* Post with delay */
    void post_delayed(std::function<void()> task,
                      std::chrono::milliseconds delay) {
        post([task = std::move(task), delay]() {
            std::this_thread::sleep_for(delay);
            task();
        });
    }

    size_t pending() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return tasks_.size();
    }

private:
    void worker_loop() {
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this]() {
                    return !running_ || !tasks_.empty();
                });

                if (!running_ && tasks_.empty())
                    return;

                task = std::move(tasks_.front());
                tasks_.pop();
            }
            task();
        }
    }

    std::queue<std::function<void()>> tasks_;
    std::vector<std::thread> workers_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> running_;
    size_t num_workers_;
};

/* CRTP mixin: make any class observable */
template<typename Derived>
class Observable {
public:
    using ChangeCallback = std::function<void(const Derived&)>;

    Connection on_change(ChangeCallback cb) {
        return signal_.connect([cb](const Derived& d) { cb(d); });
    }

protected:
    void notify_change() {
        signal_.emit(static_cast<const Derived&>(*this));
    }

private:
    Signal<const Derived&> signal_;
};

/* Timer: periodic or one-shot */
class Timer {
public:
    Timer() : running_(false) {}

    ~Timer() { stop(); }

    Timer(const Timer&) = delete;
    Timer& operator=(const Timer&) = delete;

    void start(std::chrono::milliseconds interval, bool repeat = true) {
        stop();
        running_ = true;
        thread_ = std::thread([this, interval, repeat]() {
            do {
                std::unique_lock<std::mutex> lock(mutex_);
                if (cv_.wait_for(lock, interval, [this]() { return !running_; }))
                    return;
                if (on_tick)
                    on_tick();
            } while (repeat && running_);
        });
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            running_ = false;
        }
        cv_.notify_all();
        if (thread_.joinable())
            thread_.join();
    }

    std::function<void()> on_tick;

private:
    std::thread thread_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> running_;
};

} // namespace event

#endif /* EVENT_HPP */
