/*
 * main.cpp - Event framework demo
 * Shows: templates, CRTP, smart pointers, observer, async queue, timer
 */
#include "event.hpp"
#include <cassert>

using namespace event;

/* Domain events */
struct UserLogin {
    std::string username;
    std::string ip_address;
};

struct OrderPlaced {
    int order_id;
    double amount;
    std::string currency;
};

struct SystemAlert {
    std::string severity;
    std::string message;
};

/* Observable config using CRTP */
class AppConfig : public Observable<AppConfig> {
public:
    void set_debug(bool debug) {
        debug_ = debug;
        notify_change();
    }

    void set_max_connections(int max) {
        max_connections_ = max;
        notify_change();
    }

    bool debug() const { return debug_; }
    int max_connections() const { return max_connections_; }

    friend std::ostream& operator<<(std::ostream& os, const AppConfig& c) {
        return os << "Config{debug=" << c.debug_
                  << ", max_connections=" << c.max_connections_ << "}";
    }

private:
    bool debug_ = false;
    int max_connections_ = 100;
};

int main() {
    std::cout << "=== Signal Demo ===" << std::endl;
    {
        Signal<int, const std::string&> on_message;

        auto conn1 = on_message.connect([](int id, const std::string& msg) {
            std::cout << "Handler 1: [" << id << "] " << msg << std::endl;
        });

        auto conn2 = on_message.connect([](int id, const std::string& msg) {
            std::cout << "Handler 2: [" << id << "] " << msg << std::endl;
        });

        on_message.emit(1, "Hello Signal");
        on_message(2, "Operator() syntax");

        std::cout << "Connected slots: " << on_message.slot_count() << std::endl;
        conn1.disconnect();
        std::cout << "After disconnect: " << on_message.slot_count() << std::endl;

        on_message.emit(3, "Only handler 2 receives this");
    }

    std::cout << "\n=== Scoped Connection Demo ===" << std::endl;
    {
        Signal<std::string> on_event;
        {
            ScopedConnection sc(on_event.connect([](const std::string& s) {
                std::cout << "Scoped handler: " << s << std::endl;
            }));
            on_event.emit("inside scope");
        } // auto-disconnects here
        on_event.emit("outside scope - no handler");
        std::cout << "Slots after scope: " << on_event.slot_count() << std::endl;
    }

    std::cout << "\n=== Event Bus Demo ===" << std::endl;
    {
        EventBus bus;

        auto login_conn = bus.subscribe<UserLogin>(
            [](const UserLogin& e) {
                std::cout << "User logged in: " << e.username
                          << " from " << e.ip_address << std::endl;
            }
        );

        auto order_conn = bus.subscribe<OrderPlaced>(
            [](const OrderPlaced& e) {
                std::cout << "Order #" << e.order_id
                          << ": " << e.amount << " " << e.currency << std::endl;
            }
        );

        int alert_count = 0;
        auto alert_conn = bus.subscribe<SystemAlert>(
            [&alert_count](const SystemAlert& e) {
                alert_count++;
                std::cout << "[" << e.severity << "] " << e.message << std::endl;
            }
        );

        bus.publish(UserLogin{"alice", "192.168.1.1"});
        bus.publish(UserLogin{"bob", "10.0.0.5"});
        bus.publish(OrderPlaced{1001, 99.99, "USD"});
        bus.publish(SystemAlert{"WARN", "High memory usage"});
        bus.publish(SystemAlert{"ERROR", "Database connection lost"});

        std::cout << "Alert count: " << alert_count << std::endl;

        login_conn.disconnect();
        bus.publish(UserLogin{"charlie", "172.16.0.1"}); // no handler
    }

    std::cout << "\n=== Observable Config (CRTP) ===" << std::endl;
    {
        AppConfig config;

        auto conn = config.on_change([](const AppConfig& c) {
            std::cout << "Config changed: " << c << std::endl;
        });

        config.set_debug(true);
        config.set_max_connections(200);

        conn.disconnect();
        config.set_debug(false); // no notification
    }

    std::cout << "\n=== Async Event Queue ===" << std::endl;
    {
        EventQueue queue(2);
        queue.start();

        std::atomic<int> processed{0};
        std::mutex cout_mutex;

        for (int i = 0; i < 10; i++) {
            queue.post([i, &processed, &cout_mutex]() {
                {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cout << "Task " << i << " executed on thread "
                              << std::this_thread::get_id() << std::endl;
                }
                processed++;
            });
        }

        /* Wait for all tasks to complete */
        while (processed.load() < 10) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        queue.stop();
        std::cout << "Processed: " << processed.load() << " tasks" << std::endl;
    }

    std::cout << "\n=== Timer Demo ===" << std::endl;
    {
        Timer timer;
        std::atomic<int> ticks{0};

        timer.on_tick = [&ticks]() {
            ticks++;
            std::cout << "Tick " << ticks.load() << std::endl;
        };

        timer.start(std::chrono::milliseconds(100), true);
        std::this_thread::sleep_for(std::chrono::milliseconds(350));
        timer.stop();

        std::cout << "Total ticks: " << ticks.load() << std::endl;
    }

    std::cout << "\nAll demos complete." << std::endl;
    return 0;
}
