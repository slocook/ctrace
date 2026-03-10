// Test target for ctrace: simulates a real-time control loop at ~100Hz
// with occasional latency spikes from allocations and I/O.
// Includes C++ namespaced classes to test mangled symbol handling.
//
// Build: clang++ -O0 -g -o test_target tests/test_target.cpp
// Run:   ./test_target

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <pthread.h>
#include <thread>
#include <vector>
#include <unistd.h>

static std::atomic<bool> g_running{true};

// --- C++ namespaced classes to exercise symbol mangling ---

namespace engine {
namespace subsystem {

class Scheduler {
public:
    class TaskQueue {
    public:
        // Deeply nested method — produces a long mangled name
        int Dispatch(std::shared_ptr<int> task) {
            volatile int acc = 0;
            for (int i = 0; i < 1000; i++) {
                acc += i;
            }
            return acc;
        }
    };

    class MetricsCollector {
    public:
        void EmitCounters(int channel) {
            volatile double d = 0.0;
            for (int i = 0; i < 500; i++) {
                d += (double)i * 0.01;
            }
            (void)d;
        }
    };

    // Method with a tick-like name in a namespace
    void ProcessWorkItems(int iteration) {
        TaskQueue queue;
        auto t = std::make_shared<int>(iteration);
        queue.Dispatch(t);

        MetricsCollector mc;
        mc.EmitCounters(iteration % 4);
    }
};

} // namespace subsystem

namespace io {

class SensorBridge {
public:
    void UpdateState(double x, double y, double z) {
        volatile double mag = x * x + y * y + z * z;
        (void)mag;
    }

    int ReadRegister(int addr) {
        return addr * 42;
    }
};

} // namespace io
} // namespace engine

// --- Original free functions ---

// Background worker: does periodic computation
void worker_thread(const char* name) {
    pthread_setname_np(name);
    while (g_running.load()) {
        volatile double acc = 0.0;
        for (int i = 0; i < 10000; i++) {
            acc += (double)i * 0.001;
        }
        usleep(20000); // 20ms
    }
}

// I/O thread: periodic writes
void io_thread() {
    pthread_setname_np("io_worker");
    while (g_running.load()) {
        FILE* f = fopen("/dev/null", "w");
        if (f) {
            char buf[4096];
            memset(buf, 'B', sizeof(buf));
            fwrite(buf, 1, sizeof(buf), f);
            fclose(f);
        }
        usleep(50000); // 50ms
    }
}

// The "tick" function that ctrace_define_tick should target
void control_loop_tick(int iteration) {
    // Base work: ~1ms of computation
    volatile double acc = 0.0;
    for (int i = 0; i < 50000; i++) {
        acc += (double)i * 0.001;
    }

    // Every 10th tick: allocate and free (allocation pressure)
    if (iteration % 10 == 0) {
        std::vector<char*> allocs;
        for (int i = 0; i < 20; i++) {
            char* p = (char*)malloc(4096);
            memset(p, 0x42, 4096);
            allocs.push_back(p);
        }
        for (auto* p : allocs) {
            free(p);
        }
    }

    // Every 50th tick: do some I/O (write to /dev/null)
    if (iteration % 50 == 0) {
        FILE* f = fopen("/dev/null", "w");
        if (f) {
            char buf[8192];
            memset(buf, 'A', sizeof(buf));
            fwrite(buf, 1, sizeof(buf), f);
            fclose(f);
        }
    }

    // Every 200th tick: sleep to simulate a latency spike
    if (iteration % 200 == 0 && iteration > 0) {
        usleep(5000); // 5ms spike
    }

    // Exercise the C++ namespaced classes every tick
    engine::subsystem::Scheduler sched;
    sched.ProcessWorkItems(iteration);

    engine::io::SensorBridge bridge;
    bridge.UpdateState(1.0, 2.0, 9.8);
    bridge.ReadRegister(0x6A);
}

int main() {
    fprintf(stderr, "test_target: PID=%d, starting 100Hz control loop\n", getpid());
    fprintf(stderr, "test_target: will run for 60 seconds\n");

    // Spawn background threads
    std::thread t1(worker_thread, "compute_1");
    std::thread t2(worker_thread, "compute_2");
    std::thread t3(io_thread);

    auto start = std::chrono::steady_clock::now();
    int iteration = 0;

    while (true) {
        auto tick_start = std::chrono::steady_clock::now();

        control_loop_tick(iteration);

        // Check if 60 seconds have elapsed
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed >= 60) break;

        // Sleep to maintain ~100Hz
        auto tick_end = std::chrono::steady_clock::now();
        auto tick_dur = std::chrono::duration_cast<std::chrono::microseconds>(
            tick_end - tick_start).count();
        long sleep_us = 10000 - tick_dur; // 10ms period = 100Hz
        if (sleep_us > 0) {
            usleep(sleep_us);
        }

        iteration++;
    }

    g_running.store(false);
    t1.join();
    t2.join();
    t3.join();

    fprintf(stderr, "test_target: completed %d iterations\n", iteration);
    return 0;
}
