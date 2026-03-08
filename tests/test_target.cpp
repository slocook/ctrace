// Test target for ctrace: simulates a real-time control loop at ~100Hz
// with occasional latency spikes from allocations and I/O.
//
// Build: clang++ -O1 -g -o test_target tests/test_target.cpp
// Run:   ./test_target

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>
#include <unistd.h>

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
}

int main() {
    fprintf(stderr, "test_target: PID=%d, starting 100Hz control loop\n", getpid());
    fprintf(stderr, "test_target: will run for 60 seconds\n");

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

    fprintf(stderr, "test_target: completed %d iterations\n", iteration);
    return 0;
}
