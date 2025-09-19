#include "CDA.h"
#include <iostream>
#include <signal.h>
#include <atomic>

std::atomic<bool> running(true);

void signalHandler(int signum) {
    std::cout << "Interrupt signal (" << signum << ") received.\n";
    running = false;
}

int main() {
    // Register signal handler
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    std::cout << "Starting Cyber-defense Agent (CDA)" << std::endl;

    try {
        CDA::Agent agent;

        // Initialize the agent
        agent.initialize();

        // Start the agent
        agent.start();

        std::cout << "CDA Agent is running. Press Ctrl+C to stop." << std::endl;

        // Keep the main thread alive
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        // Shutdown the agent
        agent.shutdown();

        std::cout << "CDA Agent shutdown complete." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
