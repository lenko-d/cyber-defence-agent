#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>

// Mock components for integration testing
class MockMonitor {
public:
    std::vector<std::string> getObservations() {
        return {
            "Normal system operation",
            "Network traffic within normal parameters",
            "CPU usage at 45%",
            "Memory usage at 60%"
        };
    }

    double getCpuUsage() { return 45.0; }
    double getMemoryUsage() { return 60.0; }
};

class MockDetector {
public:
    bool detectMalware(const std::vector<std::string>& observations) {
        for (const auto& obs : observations) {
            if (obs.find("suspicious") != std::string::npos ||
                obs.find("malware") != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    std::string classifyThreat(const std::string& observation) {
        if (observation.find("malware") != std::string::npos) {
            return "MALWARE";
        }
        return "NORMAL";
    }
};

class MockResponder {
public:
    void respondToThreat(const std::string& threat) {
        responses.push_back("Responded to: " + threat);
    }

    void quarantineMalware(const std::string& malware) {
        responses.push_back("Quarantined: " + malware);
    }

    void alertOperator(const std::string& alert) {
        responses.push_back("Alert sent: " + alert);
    }

    std::vector<std::string> responses;
};

// Integration test fixture
class IntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        monitor = std::make_unique<MockMonitor>();
        detector = std::make_unique<MockDetector>();
        responder = std::make_unique<MockResponder>();
    }

    void TearDown() override {
        monitor.reset();
        detector.reset();
        responder.reset();
    }

    std::unique_ptr<MockMonitor> monitor;
    std::unique_ptr<MockDetector> detector;
    std::unique_ptr<MockResponder> responder;
};

// Test basic integration flow
TEST_F(IntegrationTest, BasicIntegrationFlow) {
    // Get observations from monitor
    auto observations = monitor->getObservations();
    ASSERT_FALSE(observations.empty());

    // Check for threats using detector
    bool threatDetected = detector->detectMalware(observations);

    // Should not detect threats in normal observations
    ASSERT_FALSE(threatDetected);

    // Verify system metrics
    double cpuUsage = monitor->getCpuUsage();
    double memoryUsage = monitor->getMemoryUsage();

    ASSERT_GE(cpuUsage, 0.0);
    ASSERT_LE(cpuUsage, 100.0);
    ASSERT_GE(memoryUsage, 0.0);
    ASSERT_LE(memoryUsage, 100.0);
}

// Test threat detection and response integration
TEST_F(IntegrationTest, ThreatDetectionAndResponse) {
    // Create observations with threats
    std::vector<std::string> threatObservations = {
        "Normal system operation",
        "Suspicious network traffic detected",
        "Malware found in system",
        "CPU usage at 45%"
    };

    // Detect threats
    bool threatDetected = detector->detectMalware(threatObservations);
    ASSERT_TRUE(threatDetected);

    // Classify the threat
    std::string threatType = detector->classifyThreat("Malware found in system");
    ASSERT_EQ(threatType, "MALWARE");

    // Respond to threat
    responder->respondToThreat("Malware infection");
    responder->quarantineMalware("malicious_file.exe");
    responder->alertOperator("High priority security alert");

    // Verify responses were recorded
    ASSERT_EQ(responder->responses.size(), 3);
    ASSERT_EQ(responder->responses[0], "Responded to: Malware infection");
    ASSERT_EQ(responder->responses[1], "Quarantined: malicious_file.exe");
    ASSERT_EQ(responder->responses[2], "Alert sent: High priority security alert");
}

// Test concurrent monitoring and detection
TEST_F(IntegrationTest, ConcurrentMonitoringAndDetection) {
    std::atomic<bool> running(true);
    std::vector<std::string> shared_observations;
    std::mutex observations_mutex;

    // Monitoring thread
    std::thread monitor_thread([&]() {
        while (running) {
            auto obs = monitor->getObservations();
            std::lock_guard<std::mutex> lock(observations_mutex);
            shared_observations = obs;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });

    // Detection thread
    std::thread detection_thread([&]() {
        while (running) {
            std::lock_guard<std::mutex> lock(observations_mutex);
            if (!shared_observations.empty()) {
                bool threat = detector->detectMalware(shared_observations);
                // In normal observations, no threat should be detected
                ASSERT_FALSE(threat);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
        }
    });

    // Run for a short time
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    running = false;

    monitor_thread.join();
    detection_thread.join();

    SUCCEED();
}

// Test system performance under load
TEST_F(IntegrationTest, SystemPerformanceUnderLoad) {
    const int iterations = 100;
    auto start_time = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i) {
        // Simulate full monitoring-detection-response cycle
        auto observations = monitor->getObservations();
        bool threatDetected = detector->detectMalware(observations);

        if (threatDetected) {
            responder->respondToThreat("Test threat " + std::to_string(i));
        }

        // Small delay to prevent overwhelming the system
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    // Should complete within reasonable time (adjust threshold as needed)
    ASSERT_LT(duration.count(), 2000); // 2 seconds max for 100 iterations
}

// Test error handling in integration
TEST_F(IntegrationTest, ErrorHandlingIntegration) {
    // Test with empty observations
    std::vector<std::string> empty_observations;
    bool result = detector->detectMalware(empty_observations);
    ASSERT_FALSE(result);

    // Test with very large observation set
    std::vector<std::string> large_observations;
    for (int i = 0; i < 10000; ++i) {
        large_observations.push_back("Observation " + std::to_string(i));
    }

    // Should handle large datasets without crashing
    ASSERT_NO_THROW({
        detector->detectMalware(large_observations);
    });

    // Verify the large dataset was processed
    ASSERT_EQ(large_observations.size(), 10000);
}

// Test resource management
TEST_F(IntegrationTest, ResourceManagement) {
    // Create multiple component instances
    std::vector<std::unique_ptr<MockMonitor>> monitors;
    std::vector<std::unique_ptr<MockDetector>> detectors;
    std::vector<std::unique_ptr<MockResponder>> responders;

    const int num_instances = 10;

    // Create multiple instances
    for (int i = 0; i < num_instances; ++i) {
        monitors.push_back(std::make_unique<MockMonitor>());
        detectors.push_back(std::make_unique<MockDetector>());
        responders.push_back(std::make_unique<MockResponder>());
    }

    // Use the instances
    for (int i = 0; i < num_instances; ++i) {
        auto obs = monitors[i]->getObservations();
        bool threat = detectors[i]->detectMalware(obs);
        if (threat) {
            responders[i]->respondToThreat("Test threat");
        }
    }

    // Clear vectors (destructors should clean up resources)
    monitors.clear();
    detectors.clear();
    responders.clear();

    SUCCEED();
}

// Test data consistency across components
TEST_F(IntegrationTest, DataConsistency) {
    // Test that data flows correctly between components
    auto observations = monitor->getObservations();

    // Verify observations are not empty and contain expected data
    ASSERT_FALSE(observations.empty());
    ASSERT_GE(observations.size(), 4); // We expect at least 4 observations

    // Check that observations contain system metrics
    bool hasCpuInfo = false;
    bool hasMemoryInfo = false;

    for (const auto& obs : observations) {
        if (obs.find("CPU") != std::string::npos) {
            hasCpuInfo = true;
        }
        if (obs.find("Memory") != std::string::npos) {
            hasMemoryInfo = true;
        }
    }

    ASSERT_TRUE(hasCpuInfo);
    ASSERT_TRUE(hasMemoryInfo);
}

// Test component communication
TEST_F(IntegrationTest, ComponentCommunication) {
    // Simulate component communication through shared data
    std::vector<std::string> communication_log;

    // Monitor -> Detector communication
    auto observations = monitor->getObservations();
    communication_log.push_back("Monitor sent " + std::to_string(observations.size()) + " observations");

    // Detector -> Responder communication
    bool threatDetected = detector->detectMalware(observations);
    communication_log.push_back("Detector found threat: " + std::to_string(threatDetected));

    // Responder actions
    if (threatDetected) {
        responder->alertOperator("Threat detected");
        communication_log.push_back("Responder sent alert");
    }

    // Verify communication flow
    ASSERT_EQ(communication_log.size(), 2); // Monitor->Detector and Detector->Responder
    ASSERT_EQ(communication_log[0], "Monitor sent 4 observations");
    ASSERT_EQ(communication_log[1], "Detector found threat: 0");
}

// Test system recovery
TEST_F(IntegrationTest, SystemRecovery) {
    // Simulate system stress and recovery
    const int stress_iterations = 50;

    for (int i = 0; i < stress_iterations; ++i) {
        // Create stress by rapid component interactions
        auto observations = monitor->getObservations();
        bool threat = detector->detectMalware(observations);

        if (threat) {
            responder->respondToThreat("Stress test threat " + std::to_string(i));
        }

        // Small delay between iterations
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // Verify system is still functional after stress test
    auto final_observations = monitor->getObservations();
    ASSERT_FALSE(final_observations.empty());

    bool final_threat_check = detector->detectMalware(final_observations);
    // Should handle final check without issues
    (void)final_threat_check; // Suppress unused variable warning

    SUCCEED();
}

// Test boundary conditions
TEST_F(IntegrationTest, BoundaryConditions) {
    // Test with minimum valid data
    std::vector<std::string> minimal_observations = {"Single observation"};
    bool result = detector->detectMalware(minimal_observations);
    ASSERT_FALSE(result);

    // Test with maximum reasonable data
    std::vector<std::string> maximal_observations;
    for (int i = 0; i < 1000; ++i) {
        maximal_observations.push_back(std::string(1000, 'A')); // 1000 character strings
    }

    ASSERT_NO_THROW({
        detector->detectMalware(maximal_observations);
    });

    // Test with special characters
    std::vector<std::string> special_observations = {
        "Normal observation",
        "Special chars: !@#$%^&*()",
        "Unicode: 测试数据",
        "Empty string: ",
        "Very long string: " + std::string(10000, 'X')
    };

    ASSERT_NO_THROW({
        detector->detectMalware(special_observations);
    });
}

// Test performance metrics collection
TEST_F(IntegrationTest, PerformanceMetrics) {
    // Test that performance metrics can be collected during integration
    auto start_time = std::chrono::high_resolution_clock::now();

    // Perform operations
    for (int i = 0; i < 100; ++i) {
        auto observations = monitor->getObservations();
        detector->detectMalware(observations);
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);

    // Calculate operations per second
    double ops_per_second = 100.0 / (duration.count() / 1000000.0);

    // Should achieve reasonable performance
    ASSERT_GT(ops_per_second, 10.0); // At least 10 operations per second

    // Log performance for analysis
    std::cout << "Integration test performance: " << ops_per_second << " ops/sec" << std::endl;
}

// Test memory usage patterns
TEST_F(IntegrationTest, MemoryUsagePatterns) {
    // Test that memory usage remains stable during extended operation
    const int extended_iterations = 200;

    for (int i = 0; i < extended_iterations; ++i) {
        auto observations = monitor->getObservations();
        bool threat = detector->detectMalware(observations);

        if (threat) {
            responder->respondToThreat("Memory test threat");
        }

        // Periodic cleanup simulation
        if (i % 50 == 0) {
            // Simulate cleanup by clearing responder history
            responder->responses.clear();
        }
    }

    // Verify final state
    auto final_observations = monitor->getObservations();
    ASSERT_FALSE(final_observations.empty());

    SUCCEED();
}
