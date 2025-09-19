#ifndef CDA_H
#define CDA_H

#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>

namespace CDA {

// Forward declarations
class Monitor;
class Detector;
class Responder;
class Planner;
class KnowledgeBase;
class CommunicationModule;
class PacketInspector;
class UpdateManager;

// Main CDA Agent class
class Agent {
public:
    Agent();
    ~Agent();

    // Core agent functions
    void initialize();
    void start();
    void stop();
    void shutdown();

    // Mission and goals
    void setMission(const std::string& mission);
    void addGoal(const std::string& goal);
    void addConstraint(const std::string& constraint);

    // Autonomous operation
    void assessSituation();
    void makeDecision();
    void executeAction();

    // Safety and robustness
    void checkSafety();
    void selfDefend();
    void recover();

    // Upgrade and remote control
    void checkForUpdates();
    void receiveRemoteCommand(const std::string& command);
    void restartAgent();

    // LLM integration
    bool analyzeWithLLM(const std::vector<std::string>& observations);

private:
    // Core components
    std::unique_ptr<Monitor> monitor_;
    std::unique_ptr<Detector> detector_;
    std::unique_ptr<PacketInspector> packetInspector_;
    std::unique_ptr<UpdateManager> updateManager_;
    std::unique_ptr<Responder> responder_;
    std::unique_ptr<Planner> planner_;
    std::unique_ptr<KnowledgeBase> knowledgeBase_;
    std::unique_ptr<CommunicationModule> commModule_;

    // Agent state
    std::atomic<bool> running_;
    std::string mission_;
    std::vector<std::string> goals_;
    std::vector<std::string> constraints_;
    std::atomic<int> threats_detected_;

    // Threads
    std::thread monitorThread_;
    std::thread decisionThread_;
    std::thread executionThread_;
    std::unique_ptr<std::thread> httpServerThread_;

    // HTTP server
    int serverSocket_;

    // Synchronization
    std::mutex stateMutex_;

    // Private methods
    void monitorLoop();
    void decisionLoop();
    void executionLoop();
    void startHttpServer();
    void handleHttpRequest(int client_socket);
    std::string handleStatusRequest();
    std::string handleCommandRequest(const std::string& request);
    std::string handleLogsRequest();
    void logEvent(const std::string& event);
};

// Component interfaces
class Monitor {
public:
    virtual ~Monitor() = default;
    virtual void startMonitoring() = 0;
    virtual void stopMonitoring() = 0;
    virtual std::vector<std::string> getObservations() = 0;
    virtual double getCpuUsage() = 0;
    virtual double getMemoryUsage() = 0;
};

class Detector {
public:
    virtual ~Detector() = default;
    virtual bool detectMalware(const std::vector<std::string>& observations) = 0;
    virtual std::string classifyThreat(const std::string& observation) = 0;
};

class Responder {
public:
    virtual ~Responder() = default;
    virtual void respondToThreat(const std::string& threat) = 0;
    virtual void quarantineMalware(const std::string& malware) = 0;
    virtual void alertOperator(const std::string& alert) = 0;
};

class Planner {
public:
    virtual ~Planner() = default;
    virtual std::vector<std::string> createPlan(const std::string& situation) = 0;
    virtual void assessPlan(const std::vector<std::string>& plan) = 0;
};

class KnowledgeBase {
public:
    virtual ~KnowledgeBase() = default;
    virtual void storeKnowledge(const std::string& key, const std::string& value) = 0;
    virtual std::string retrieveKnowledge(const std::string& key) = 0;
    virtual void learnFromExperience(const std::string& experience) = 0;
};

class CommunicationModule {
public:
    virtual ~CommunicationModule() = default;
    virtual void connectToBackend() = 0;
    virtual void sendData(const std::string& data) = 0;
    virtual std::string receiveData() = 0;
};

// Factory functions
std::unique_ptr<Monitor> createMonitor();
std::unique_ptr<Detector> createDetector();

} // namespace CDA

#endif // CDA_H
