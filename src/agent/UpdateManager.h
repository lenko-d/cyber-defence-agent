#ifndef UPDATE_MANAGER_H
#define UPDATE_MANAGER_H

#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <filesystem>
#include <unordered_map>

namespace fs = std::filesystem;

namespace CDA {

struct VersionInfo {
    std::string version;
    std::string release_date;
    std::string changelog;
    std::string download_url;
    std::string checksum;
    bool critical;
};

struct UpdateStatus {
    bool update_available;
    VersionInfo latest_version;
    std::string current_version;
    std::string last_check_time;
    std::string status_message;
};

class UpdateManager {
public:
    UpdateManager();
    ~UpdateManager();

    // Update checking
    UpdateStatus checkForUpdates();
    bool isUpdateAvailable();

    // Update installation
    bool downloadUpdate(const VersionInfo& version);
    bool installUpdate(const VersionInfo& version);
    bool rollbackUpdate();

    // Version management
    std::string getCurrentVersion();
    void setCurrentVersion(const std::string& version);

    // Configuration
    void setUpdateServer(const std::string& server_url);
    void setUpdateInterval(int minutes);
    void enableAutoUpdate(bool enable);

    // Backup and recovery
    bool createBackup();
    bool restoreBackup(const std::string& backup_path);

    // Status and logging
    std::string getLastError();
    void logUpdateEvent(const std::string& event);

private:
    // Helper functions
    std::string getCurrentTimeString();
    int compareVersions(const std::string& v1, const std::string& v2);
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* response);
    std::string update_server_;
    std::string current_version_;
    std::string backup_path_;
    int update_interval_minutes_;
    bool auto_update_enabled_;
    std::atomic<bool> update_in_progress_;

    std::mutex update_mutex_;
    std::string last_error_;

    // Update process
    VersionInfo fetchLatestVersion();
    bool validateUpdate(const VersionInfo& version);
    bool verifyChecksum(const std::string& file_path, const std::string& expected_checksum);
    bool extractUpdate(const std::string& archive_path, const std::string& extract_path);
    bool replaceFiles(const std::string& new_files_path);
    bool cleanupTempFiles();

    // Backup management
    std::string createBackupName();
    bool backupCurrentInstallation();
    std::vector<std::string> getBackupList();

    // Network operations
    std::string downloadFile(const std::string& url, const std::string& destination);
    std::string httpGet(const std::string& url);

    // File operations
    bool copyDirectory(const fs::path& source, const fs::path& destination);
    bool removeDirectory(const fs::path& path);
    std::string calculateMD5(const std::string& file_path);

    // Configuration
    void loadConfiguration();
    void saveConfiguration();
    std::unordered_map<std::string, std::string> config_;

    // Constants
    static constexpr const char* DEFAULT_UPDATE_SERVER = "https://updates.aica-agent.com";
    static constexpr const char* VERSION_FILE = "version.txt";
    static constexpr const char* BACKUP_DIR = "backups";
    static constexpr const char* TEMP_DIR = "temp";
};

} // namespace CDA

#endif // UPDATE_MANAGER_H
