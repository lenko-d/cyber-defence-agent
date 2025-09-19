#include "UpdateManager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <archive.h>
#include <archive_entry.h>
#include <openssl/md5.h>
#include <algorithm>

namespace CDA {

UpdateManager::UpdateManager()
    : update_server_(DEFAULT_UPDATE_SERVER),
      current_version_("1.0.0"),
      update_interval_minutes_(60),
      auto_update_enabled_(false),
      update_in_progress_(false) {

    loadConfiguration();
    backup_path_ = fs::current_path() / BACKUP_DIR;
    fs::create_directories(backup_path_);
}

UpdateManager::~UpdateManager() {
    saveConfiguration();
}

UpdateStatus UpdateManager::checkForUpdates() {
    UpdateStatus status;
    status.current_version = current_version_;
    status.last_check_time = getCurrentTimeString();

    try {
        VersionInfo latest = fetchLatestVersion();
        status.latest_version = latest;

        // Compare versions
        if (compareVersions(latest.version, current_version_) > 0) {
            status.update_available = true;
            status.status_message = "Update available: " + latest.version;
        } else {
            status.update_available = false;
            status.status_message = "Agent is up to date";
        }

    } catch (const std::exception& e) {
        status.update_available = false;
        status.status_message = "Failed to check for updates: " + std::string(e.what());
        last_error_ = e.what();
    }

    return status;
}

bool UpdateManager::isUpdateAvailable() {
    UpdateStatus status = checkForUpdates();
    return status.update_available;
}

bool UpdateManager::downloadUpdate(const VersionInfo& version) {
    std::lock_guard<std::mutex> lock(update_mutex_);

    if (update_in_progress_) {
        last_error_ = "Update already in progress";
        return false;
    }

    update_in_progress_ = true;

    try {
        // Create temp directory
        fs::path temp_dir = fs::current_path() / TEMP_DIR;
        fs::create_directories(temp_dir);

        // Download update archive
        std::string archive_path = (temp_dir / "update.tar.gz").string();
        std::string download_result = downloadFile(version.download_url, archive_path);

        if (download_result.empty()) {
            last_error_ = "Failed to download update";
            update_in_progress_ = false;
            return false;
        }

        // Verify checksum
        if (!version.checksum.empty() && !verifyChecksum(archive_path, version.checksum)) {
            last_error_ = "Checksum verification failed";
            update_in_progress_ = false;
            return false;
        }

        update_in_progress_ = false;
        logUpdateEvent("Update downloaded successfully: " + version.version);
        return true;

    } catch (const std::exception& e) {
        last_error_ = std::string("Download failed: ") + e.what();
        update_in_progress_ = false;
        return false;
    }
}

bool UpdateManager::installUpdate(const VersionInfo& version) {
    std::lock_guard<std::mutex> lock(update_mutex_);

    if (update_in_progress_) {
        last_error_ = "Update already in progress";
        return false;
    }

    update_in_progress_ = true;

    try {
        // Create backup first
        if (!createBackup()) {
            last_error_ = "Failed to create backup";
            update_in_progress_ = false;
            return false;
        }

        // Extract update
        fs::path temp_dir = fs::current_path() / TEMP_DIR;
        fs::path extract_path = temp_dir / "extracted";
        std::string archive_path = (temp_dir / "update.tar.gz").string();

        if (!extractUpdate(archive_path, extract_path.string())) {
            last_error_ = "Failed to extract update";
            update_in_progress_ = false;
            return false;
        }

        // Replace files
        if (!replaceFiles(extract_path.string())) {
            last_error_ = "Failed to install update files";
            // Attempt rollback
            rollbackUpdate();
            update_in_progress_ = false;
            return false;
        }

        // Update version
        setCurrentVersion(version.version);

        // Cleanup
        cleanupTempFiles();

        update_in_progress_ = false;
        logUpdateEvent("Update installed successfully: " + version.version);
        return true;

    } catch (const std::exception& e) {
        last_error_ = std::string("Installation failed: ") + e.what();
        // Attempt rollback
        rollbackUpdate();
        update_in_progress_ = false;
        return false;
    }
}

bool UpdateManager::rollbackUpdate() {
    try {
        // Find latest backup
        std::vector<std::string> backups = getBackupList();
        if (backups.empty()) {
            last_error_ = "No backup available for rollback";
            return false;
        }

        // Use latest backup
        std::string latest_backup = backups.back();
        return restoreBackup(latest_backup);

    } catch (const std::exception& e) {
        last_error_ = std::string("Rollback failed: ") + e.what();
        return false;
    }
}

std::string UpdateManager::getCurrentVersion() {
    return current_version_;
}

void UpdateManager::setCurrentVersion(const std::string& version) {
    current_version_ = version;

    // Save to version file
    std::ofstream version_file(VERSION_FILE);
    if (version_file.is_open()) {
        version_file << version << std::endl;
    }

    config_["current_version"] = version;
    saveConfiguration();
}

void UpdateManager::setUpdateServer(const std::string& server_url) {
    update_server_ = server_url;
    config_["update_server"] = server_url;
    saveConfiguration();
}

void UpdateManager::setUpdateInterval(int minutes) {
    update_interval_minutes_ = minutes;
    config_["update_interval"] = std::to_string(minutes);
    saveConfiguration();
}

void UpdateManager::enableAutoUpdate(bool enable) {
    auto_update_enabled_ = enable;
    config_["auto_update"] = enable ? "true" : "false";
    saveConfiguration();
}

bool UpdateManager::createBackup() {
    return backupCurrentInstallation();
}

bool UpdateManager::restoreBackup(const std::string& backup_path) {
    try {
        fs::path backup_dir(backup_path);
        fs::path current_dir = fs::current_path();

        // Remove current files (except backup directory)
        for (const auto& entry : fs::directory_iterator(current_dir)) {
            if (entry.path().filename() != BACKUP_DIR) {
                if (fs::is_directory(entry)) {
                    fs::remove_all(entry);
                } else {
                    fs::remove(entry);
                }
            }
        }

        // Restore from backup
        for (const auto& entry : fs::directory_iterator(backup_dir)) {
            if (fs::is_directory(entry)) {
                copyDirectory(entry, current_dir / entry.path().filename());
            } else {
                fs::copy(entry, current_dir / entry.path().filename());
            }
        }

        logUpdateEvent("Backup restored: " + backup_path);
        return true;

    } catch (const std::exception& e) {
        last_error_ = std::string("Restore failed: ") + e.what();
        return false;
    }
}

std::string UpdateManager::getLastError() {
    return last_error_;
}

void UpdateManager::logUpdateEvent(const std::string& event) {
    std::ofstream log_file("update.log", std::ios::app);
    if (log_file.is_open()) {
        log_file << getCurrentTimeString() << " - " << event << std::endl;
    }
}

// Private methods

VersionInfo UpdateManager::fetchLatestVersion() {
    std::string url = update_server_ + "/latest-version.json";
    std::string response = httpGet(url);

    if (response.empty()) {
        throw std::runtime_error("Failed to fetch version information");
    }

    // Parse JSON response (simplified)
    VersionInfo version;
    // In a real implementation, parse JSON properly
    version.version = "1.1.0"; // Mock data
    version.release_date = getCurrentTimeString();
    version.changelog = "Bug fixes and security improvements";
    version.download_url = update_server_ + "/downloads/cda-agent-1.1.0.tar.gz";
    version.checksum = "mock_checksum";
    version.critical = false;

    return version;
}

bool UpdateManager::validateUpdate(const VersionInfo& version) {
    // Validate version format
    if (version.version.empty()) {
        return false;
    }

    // Validate download URL
    if (version.download_url.empty()) {
        return false;
    }

    return true;
}

bool UpdateManager::verifyChecksum(const std::string& file_path, const std::string& expected_checksum) {
    std::string actual_checksum = calculateMD5(file_path);
    return actual_checksum == expected_checksum;
}

bool UpdateManager::extractUpdate(const std::string& archive_path, const std::string& extract_path) {
    struct archive* a = archive_read_new();
    struct archive* ext = archive_write_disk_new();

    archive_read_support_format_tar(a);
    archive_read_support_filter_gzip(a);
    archive_read_support_format_tar(a);

    archive_write_disk_set_options(ext, ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS);

    if (archive_read_open_filename(a, archive_path.c_str(), 10240) != ARCHIVE_OK) {
        return false;
    }

    fs::create_directories(extract_path);

    for (;;) {
        struct archive_entry* entry;
        int r = archive_read_next_header(a, &entry);
        if (r == ARCHIVE_EOF) break;
        if (r != ARCHIVE_OK) return false;

        const char* current_file = archive_entry_pathname(entry);
        std::string full_output_path = extract_path + "/" + current_file;
        archive_entry_set_pathname(entry, full_output_path.c_str());

        r = archive_write_header(ext, entry);
        if (r != ARCHIVE_OK) return false;

        if (archive_entry_size(entry) > 0) {
            const void* buff;
            size_t size;
            int64_t offset;

            for (;;) {
                r = archive_read_data_block(a, &buff, &size, &offset);
                if (r == ARCHIVE_EOF) break;
                if (r != ARCHIVE_OK) return false;
                archive_write_data(ext, buff, size);
            }
        }

        archive_write_finish_entry(ext);
    }

    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);

    return true;
}

bool UpdateManager::replaceFiles(const std::string& new_files_path) {
    try {
        fs::path source(new_files_path);
        fs::path destination = fs::current_path();

        // Copy new files
        for (const auto& entry : fs::recursive_directory_iterator(source)) {
            fs::path relative_path = fs::relative(entry.path(), source);
            fs::path dest_path = destination / relative_path;

            if (fs::is_directory(entry)) {
                fs::create_directories(dest_path);
            } else {
                fs::copy(entry, dest_path, fs::copy_options::overwrite_existing);
            }
        }

        return true;

    } catch (const std::exception& e) {
        last_error_ = std::string("File replacement failed: ") + e.what();
        return false;
    }
}

bool UpdateManager::cleanupTempFiles() {
    try {
        fs::path temp_dir = fs::current_path() / TEMP_DIR;
        if (fs::exists(temp_dir)) {
            fs::remove_all(temp_dir);
        }
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

std::string UpdateManager::createBackupName() {
    std::time_t now = std::time(nullptr);
    char buffer[20];
    std::strftime(buffer, sizeof(buffer), "%Y%m%d_%H%M%S", std::localtime(&now));
    return std::string("backup_") + buffer + "_" + current_version_;
}

bool UpdateManager::backupCurrentInstallation() {
    try {
        std::string backup_name = createBackupName();
        fs::path backup_dir = fs::path(backup_path_) / backup_name;
        fs::path current_dir = fs::current_path();

        fs::create_directories(backup_dir);

        // Copy all files except backup directory
        for (const auto& entry : fs::directory_iterator(current_dir)) {
            if (entry.path().filename() != BACKUP_DIR) {
                if (fs::is_directory(entry)) {
                    copyDirectory(entry, backup_dir / entry.path().filename());
                } else {
                    fs::copy(entry, backup_dir / entry.path().filename());
                }
            }
        }

        logUpdateEvent("Backup created: " + backup_name);
        return true;

    } catch (const std::exception& e) {
        last_error_ = std::string("Backup failed: ") + e.what();
        return false;
    }
}

std::vector<std::string> UpdateManager::getBackupList() {
    std::vector<std::string> backups;

    if (!fs::exists(backup_path_)) {
        return backups;
    }

    for (const auto& entry : fs::directory_iterator(backup_path_)) {
        if (fs::is_directory(entry)) {
            backups.push_back(entry.path().string());
        }
    }

    std::sort(backups.begin(), backups.end());
    return backups;
}

std::string UpdateManager::downloadFile(const std::string& url, const std::string& destination) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return "";
    }

    FILE* fp = fopen(destination.c_str(), "wb");
    if (!fp) {
        curl_easy_cleanup(curl);
        return "";
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, nullptr);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // For development only

    CURLcode res = curl_easy_perform(curl);

    fclose(fp);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        return "";
    }

    return destination;
}

std::string UpdateManager::httpGet(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return "";
    }

    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // For development only

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        return "";
    }

    return response;
}

size_t UpdateManager::writeCallback(void* contents, size_t size, size_t nmemb, std::string* response) {
    size_t total_size = size * nmemb;
    response->append(static_cast<char*>(contents), total_size);
    return total_size;
}

bool UpdateManager::copyDirectory(const fs::path& source, const fs::path& destination) {
    try {
        fs::create_directories(destination);

        for (const auto& entry : fs::recursive_directory_iterator(source)) {
            fs::path relative_path = fs::relative(entry.path(), source);
            fs::path dest_path = destination / relative_path;

            if (fs::is_directory(entry)) {
                fs::create_directories(dest_path);
            } else {
                fs::copy(entry, dest_path, fs::copy_options::overwrite_existing);
            }
        }

        return true;

    } catch (const std::exception& e) {
        return false;
    }
}

bool UpdateManager::removeDirectory(const fs::path& path) {
    try {
        if (fs::exists(path)) {
            fs::remove_all(path);
        }
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

std::string UpdateManager::calculateMD5(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }

    MD5_CTX md5_ctx;
    MD5_Init(&md5_ctx);

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        MD5_Update(&md5_ctx, buffer, file.gcount());
    }
    MD5_Update(&md5_ctx, buffer, file.gcount());

    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_Final(hash, &md5_ctx);

    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}

void UpdateManager::loadConfiguration() {
    std::ifstream config_file("update_config.txt");
    if (config_file.is_open()) {
        std::string line;
        while (std::getline(config_file, line)) {
            size_t pos = line.find('=');
            if (pos != std::string::npos) {
                std::string key = line.substr(0, pos);
                std::string value = line.substr(pos + 1);
                config_[key] = value;

                if (key == "current_version") current_version_ = value;
                else if (key == "update_server") update_server_ = value;
                else if (key == "update_interval") update_interval_minutes_ = std::stoi(value);
                else if (key == "auto_update") auto_update_enabled_ = (value == "true");
            }
        }
    }
}

void UpdateManager::saveConfiguration() {
    std::ofstream config_file("update_config.txt");
    if (config_file.is_open()) {
        for (const auto& pair : config_) {
            config_file << pair.first << "=" << pair.second << std::endl;
        }
    }
}

std::string UpdateManager::getCurrentTimeString() {
    std::time_t now = std::time(nullptr);
    char buffer[30];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    return buffer;
}

int UpdateManager::compareVersions(const std::string& v1, const std::string& v2) {
    // Simple version comparison (can be enhanced)
    std::vector<int> v1_parts, v2_parts;

    std::istringstream iss1(v1);
    std::string token;
    while (std::getline(iss1, token, '.')) {
        v1_parts.push_back(std::stoi(token));
    }

    std::istringstream iss2(v2);
    while (std::getline(iss2, token, '.')) {
        v2_parts.push_back(std::stoi(token));
    }

    size_t max_size = std::max(v1_parts.size(), v2_parts.size());
    v1_parts.resize(max_size, 0);
    v2_parts.resize(max_size, 0);

    for (size_t i = 0; i < max_size; ++i) {
        if (v1_parts[i] > v2_parts[i]) return 1;
        if (v1_parts[i] < v2_parts[i]) return -1;
    }

    return 0;
}

} // namespace CDA
