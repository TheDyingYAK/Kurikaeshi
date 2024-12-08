#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <chrono>
#include <ctime>

namespace fs = std::filesystem;
using namespace std; // Simplifies code readability

const string WATCH_DIR = "/home"; // Directory to monitor
const string LOG_FILE = "/var/log/pe_file_hashes.log";

// Helper function to convert hash bytes to a string
string bytes_to_hex(unsigned char* hash, size_t length) {
    string result;
    char buf[3];
    for (size_t i = 0; i < length; i++) {
        sprintf(buf, "%02x", hash[i]);
        result.append(buf);
    }
    return result;
}

// Function to calculate the MD5 hash of a file
string calculate_md5(const string& filepath) {
    unsigned char buffer[8192];
    unsigned char md5_result[MD5_DIGEST_LENGTH];
    ifstream file(filepath, ios::binary);

    if (!file) {
        cerr << "Failed to open file: " << filepath << endl;
        return "";
    }

    MD5_CTX md5_context;
    MD5_Init(&md5_context);

    while (file.read(reinterpret_cast<char*>(buffer), sizeof(buffer))) {
        MD5_Update(&md5_context, buffer, file.gcount());
    }

    MD5_Final(md5_result, &md5_context);
    return bytes_to_hex(md5_result, MD5_DIGEST_LENGTH);
}

// Function to calculate the SHA-1 hash of a file
string calculate_sha1(const string& filepath) {
    unsigned char buffer[8192];
    unsigned char sha1_result[SHA_DIGEST_LENGTH];
    ifstream file(filepath, ios::binary);

    if (!file) {
        cerr << "Failed to open file: " << filepath << endl;
        return "";
    }

    SHA_CTX sha1_context;
    SHA1_Init(&sha1_context);

    while (file.read(reinterpret_cast<char*>(buffer), sizeof(buffer))) {
        SHA1_Update(&sha1_context, buffer, file.gcount());
    }

    SHA1_Final(sha1_result, &sha1_context);
    return bytes_to_hex(sha1_result, SHA_DIGEST_LENGTH);
}

// Function to calculate the SHA-256 hash of a file
string calculate_sha256(const string& filepath) {
    unsigned char buffer[8192];
    unsigned char sha256_result[SHA256_DIGEST_LENGTH];
    ifstream file(filepath, ios::binary);

    if (!file) {
        cerr << "Failed to open file: " << filepath << endl;
        return "";
    }

    SHA256_CTX sha256_context;
    SHA256_Init(&sha256_context);

    while (file.read(reinterpret_cast<char*>(buffer), sizeof(buffer))) {
        SHA256_Update(&sha256_context, buffer, file.gcount());
    }

    SHA256_Final(sha256_result, &sha256_context);
    return bytes_to_hex(sha256_result, SHA256_DIGEST_LENGTH);
}

// Function to log hashes to a file
void log_hashes(const string& filepath, const string& md5_hash, const string& sha1_hash, const string& sha256_hash) {
    ofstream log(LOG_FILE, ios::app);
    if (log) {
        auto now = chrono::system_clock::to_time_t(chrono::system_clock::now());
        log << ctime(&now) << filepath << endl;
        log << "  MD5:    " << md5_hash << endl;
        log << "  SHA-1:  " << sha1_hash << endl;
        log << "  SHA-256:" << sha256_hash << endl;
    }
    else {
        cerr << "Failed to write to log file: " << LOG_FILE << endl;
    }
}

int main() {
    // Ensure the directory exists
    if (!fs::exists(WATCH_DIR)) {
        cerr << "Directory does not exist: " << WATCH_DIR << endl;
        return 1;
    }

    // Initialize inotify
    int inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init");
        return 1;
    }

    // Add watch to the directory
    int watch_descriptor = inotify_add_watch(inotify_fd, WATCH_DIR.c_str(), IN_CREATE);
    if (watch_descriptor < 0) {
        perror("inotify_add_watch");
        close(inotify_fd);
        return 1;
    }

    cout << "Monitoring directory: " << WATCH_DIR << endl;

    // Buffer to store inotify events
    constexpr size_t BUF_LEN = 1024 * (sizeof(struct inotify_event) + 16);
    char buffer[BUF_LEN];

    // Event loop
    while (true) {
        ssize_t length = read(inotify_fd, buffer, BUF_LEN);
        if (length < 0) {
            perror("read");
            break;
        }
                // Process inotify events
        for (char* ptr = buffer; ptr < buffer + length;) {
            struct inotify_event* event = reinterpret_cast<struct inotify_event*>(ptr);

            if (event->len > 0 && (event->mask & IN_CREATE)) {
                string filename(event->name);
                if (filename.ends_with(".exe")) {
                    string filepath = WATCH_DIR + "/" + filename;
                    cout << "New PE file detected: " << filepath << endl;

                    string md5_hash = calculate_md5(filepath);
                    string sha1_hash = calculate_sha1(filepath);
                    string sha256_hash = calculate_sha256(filepath);

                    if (!md5_hash.empty() && !sha1_hash.empty() && !sha256_hash.empty()) {
                        log_hashes(filepath, md5_hash, sha1_hash, sha256_hash);
                        cout << "Hashes recorded:" << endl;
                        cout << "  MD5:    " << md5_hash << endl;
                        cout << "  SHA-1:  " << sha1_hash << endl;
                        cout << "  SHA-256:" << sha256_hash << endl;
                    }
                }
            }

            ptr += sizeof(struct inotify_event) + event->len;
        }
    }

    // Cleanup
    inotify_rm_watch(inotify_fd, watch_descriptor);
    close(inotify_fd);

    return 0;
}
