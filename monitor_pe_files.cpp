#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <filesystem>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <cstring>

namespace fs = std::filesystem;
using namespace std;

// Function to calculate MD5 hash
string calculate_md5(const string& file_path) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5_context;

    ifstream file(file_path, ios::binary);
    if (!file) {
        cerr << "Error opening file for MD5: " << file_path << endl;
        return "";
    }

    MD5_Init(&md5_context);

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        MD5_Update(&md5_context, buffer, file.gcount());
    }

    MD5_Final(hash, &md5_context);

    stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// Function to calculate SHA-1 hash
string calculate_sha1(const string& file_path) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA_CTX sha1_context;

    ifstream file(file_path, ios::binary);
    if (!file) {
        cerr << "Error opening file for SHA-1: " << file_path << endl;
        return "";
    }

    SHA1_Init(&sha1_context);

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        SHA1_Update(&sha1_context, buffer, file.gcount());
    }

    SHA1_Final(hash, &sha1_context);

    stringstream ss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// Function to calculate SHA-256 hash
string calculate_sha256(const string& file_path) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_context;

    ifstream file(file_path, ios::binary);
    if (!file) {
        cerr << "Error opening file for SHA-256: " << file_path << endl;
        return "";
    }

    SHA256_Init(&sha256_context);

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        SHA256_Update(&sha256_context, buffer, file.gcount());
    }

    SHA256_Final(hash, &sha256_context);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// Function to log hashes to a file
void log_hashes(const string& file_path, const string& md5, const string& sha1, const string& sha256) {
    ofstream log_file("/var/log/monitor_pe_files.log", ios::app);
    if (!log_file) {
        cerr << "Error opening log file." << endl;
        return;
    }

    log_file << "File: " << file_path << endl;
    log_file << "MD5: " << md5 << endl;
    log_file << "SHA-1: " << sha1 << endl;
    log_file << "SHA-256: " << sha256 << endl;
    log_file << "----------------------------------------" << endl;
}

int main() {
    // Ensure the directories exist
    if (!fs::exists("/home") || !fs::exists("/root")) {
        cerr << "Required directories do not exist: /home or /root" << endl;
        return 1;
    }

    // Initialize inotify
    int inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init");
        return 1;
    }

    // Declare watch_descriptors map
    unordered_map<int, string> watch_descriptors;

    // Function to add a watch recursively
    auto add_watch_recursive = [&](const string& dir) {
        try {
            for (const auto& entry : fs::recursive_directory_iterator(dir)) {
                if (entry.is_directory()) {
                    int wd = inotify_add_watch(inotify_fd, entry.path().c_str(), IN_CREATE);
                    if (wd < 0) {
                        cerr << "Failed to add watch for: " << entry.path() << endl;
                    } else {
                        watch_descriptors[wd] = entry.path();
                    }
                }
            }
        } catch (const fs::filesystem_error& e) {
            cerr << "Filesystem error: " << e.what() << endl;
        }
    };

    // Add watches for /home and /root recursively
    add_watch_recursive("/home");
    add_watch_recursive("/root");

    cout << "Monitoring directories recursively under /home and /root" << endl;

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

            if (event->len > 0) {
                string filename = watch_descriptors[event->wd] + "/" + event->name;

                if (event->mask & IN_CREATE) {
                    if (fs::is_directory(filename)) {
                        // Add a watch for the newly created directory
                        int wd = inotify_add_watch(inotify_fd, filename.c_str(), IN_CREATE);
                        if (wd >= 0) {
                            watch_descriptors[wd] = filename;
                            cout << "Added watch for new directory: " << filename << endl;
                        } else {
                            cerr << "Failed to add watch for new directory: " << filename << endl;
                        }
                    } else if (filename.size() >= 4 && filename.substr(filename.size() - 4) == ".exe") {
                        cout << "New PE file detected: " << filename << endl;

                        string md5_hash = calculate_md5(filename);
                        string sha1_hash = calculate_sha1(filename);
                        string sha256_hash = calculate_sha256(filename);

                        if (!md5_hash.empty() && !sha1_hash.empty() && !sha256_hash.empty()) {
                            log_hashes(filename, md5_hash, sha1_hash, sha256_hash);
                            cout << "Hashes recorded:" << endl;
                            cout << "  MD5:    " << md5_hash << endl;
                            cout << "  SHA-1:  " << sha1_hash << endl;
                            cout << "  SHA-256:" << sha256_hash << endl;
                        }
                    }
                }
            }

            ptr += sizeof(struct inotify_event) + event->len;
        }
    }

    // Cleanup
    for (const auto& [wd, path] : watch_descriptors) {
        inotify_rm_watch(inotify_fd, wd);
    }
    close(inotify_fd);

    return 0;
}
