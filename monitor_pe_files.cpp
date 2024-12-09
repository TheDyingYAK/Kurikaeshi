#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <openssl/evp.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <chrono>
#include <ctime>

namespace fs = std::filesystem;
using namespace std;

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

// Generalized function to compute a hash using the EVP interface
string calculate_hash(const string& filepath, const EVP_MD* hash_algorithm) {
    unsigned char buffer[8192];
    unsigned char hash_result[EVP_MAX_MD_SIZE];
    unsigned int hash_length = 0;
    ifstream file(filepath, ios::binary);

    if (!file) {
        cerr << "Failed to open file: " << filepath << endl;
        return "";
    }

    // Create and initialize the digest context
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context) {
        cerr << "Failed to create digest context" << endl;
        return "";
    }

    // Initialize the digest operation
    if (EVP_DigestInit_ex(context, hash_algorithm, nullptr) != 1) {
        cerr << "Failed to initialize digest operation" << endl;
        EVP_MD_CTX_free(context);
        return "";
    }

    // Update the digest with file data
    while (file.read(reinterpret_cast<char*>(buffer), sizeof(buffer))) {
        if (EVP_DigestUpdate(context, buffer, file.gcount()) != 1) {
            cerr << "Failed to update digest" << endl;
            EVP_MD_CTX_free(context);
            return "";
        }
    }

    // Finalize the digest
    if (EVP_DigestFinal_ex(context, hash_result, &hash_length) != 1) {
        cerr << "Failed to finalize digest" << endl;
        EVP_MD_CTX_free(context);
        return "";
    }

    // Free the digest context
    EVP_MD_CTX_free(context);

    return bytes_to_hex(hash_result, hash_length);
}

// Wrapper functions for MD5, SHA-1, and SHA-256
string calculate_md5(const string& filepath) {
    return calculate_hash(filepath, EVP_md5());
}

string calculate_sha1(const string& filepath) {
    return calculate_hash(filepath, EVP_sha1());
}

string calculate_sha256(const string& filepath) {
    return calculate_hash(filepath, EVP_sha256());
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

    // Map to store watch descriptors and corresponding paths
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
                    } else if (filename.ends_with(".exe")) {
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
