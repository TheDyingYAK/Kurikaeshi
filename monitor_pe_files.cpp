#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <filesystem>
#include <openssl/evp.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <cstring>
#include <iomanip>

namespace fs = std::filesystem;
using namespace std;

// Function to calculate MD5 hash
string calculate_md5(const string& file_path) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_length;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        cerr << "Failed to create MD5 context" << endl;
        return "";
    }

    ifstream file(file_path, ios::binary);
    if (!file) {
        cerr << "Error opening file for MD5: " << file_path << endl;
        EVP_MD_CTX_free(md_ctx);
        return "";
    }

    if (EVP_DigestInit_ex(md_ctx, EVP_md5(), nullptr) != 1) {
        cerr << "Failed to initialize MD5 context" << endl;
        EVP_MD_CTX_free(md_ctx);
        return "";
    }

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        if (EVP_DigestUpdate(md_ctx, buffer, file.gcount()) != 1) {
            cerr << "Failed to update MD5 hash" << endl;
            EVP_MD_CTX_free(md_ctx);
            return "";
        }
    }

    if (EVP_DigestFinal_ex(md_ctx, hash, &hash_length) != 1) {
        cerr << "Failed to finalize MD5 hash" << endl;
        EVP_MD_CTX_free(md_ctx);
        return "";
    }

    EVP_MD_CTX_free(md_ctx);

    stringstream ss;
    for (unsigned int i = 0; i < hash_length; ++i) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// Function to calculate SHA-1 hash
string calculate_sha1(const string& file_path) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_length;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        cerr << "Failed to create SHA-1 context" << endl;
        return "";
    }

    ifstream file(file_path, ios::binary);
    if (!file) {
        cerr << "Error opening file for SHA-1: " << file_path << endl;
        EVP_MD_CTX_free(md_ctx);
        return "";
    }

    if (EVP_DigestInit_ex(md_ctx, EVP_sha1(), nullptr) != 1) {
        cerr << "Failed to initialize SHA-1 context" << endl;
        EVP_MD_CTX_free(md_ctx);
        return "";
    }

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        if (EVP_DigestUpdate(md_ctx, buffer, file.gcount()) != 1) {
            cerr << "Failed to update SHA-1 hash" << endl;
            EVP_MD_CTX_free(md_ctx);
            return "";
        }
    }

    if (EVP_DigestFinal_ex(md_ctx, hash, &hash_length) != 1) {
        cerr << "Failed to finalize SHA-1 hash" << endl;
        EVP_MD_CTX_free(md_ctx);
        return "";
    }

    EVP_MD_CTX_free(md_ctx);

    stringstream ss;
    for (unsigned int i = 0; i < hash_length; ++i) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// Function to calculate SHA-256 hash
string calculate_sha256(const string& file_path) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_length;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        cerr << "Failed to create SHA-256 context" << endl;
        return "";
    }

    ifstream file(file_path, ios::binary);
    if (!file) {
        cerr << "Error opening file for SHA-256: " << file_path << endl;
        EVP_MD_CTX_free(md_ctx);
        return "";
    }

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr) != 1) {
        cerr << "Failed to initialize SHA-256 context" << endl;
        EVP_MD_CTX_free(md_ctx);
        return "";
    }

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        if (EVP_DigestUpdate(md_ctx, buffer, file.gcount()) != 1) {
            cerr << "Failed to update SHA-256 hash" << endl;
            EVP_MD_CTX_free(md_ctx);
            return "";
        }
    }

    if (EVP_DigestFinal_ex(md_ctx, hash, &hash_length) != 1) {
        cerr << "Failed to finalize SHA-256 hash" << endl;
        EVP_MD_CTX_free(md_ctx);
        return "";
    }

    EVP_MD_CTX_free(md_ctx);

    stringstream ss;
    for (unsigned int i = 0; i < hash_length; ++i) {
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
    int inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init");
        return 1;
    }

    unordered_map<int, string> watch_descriptors;

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

    add_watch_recursive("/home");
    add_watch_recursive("/root");

    constexpr size_t BUF_LEN = 1024 * (sizeof(struct inotify_event) + 16);
    char buffer[BUF_LEN];

    while (true) {
        ssize_t length = read(inotify_fd, buffer, BUF_LEN);
        if (length < 0) {
            perror("read");
            break;
        }

        for (char* ptr = buffer; ptr < buffer + length;) {
            struct inotify_event* event = reinterpret_cast<struct inotify_event*>(ptr);
            if (event->len > 0) {
                string filename = watch_descriptors[event->wd] + "/" + event->name;
                if (event->mask & IN_CREATE && filename.ends_with(".exe")) {
                    string md5 = calculate_md5(filename);
                    string sha1 = calculate_sha1(filename);
                    string sha256 = calculate_sha256(filename);
                    log_hashes(filename, md5, sha1, sha256);
                }
            }
            ptr += sizeof(struct inotify_event) + event->len;
        }
    }

    for (const auto& [wd, path] : watch_descriptors) {
        inotify_rm_watch(inotify_fd, wd);
    }
    close(inotify_fd);

    return 0;
}
