#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <openssl/md5.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <chrono>
#include <ctime>

namespace fs = std::filesystem;
using namespace std; // Remove the need for std::

const string WATCH_DIR = "/home"; // Directory to monitor
const string LOG_FILE = "/var/log/pe_file_hashes.log";

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

    char md5_string[2 * MD5_DIGEST_LENGTH + 1];
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(&md5_string[i * 2], "%02x", md5_result[i]);
    }

    return string(md5_string);
}

// Function to log to a file
void log_md5(const string& filepath, const string& md5_hash) {
    ofstream log(LOG_FILE, ios::app);
    if (log) {
        auto now = chrono::system_clock::to_time_t(chrono::system_clock::now());
        log << ctime(&now) << filepath << " - MD5: " << md5_hash << endl;
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
                    if (!md5_hash.empty()) {
                        log_md5(filepath, md5_hash);
                        cout << "MD5 hash recorded: " << md5_hash << endl;
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
