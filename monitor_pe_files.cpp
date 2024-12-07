// service to monitor for PE files being written to the users directory and then calculate the MD5 hash

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

using namespace std; // Remove
namespace fs = filesystem;

const string WATCH_DIR = "/home"; // Directory to monitor
const string LOG_FILE = "/var/log/pe_file_hashes.log";

// Function to calculate the MD5 hash of a file
string calculate_md5(const string& filepath) {
    unsigned char buffer[8192];
    unsigned char md5_results[MD5_DIGEST_LENGTH];
    ifstream file(filepath, ios::binary);

    if (!file) {
        cerr << "Failed toopen file: " << filepath << endl;
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
        sprintf(&md5_string[i * 2], "&02x", md5_result[i]);
    }

    return string(md5_string);
}

// Function to log to a file