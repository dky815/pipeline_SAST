#ifndef HELPER_FUNCTIONS_H
#define HELPER_FUNCTIONS_H

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <openssl/rand.h>
#include <regex>
#include <sstream>
#include <string>
#include <unistd.h>

#include "encryption/encryption.h"
#include "encryption/randomizer_function.h"

namespace fs = std::filesystem;

bool createDirectory(const fs::path& path) {
    std::error_code ec; // For error handling without exceptions
    if (fs::create_directory(path, ec)) {
        return true; // Directory created successfully
    } else {
        if (ec) { // Check if error code is set
            std::cerr << "Error creating directory: " << ec.message() << " (" << path << ")" << std::endl;
            return false;
        } else {
            std::cerr << "Directory already exists: " << path << std::endl;
            return true;
        }
    }
}

/// Normalize a path by removing trailing slashes and collapsing consecutive slashes to a single slash
/// \param path The path to normalize
std::string normalizePath(std::string path) {
    int n = path.length();
    int i = n - 1;
    while (i > 0 && path[i] == '/') {
        i--;
    }
    path.erase(i + 1, n - i - 1);
    if (path.length() > 1) {
        std::string::iterator it = std::unique(path.begin(), path.end(), [](char currentChar, char nextChar) {
            return currentChar == nextChar && currentChar == '/';
        });
        path.erase(it, path.end());
    }
    return path;
}

std::vector<uint8_t> readEncKeyFromMetadata(const std::string& userName, const std::string& directory) {
    const std::string metadataFilePath = !directory.empty() ? directory : "common/";
    std::ifstream metadataFile(metadataFilePath + userName + "_key", std::ios::in | std::ios::binary);

    if (!metadataFile) {
        std::cerr << "Failed to read key from metadata for " << userName << std::endl;
        return {}; // Return an empty vector if the file failed to open
    }

    std::vector<uint8_t> encryptionKey(KEY_SIZE);
    metadataFile.read(reinterpret_cast<char*>(encryptionKey.data()), encryptionKey.size());

    return encryptionKey;
}

bool isValidFilename(const std::string& filename) {
    std::regex validFilenamePattern(
        "^[a-zA-Z0-9](?:[a-zA-Z0-9 ._-]*[a-zA-Z0-9])?(\\.(?!$)[a-zA-Z0-9_-]+)+$"
        "|^([a-zA-Z0-9](?:[a-zA-Z0-9 ._-]*[a-zA-Z0-9])?)$"
    );
    const int MaxFilenameLength = 255;
    return std::regex_match(filename, validFilenamePattern) && (filename.length() <= MaxFilenameLength);
}

bool checkIfPersonalDirectory(const std::string& username, const std::string& pwd, const std::string& filesystemPath) {
    std::string userDirectory = FilenameRandomizer::GetRandomizedName("/filesystem/" + username, filesystemPath);
    std::string personalDirectory = FilenameRandomizer::GetRandomizedName("/filesystem/" + userDirectory + "/personal", filesystemPath);
    std::string authorizedWritePath = "/filesystem/" + userDirectory + "/" + personalDirectory;
    return (pwd.length() >= authorizedWritePath.length() &&
           pwd.substr(0, authorizedWritePath.length()) == authorizedWritePath);
}

std::string getUsernameFromPath(const std::string& path) {
    const std::string filesystemPrefix = "/filesystem/";
    if (path.size() <= filesystemPrefix.size()) return "";

    // Remove the filesystem prefix from the start of the path
    std::string withoutPrefix = path.substr(filesystemPrefix.size());

    // Find the next slash after the username
    size_t slashIndex = withoutPrefix.find('/');
    if (slashIndex != std::string::npos) {
        // If found, truncate the string to only include the username
        return withoutPrefix.substr(0, slashIndex);
    }

    // If no further slash is found, the remaining string is the username
    return withoutPrefix;
}

void createInitFsForUser(const std::string& username, const std::string& path) {
    mode_t old_umask = umask(0); // to ensure the following modes get set
    mode_t mode = 0700;

    std::string encrypted_username = FilenameRandomizer::EncryptFilename("/filesystem/" + username, path);
    std::string u_folder = path + "/filesystem/" + encrypted_username;
    if (mkdir(u_folder.c_str(), mode) != 0) {
        std::cerr << "Error creating root folder for " << username << std::endl;
    } else {
        std::string encrypted_p_folder = FilenameRandomizer::EncryptFilename("/filesystem/" + encrypted_username + "/personal", path);
        u_folder = path + "/filesystem/" + encrypted_username + "/" + encrypted_p_folder;
        if (mkdir(u_folder.c_str(), mode) != 0) {
            std::cerr << "Error creating personal folder for " << username << std::endl;
        }
        std::string encrypted_s_folder = FilenameRandomizer::EncryptFilename("/filesystem/" + encrypted_username + "/shared", path);
        u_folder = path + "/filesystem/" + encrypted_username + "/" + encrypted_s_folder;
        if (mkdir(u_folder.c_str(), mode) != 0) {
            std::cerr << "Error creating shared folder for " << username << std::endl;
        }
    }
    umask(old_umask); // Restore the original umask value
}

#endif // HELPER_FUNCTIONS_H
