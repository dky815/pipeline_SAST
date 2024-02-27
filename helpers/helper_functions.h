/*
* Helper functions needed across the code.
*/

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

/// Helper function to create a new directory
/// \param path Path for creating dir
bool createDirectory(const fs::path& path) {
    std::error_code ec;
    if (fs::create_directory(path, ec)) {
        return true;
    } else {
        if (ec) {
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
    std::string encryptedUsername = FilenameRandomizer::EncryptFilename("/filesystem/" + username, path);
    fs::path userDir = fs::path(path) / "filesystem" / encryptedUsername;
    if (!createDirectory(userDir)) {
        std::cerr << "Error creating root folder for " << username << std::endl;
        return;
    }
    
    std::string encryptedPersonalFolder = FilenameRandomizer::EncryptFilename("/filesystem/" + encryptedUsername + "/personal", path);
    fs::path personalDir = userDir / encryptedPersonalFolder;
    if (!createDirectory(personalDir)) {
        std::cerr << "Error creating personal folder for " << username << std::endl;
    }
    
    std::string encryptedSharedFolder = FilenameRandomizer::EncryptFilename("/filesystem/" + encryptedUsername + "/shared", path);
    fs::path sharedDir = userDir / encryptedSharedFolder;
    if (!createDirectory(sharedDir)) {
        std::cerr << "Error creating shared folder for " << username << std::endl;
    }
}


#endif // HELPER_FUNCTIONS_H
