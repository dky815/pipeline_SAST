/*
* Helper functions needed for file operations/features.
*/

#ifndef FEATURES_HELPERS_H
#define FEATURES_HELPERS_H

#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <vector>

#include "encryption/randomizer_function.h"
#include "authentication/authentication.h"
#include "helpers/helper_functions.h"

namespace fs = std::filesystem;

fs::path adminRootPath = fs::current_path() / "filesystem";
fs::path userRootPath = fs::current_path() / "filesystem";
fs::path rootPath;

std::string getCustomPWD(const std::string& basePath) {
    std::string currentPath = fs::current_path().string();
    return currentPath.erase(1, basePath.length());
}

bool doesFileExist(const std::string& randomizedFilename) {
    if (!fs::exists(randomizedFilename)) {
        std::cout << "File does not exist" << std::endl;
        return false;
    }
    fs::file_status status = fs::status(randomizedFilename);
    if (status.type() == fs::file_type::directory) {
        std::cerr << "File does not exist" << std::endl;
        return false;
    }
    return true;
}

bool doesUserExist(const std::string& username, const std::string& filesystemPath) {
    std::string path = filesystemPath + "/key/public_keys";
    for (const fs::directory_entry& entry : fs::directory_iterator(path)) {
        std::string entryPath = entry.path();
        entryPath.erase(entryPath.size() - 4);
        int deleteUpto = entryPath.find_last_of('/') + 1;
        entryPath.erase(0, deleteUpto);
        if (username == entryPath) {
            return true;
        }
    }
    std::cout << "User " << username << " does not exist!" << std::endl;
    return false;
}

std::string getRandomizedUserDirectory(const std::string& username, const std::string& filesystemPath) {
    return FilenameRandomizer::GetRandomizedName("/filesystem/" + username, filesystemPath);
}

std::string getRandomizedSharedDirectory(const std::string& randomizedUserDirectory, const std::string& filesystemPath) {
    return FilenameRandomizer::GetRandomizedName("/filesystem/" + randomizedUserDirectory + "/shared", filesystemPath);
}

// Parses the contents of the shared file to extract usernames and keys.
void parseFileContents(std::ifstream& file, std::vector<std::string>& keys, std::vector<std::string>& usernames) {
  std::string line;
  while (std::getline(file, line)) {
    size_t pos = line.find(":");
    if (pos != std::string::npos) {
      std::string username = line.substr(0, pos);
      std::string key = line.substr(pos + 1);
      usernames.push_back(username);
      keys.push_back(key);
    }
  }
}

// Updates shared files with encrypted content for each user specified in the usernames vector
void updateSharedFiles(std::vector<std::string> keys, std::vector<std::string> usernames, std::string randomizedFilename, std::string filesystemPath, std::string content) {
    for (int i = 0; i < keys.size(); i++) {
        std::string key = keys[i];
        std::string sharedRandomizedFilename = FilenameRandomizer::GetRandomizedName(key, filesystemPath);

        int lastOccurence = key.find_last_of('/');
        key.erase(lastOccurence + 1, key.length());

        std::string shareUserPath = filesystemPath + key + sharedRandomizedFilename;
        std::vector<uint8_t> shareKey = readEncKeyFromMetadata(usernames[i], filesystemPath + "/common/");
        
        // Encrypt the file at the specified path with the provided content using the user's encryption key
        Encryption::encryptFile(shareUserPath, content, shareKey);
    }
}

// Checks if a file is shared, and if so, updates shared files accordingly.
void checkIfShared(std::string randomizedFilename, std::string filesystemPath, std::string content) {
  // Construct the filepath to the shared file directory
  std::string filepath = filesystemPath + "/shared/" + randomizedFilename;

  if (fs::exists(filepath)) {
    std::ifstream file(filepath);
    std::vector<std::string> keys, usernames;
    parseFileContents(file, keys, usernames);
    file.close();

    updateSharedFiles(keys, usernames, randomizedFilename, filesystemPath, content);
  }
}

// Checks a specific file for a match with the shared username and the value to check
bool checkSpecificFile(const std::string& filepath, const std::string& sharedUsername, const std::string& valueToCheck) {
    if (fs::exists(filepath)) {
        std::ifstream file(filepath);
        std::string line;
        while (getline(file, line)) {
            size_t pos = line.find(":");
            if (pos != std::string::npos) {
                std::string user = line.substr(0, pos);
                std::string key = line.substr(pos + 1);
                if (user == sharedUsername && key == valueToCheck) {
                    return true;
                }
            }
        }
    }
    return false;
}

bool checkFileForKey(const fs::path& filePath, const std::string& valueToCheck) {
    std::ifstream file(filePath);
    std::string line;
    while (getline(file, line)) {
        size_t pos = line.find(":");
        if (pos != std::string::npos) {
            std::string key = line.substr(pos + 1);
            if (key == valueToCheck) {
                return true;
            }
        }
    }
    return false;
}

// Checks if a file is shared with a specific user.
bool isFileSharedWithUser(std::string filename, std::string filesystemPath, std::string sharedUsername, std::string username) {
    // Randomize filenames and directories for security or privacy reasons
    std::string randomizedFilename = FilenameRandomizer::GetRandomizedName(getCustomPWD(filesystemPath) + "/" + filename, filesystemPath);
    std::string randomizedUserDirectory = FilenameRandomizer::GetRandomizedName("/filesystem/" + sharedUsername, filesystemPath);
    std::string randomizedSharedDirectory = FilenameRandomizer::GetRandomizedName("/filesystem/" + randomizedUserDirectory + "/shared", filesystemPath);

    // Construct the value to check for in the shared files
    std::string valueToCheck = "/filesystem/" + randomizedUserDirectory + "/" + randomizedSharedDirectory + "/" + username + "-" + filename;

    // Iterate through each file in the shared files directory to find a match
    std::string filepath = filesystemPath + "/shared/";
    for (const auto& entry : fs::directory_iterator(filepath)) {
        if (fs::is_regular_file(entry)) {
            if (checkFileForKey(entry.path(), valueToCheck)) {
                return true;
            }
        }
    }
    if (checkSpecificFile(filepath, sharedUsername, valueToCheck)) {
        return true;
    }
    return false;
}

std::string getEncFilename(std::string inputFilename, std::string inputPath, std::string filesystemPath, bool isMkdir) {
  int dirItrPath = inputPath.find_last_of('/');
  for (fs::directory_entry entry : fs::directory_iterator(filesystemPath + inputPath.substr(0, dirItrPath+1))) {
    std::string entryPath = entry.path();
    int deleteUpto = entryPath.find_last_of('/') + 1;
    entryPath.erase(0, deleteUpto);

    fs::file_status status = fs::status(entryPath);
    std::string decryptedName = FilenameRandomizer::DecryptFilename(entryPath, filesystemPath);
    // Return same path if a file with the same name exists
    if (inputFilename == decryptedName && status.type() == fs::file_type::regular) {
      if (!isMkdir)
        return entryPath;
      else {
        std::cerr << "A file with the same name already exists in the current path. Please choose a different name." << std::endl;
        return "";
      }
    }
    else if (inputFilename == decryptedName && status.type() == fs::file_type::directory) {
      std::cerr << "A directory with the same name already exists in the current path. Please choose a different name." << std::endl;
      return "";
    }
  }
  return FilenameRandomizer::EncryptFilename(inputPath, filesystemPath);
}

// Creates and encrypts a file within the user's personal directory after performing security checks.
void createAndEncryptFile(std::string filename, std::string contents, std::vector<uint8_t> key, std::string filesystemPath, std::string username) {
  // Ensure the operation is within the user's personal directory
  if (!checkIfPersonalDirectory(username, getCustomPWD(filesystemPath), filesystemPath)) {
    std::cout << "Forbidden " << std::endl;
    return;
  }

  // Ensure the filename does not contain illegal characters ("/")
  if (filename.find('/') != std::string::npos) {
    std::cout << "File name cannot contain '/'" << std::endl;
    return;
  }

  // Construct the full path for the file
  std::string path = getCustomPWD(filesystemPath) + "/" + filename;
  // Obtain an encrypted name for the file, to maintain security or privacy
  std::string encryptedName = getEncFilename(filename, path, filesystemPath, false);
  if (!encryptedName.empty()) {
    // Encrypt and save the file with the encrypted name
    Encryption::encryptFile(encryptedName, contents, key);
    // Check if the file is intended to be shared and handle accordingly
    checkIfShared(encryptedName, filesystemPath, contents);
    std::cout << "File created and encrypted successfully!" << std::endl;
  }
}

// Helper function to process the path and extract/decrypt filenames
std::vector<std::string> processAndDecryptPath(std::string path, const std::string& filesystemPath) {
    const std::string delimiter = "/";
    std::vector<std::string> filenames;
    size_t pos = 0;

    while ((pos = path.find(delimiter)) != std::string::npos) {
        std::string name = path.substr(0, pos);
        if (name == "filesystem") {
            // Add 'filesystem' directly without decryption
            filenames.push_back(name);
        } else {
            // Decrypt the name and add it to the filenames vector
            std::string decrypted = FilenameRandomizer::GetFilename(name, filesystemPath);
            filenames.push_back(decrypted);
        }
        // Prepare for the next iteration
        path.erase(0, pos + delimiter.length());
    }

    // Handle the case where there is a remaining part of the path after the last delimiter
    if (!path.empty()) {
        if (path == "filesystem") {
            filenames.push_back(path);
        } else {
            std::string decrypted = FilenameRandomizer::GetFilename(path, filesystemPath);
            filenames.push_back(decrypted);
        }
    }

    return filenames;
}

std::string decryptFilePath(std::string path, const std::string& filesystemPath) {
    // Normalize the path by removing a leading "/"
    if (!path.empty() && path[0] == '/') {
        path = path.substr(1);
    }

    std::vector<std::string> decryptedFilenames = processAndDecryptPath(path, filesystemPath);

    // Reconstruct the decrypted file path
    std::string decryptedFilePath = "/";
    for (const auto& name : decryptedFilenames) {
        decryptedFilePath += name + "/";
    }
    decryptedFilePath.pop_back();

    return decryptedFilePath;
}

// Encrypts and constructs the file path by randomizing each component.
std::string getEncryptedFilePath(std::string path, std::string filesystemPath) {
    if (path == "." || path == "./") {
        return path;
    }
    std::string pwd = getCustomPWD(filesystemPath);
    size_t pos = 0;
    const std::string delimiter = "/";
    std::vector<std::string> filenames;
    std::string keyPath = pwd;

    while ((pos = path.find(delimiter)) != std::string::npos) {
        std::string name = path.substr(0, pos);
        if (name == ".") {
            filenames.push_back(name);
        } else if (name == "..") {
            int lastOccurrence = keyPath.find_last_of('/');
            keyPath.erase(lastOccurrence, keyPath.length());
            filenames.push_back(name);
        } else {
            std::string randomized = FilenameRandomizer::GetRandomizedName(keyPath + "/" + name, filesystemPath);
            filenames.push_back(randomized);
            keyPath += "/" + randomized;
        }
        path.erase(0, pos + delimiter.length());
    }

    if (path == ".." || path == ".") {
        filenames.push_back(path);
    } else {
        std::string randomizedName = FilenameRandomizer::GetRandomizedName(keyPath + "/" + path, filesystemPath);
        if (!randomizedName.empty()) {
            filenames.push_back(randomizedName);
        }
    }

    std::string encryptedFilePath;
    for (const auto& name : filenames) {
        encryptedFilePath += name + "/";
    }

    if (!encryptedFilePath.empty() && encryptedFilePath.back() == '/') {
        encryptedFilePath.pop_back();
    }
    return encryptedFilePath;
}

#endif // FEATURES_HELPERS_H
