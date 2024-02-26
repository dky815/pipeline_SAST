#ifndef USER_FEATURES_H
#define USER_FEATURES_H

#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <filesystem>
#include <fstream>

#include "helpers/helper_functions.h"
#include "user_management/user_management.h"
#include "encryption/randomizer_function.h"
#include "user_features_helpers.h"

/**
 * Appends content to a file or creates the file if it doesn't exist.
 * @param filename The name of the file to append the content to.
 * @param filepath The path where the file is located.
 * @param content The content to append to the file.
 */
void addContentsToFile(std::string filename, std::string filepath, std::string content) {
  filepath += "/" + filename;
  std::ofstream file(filepath, std::ios::app);

  if (file) {
    file << content << std::endl;
    file.close();
  } 
  else {
    std::ofstream newFile(filepath);
    if (newFile) {
        newFile << content << std::endl;
    }
    newFile.close();
  }
}

/**
 * Shares a file with a specified user by encrypting and copying it to the user's shared directory.
 * The function first checks if the file and the user exist. Then, it encrypts the file with the user's key
 * and places it in the user's shared directory, recording the action in a shared files log.
 * 
 * @param key The encryption key used for decrypting the file before re-encrypting it for the recipient.
 * @param username The name of the user with whom the file is to be shared.
 * @param filename The name of the file to share.
 * @param filesystemPath The base path of the filesystem where the file is located.
 * @param loggedUsername The username of the user who is sharing the file.
 */
void shareFile(std::vector<uint8_t> key, std::string username, std::string filename, std::string filesystemPath, std::string loggedUsername) {
    std::string randomizedFilename = FilenameRandomizer::GetRandomizedName(getCustomPWD(filesystemPath) + "/" + filename, filesystemPath);

    if (!doesFileExist(randomizedFilename) || !doesUserExist(username, filesystemPath)) {
        return;
    }

    std::string randomizedUserDirectory = getRandomizedUserDirectory(username, filesystemPath);
    std::string randomizedSharedDirectory = getRandomizedSharedDirectory(randomizedUserDirectory, filesystemPath);
    std::string content = Encryption::decryptFile(randomizedFilename, key);
    std::vector<uint8_t> shareKey = readEncKeyFromMetadata(username, filesystemPath + "/common/");
    std::string filenameKey = "/filesystem/" + randomizedUserDirectory + "/" + randomizedSharedDirectory + "/" + loggedUsername + "-" + filename;
    std::string sharedRandomizedFilename = FilenameRandomizer::EncryptFilename(filenameKey, filesystemPath);
    std::string shareUserPath = filesystemPath + "/filesystem/" + randomizedUserDirectory + "/" + randomizedSharedDirectory + "/" + sharedRandomizedFilename;
    Encryption::encryptFile(shareUserPath, content, shareKey);

    std::string sharedDataPath = filesystemPath + "/shared";
    std::string sharedDataContent = username + ":" + filenameKey;
    addContentsToFile(randomizedFilename, sharedDataPath, sharedDataContent);
    std::cout << "File shared successfully!" << std::endl;
}

/**
 * Creates a directory within the user's personal space after validating permissions and name constraints.
 * The directory name is encrypted to maintain user data confidentiality.
 *
 * @param directoryName The name of the directory to create.
 * @param filesystemPath The base filesystem path.
 * @param username The user within whose personal space the directory is to be created.
 */
void createDirectoryInUserSpace(std::string directoryName, std::string &filesystemPath, std::string username) {
  if (!checkIfPersonalDirectory(username, getCustomPWD(filesystemPath), filesystemPath)) {
    std::cerr << "Forbidden" << std::endl;
    return;
  }

  if (directoryName.find('/') != std::string::npos) {
    std::cout << "Directory name cannot contain '/'" << std::endl;
    return;
  }

  std::string path = getCustomPWD(filesystemPath) + "/" + directoryName;
  std::string encryptedName = getEncFilename(directoryName, path, filesystemPath, true);
  if (!encryptedName.empty()) {
    system(("mkdir -p " + encryptedName).c_str());
    std::cout << "Directory created successfully." << std::endl;
  }
}


void printDecryptedCurrentPath(std::string filesystemPath) {
  std::string pwd = decryptFilePath(getCustomPWD(filesystemPath), filesystemPath);
  std::cout << pwd << std::endl;
}

/**
 * Lists the contents of the current directory, distinguishing between directories and files.
 * Hidden files (starting with '.') are skipped, and directory entries are decrypted for display.
 *
 * @param filesystemPath The base path of the filesystem to determine the root for hiding the parent directory indicator.
 */
void listDirectoryContents(std::string filesystemPath) {
    std::string path = fs::current_path();
    std::cout << "d -> ." << std::endl;

    if (path != filesystemPath + "/filesystem") {
        std::cout << "d -> .." << std::endl;
    }

    for (const fs::directory_entry& entry : fs::directory_iterator(path)) {
        std::string entryPath = entry.path().filename().string();

        if (entryPath.find(".") == 0) {
            continue;
        }

        fs::file_status status = entry.status();
        std::string decryptedName = FilenameRandomizer::DecryptFilename(entryPath, filesystemPath);

        if (status.type() == fs::file_type::directory) {
            std::cout << "d -> " << decryptedName << std::endl;
        } else if (status.type() == fs::file_type::regular) {
            std::cout << "f -> " << decryptedName << std::endl;
        }
    }
}

/**
 * Processes file access requests by validating the filename and displaying the file content if available.
 * It supports different actions based on the user type, including decrypting the file for admin users with a specific key.
 *
 * @param inputStream The input stream containing the filename to access.
 * @param filesystemPath The base path of the filesystem for locating files.
 * @param userType The type of the user (e.g., admin or regular user) to determine access rights.
 * @param key The encryption key used for decrypting the file content.
 */
void processFileAccess(std::istringstream& inputStream, std::string filesystemPath, UserType userType, std::vector<uint8_t> key) {
    std::string filename;
    inputStream >> filename;

    if (filename.empty()) {
        std::cout << "File name not provided" << std::endl;
        return;
    }
    if (filename.find('/') != std::string::npos) {
        std::cout << "File name cannot contain '/'" << std::endl;
        return;
    }

    std::string path = getCustomPWD(filesystemPath) + "/" + filename;
    std::string encryptedName = FilenameRandomizer::GetRandomizedName(path, filesystemPath);

    if (!fs::exists(encryptedName)) {
        std::cerr << "File does not exist" << std::endl;
        return;
    }
    if (fs::is_directory(fs::status(encryptedName))) {
        std::cerr << "File does not exist" << std::endl;
        return;
    }

    if (userType == UserType::admin) {
        std::string pwd = decryptFilePath(getCustomPWD(filesystemPath), filesystemPath);
        std::string userForKey = getUsernameFromPath(pwd);
        std::vector<uint8_t> userKey = readEncKeyFromMetadata(userForKey, filesystemPath + "/common/");
        std::cout << Encryption::decryptFile(encryptedName, userKey) << std::endl;
    } else {
        std::cout << Encryption::decryptFile(encryptedName, key) << std::endl;
    }
}

/**
 * Handles requests to share a file with another user, ensuring the operation is permitted and the file hasn't been shared previously.
 * It validates the filename and checks sharing permissions based on the user's directory and sharing status.
 *
 * @param inputStream The stream containing the filename and the username with whom to share the file.
 * @param userName The name of the user attempting to share the file.
 * @param key The encryption key for the file to be shared.
 * @param filesystemPath The base filesystem path for file location and sharing operations.
 */
void handleFileSharing(std::istringstream& inputStream, std::string userName, std::vector<uint8_t> key, std::string filesystemPath) {
    std::string filename, shareUsername;
    inputStream >> filename >> shareUsername;

    if (!checkIfPersonalDirectory(userName, getCustomPWD(filesystemPath), filesystemPath)) {
        std::cout << "Forbidden" << std::endl;
        return;
    }

    if (filename.find('/') != std::string::npos) {
        std::cout << "File name cannot contain '/'" << std::endl;
        return;
    }

    if (isFileSharedWithUser(filename, filesystemPath, shareUsername, userName)) {
        std::cout << "A file with name " << filename << " has already been shared with " << shareUsername << std::endl;
    } else {
        shareFile(key, shareUsername, filename, filesystemPath, userName);
    }
}

/**
 * Handles the creation of a new file with provided contents, ensuring the filename is valid
 * and the user has the necessary permissions to create a file within their personal directory.
 *
 * @param inputStream The input stream to extract the filename and contents from.
 * @param userName The name of the user attempting to create the file.
 * @param key The encryption key for the file.
 * @param filesystemPath The base path of the filesystem.
 */
void processFileCreation(std::istringstream& inputStream, std::string userName, std::vector<uint8_t> key, std::string filesystemPath) {
    std::string filename, contents;
    inputStream >> filename;
    std::getline(inputStream, contents);

    if (filename.find('/') != std::string::npos) {
        std::cout << "File name cannot contain '/'" << std::endl;
        return;
    }
    if (!checkIfPersonalDirectory(userName, getCustomPWD(filesystemPath), filesystemPath)) {
        std::cout << "Forbidden" << std::endl;
        return;
    }

    std::filesystem::path pathObj(filename);
    std::string filenameStr = pathObj.filename().string();
    if (!filenameStr.empty() && isValidFilename(filename)) {
        createAndEncryptFile(filename, contents, key, filesystemPath, userName);
    } else {
        std::cerr << "Not a valid filename, try again." << std::endl;
    }
}

/**
 * Processes the addition of a new user to the system, ensuring the username is provided
 * and invoking the addUser function with the new user's details.
 *
 * @param inputStream The input stream to extract the new user's name from.
 * @param filesystemPath The base path of the filesystem.
 */
void processAddUser(std::istringstream& inputStream, std::string filesystemPath) {
    std::string newUser;
    inputStream >> newUser;

    if (newUser.empty()) {
        std::cerr << "Please enter a username" << std::endl;
        return;
    }
    addUser(newUser, filesystemPath, false);
}

/**
 * Handles the creation of a new directory within the user's personal space, ensuring
 * the directory name is valid and the user has the necessary permissions.
 *
 * @param directoryName The name of the directory to be created.
 * @param filesystemPath The base path of the filesystem.
 * @param userName The name of the user attempting to create the directory.
 */
void processCreateDirectoryInUserSpace(std::string directoryName, std::string filesystemPath, std::string userName) {
    if (directoryName.find('/') != std::string::npos || directoryName.find('`') != std::string::npos) {
        std::cerr << "Directory name cannot contain '/' or '`'" << std::endl;
        return;
    }
    if (!checkIfPersonalDirectory(userName, getCustomPWD(filesystemPath), filesystemPath)) {
        std::cout << "Forbidden: User lacks permission to create directory here." << std::endl;
        return;
    }
    if (directoryName.empty() || directoryName == "filesystem" || directoryName == "." || directoryName == "..") {
        std::cerr << "Invalid directory name provided." << std::endl;
        return;
    }
    
    fs::path targetPath = fs::absolute(directoryName);
    if (fs::exists(targetPath) && fs::is_directory(targetPath)) {
        std::cerr << "Directory already exists." << std::endl;
        return;
    }
    try {
        createDirectoryInUserSpace(directoryName, filesystemPath, userName);
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Failed to create directory: " << e.what() << std::endl;
    }
}

int userFeatures(std::string user_name, UserType user_type, std::vector<uint8_t> key, std::string filesystem_path) {
  std::cout << "++++++++++++++++++++++++" << std::endl;
  std::cout << "++| WELCOME TO EFS! |++" << std::endl;
  std::cout << "++++++++++++++++++++++++" << std::endl;
  std::cout << "\nEFS Commands Available: \n" << std::endl;

  std::cout << "cd <directory> \n"
          "pwd \n"
          "ls  \n"
          "cat <filename> \n"
          "share <filename> <username> \n"
          "mkdir <directory_name> \n"
          "mkfile <filename> <contents> \n"
          "exit \n";

  if (user_type == admin) {
    // if admin, allow the following command
    std::cout << "adduser <username>" << std::endl;
    std::cout << "++++++++++++++++++++++++" << std::endl;

    // also set root path to admin path which is the whole fs
    rootPath = adminRootPath;
  } else if (user_type == user) {
    std::cout << "++++++++++++++++++++++++" << std::endl;
    // set root path = user's root path which is its own directory
    std::string user_folder = FilenameRandomizer::GetRandomizedName("/filesystem/" + user_name, filesystem_path);
    rootPath = userRootPath / user_folder;
  }

  fs::current_path(rootPath);
  std::string input_feature, cmd, filename, username, directory_name, contents;

  do {
    std::cout << user_name << " " << decryptFilePath(getCustomPWD(filesystem_path), filesystem_path) << "> ";
    // get command from the user
    getline(std::cin, input_feature);

    if (std::cin.eof()) {
        // Ctrl+D was pressed
        std::cout << "Ctrl+D detected." << std::endl;
        return 1;
    }

    // get the first word (command) from the input
    std::istringstream istring_stream(input_feature);
    istring_stream >> cmd;

    if (cmd == "cd") {

      // Clear the input stream first, to avoid any un-intended issues with it
      istring_stream.clear();

      // set a global directory for starting in a clean state
      directory_name = "/";

      // get the directory name from istring stream buffer
      istring_stream >> directory_name;

      if(directory_name.empty()) {
        // just `cd` is equivalent of `cd /` , so going to root directory.

        // assign root name first to avoid issues with the emptiness of directory_name in the second run.
        directory_name = "/";

        // This should vary depending upon what kind of user is currently logged in
        // cd / should take you to the current user’s root directory
        // TODO: it appears rootPath is getting set properly occasionaly, try `cd admin` and then `pwd` and then `mkdir folder1`
        // TODO: we should change to `<rootPath>` right away after logging in, rootPath will change depending on who logs in
        fs::current_path(rootPath);

        continue;
      }

      if(directory_name.find('`') != std::string::npos) {
        std::cerr << "Error: directory name should not contain `backticks`, try again." << std::endl;
      } else {

        if (directory_name == "~" || directory_name == "/"){
            // This should vary depending upon what kind of user is currently logged in
            // cd ~ should take you to the current user’s root directory
            fs::current_path(rootPath);

            continue;
        }

        directory_name = normalizePath(directory_name);
        directory_name = getEncryptedFilePath(directory_name, filesystem_path);

        if(directory_name == "." || directory_name == "./") {
            // like `cd .`
            // do nothing and continue
            continue;

        }

        if (!(fs::exists(directory_name) && fs::is_directory(directory_name))) {
            // Check early for linux machines
            // If a directory doesn't exist, the user should stay in the current directory

            continue;
        }

        // construct a target (absolute) path from the directory name
        fs::path current_path = fs::current_path();
        fs::path target_path = fs::absolute(directory_name);
        fs::path relative_path = fs::relative(target_path, rootPath);
        fs::path resolved_root = fs::absolute(rootPath);
        fs::path resolved_target = fs::absolute(target_path);
        if (target_path.has_relative_path()) {
          if (fs::exists(directory_name) && fs::is_directory(directory_name)) {
            // checking this before because lexically_relative errors if the dir doesn't exist
            if(target_path.lexically_relative(rootPath).native().front() == '.') {
              if(directory_name == "." || directory_name == "..") {
                if (directory_name == "/") {
                  // This should vary depending upon what kind of user is currently logged in
                  // cd / should take you to the current user’s root directory
                  fs::current_path(rootPath);
                } else if (target_path == rootPath) {
                  if (current_path == rootPath) {
                    // like `cd .`  - so no need to change the directory
                    fs::current_path(fs::current_path());
                  } else {
                    // go to root path
                    fs::current_path(rootPath);
                  }
                } else if (target_path == rootPath.parent_path()) {
                  // like `cd ..`
                  fs::current_path(fs::current_path().parent_path());
                } else {
                  // if the directory path is outside the root path
                  // Warn and stay in the current directory
                  std::cerr << "Directory is outside of the root directory." << std::endl;
                  std::cout << "Staying in current directory." << std::endl;
                }
              } else {
                if (target_path == rootPath) {
                  if (current_path == rootPath) {
                    // like `cd .`  - so no need to change the directory
                    fs::current_path(fs::current_path());
                  } else {
                    // go to root path
                    fs::current_path(rootPath);
                  }
                } else {
                  // if the directory path is outside the root path
                  // Warn and stay in the current directory
                  std::cerr << "Directory is outside of the root directory." << std::endl;
                  std::cout << "Staying in current directory." << std::endl;
                }
              }
            } else {
              if (directory_name == "/") {
                // This should vary depending upon what kind of user is currently logged in
                // cd / should take you to the current user’s root directory
                fs::current_path(rootPath);
              } else if (target_path == rootPath) {
                if (current_path == rootPath) {
                  // like `cd .`  - so no need to change the directory
                  fs::current_path(fs::current_path());
                } else {
                  // go to root path
                  fs::current_path(rootPath);
                }
              } else if (target_path == rootPath.parent_path()) {
                // like `cd ..`
                fs::current_path(fs::current_path().parent_path());
              } else if (fs::exists(directory_name) && fs::is_directory(directory_name)) {
                if (relative_path.has_parent_path()) {
                  if (relative_path.string().find("..") != std::string::npos) {
                    // if the directory path is outside the root path
                    // Warn and stay in the current directory
                    std::cerr << "Directory is outside of the root directory." << std::endl;
                    std::cout << "Staying in current directory." << std::endl;
                  } else {
                    // relative path is trying a subdirectory
                    if (fs::exists(directory_name) && fs::is_directory(directory_name)) {
                      // the directory exists, so we can change to given directory
                      fs::current_path(target_path);
                    } else {
                      // If a directory doesn't exist, the user should stay in the current directory
                      std::cerr << "Directory does not exist." << std::endl;
                      std::cout << "Staying in current directory." << std::endl;
                    }
                  }
                } else {
                  if (relative_path.string().find("..") != std::string::npos) {
                    // relative_path contains .. meaning it is trying to go outside root directory
                    // if the directory path is outside the root path
                    // Warn and stay in the current directory
                    std::cerr << "Directory is outside of the root directory." << std::endl;
                    std::cout << "Staying in current directory." << std::endl;
                  } else {
                    // the directory exists, so we can change to given directory
                    fs::current_path(target_path);
                  }
                }
              } else {
                // If a directory doesn't exist, the user should stay in the current directory
                std::cerr << "Directory does not exist." << std::endl;
                std::cout << "Staying in current directory." << std::endl;
              }
            }
          } else {
            // If a directory doesn't exist, the user should stay in the current directory
            std::cerr << "Directory does not exist." << std::endl;
            std::cout << "Staying in current directory." << std::endl;
          }
        } else {
          if (directory_name == "/"){
            // This should vary depending upon what kind of user is currently logged in
            // cd / should take you to the current user’s root directory
            fs::current_path(rootPath);
          } else {
            // Allow relative paths only
            // Warn and stay in the current directory
            std::cerr << "Give a relative path." << std::endl;
            std::cout << "Staying in current directory." << std::endl;
          }
        }
      }
    } else if (cmd == "pwd") {
      printDecryptedCurrentPath(filesystem_path);
    } else if (cmd == "ls") {
      listDirectoryContents(filesystem_path);
    } else if (cmd == "cat") {
      processFileAccess(istring_stream, filesystem_path, user_type, key);
    } else if (cmd == "share") {
      handleFileSharing(istring_stream, user_name, key, filesystem_path);
    } else if (cmd == "mkdir") {
      istring_stream >> directory_name;
      processCreateDirectoryInUserSpace(directory_name, filesystem_path, user_name);
    } else if (cmd == "mkfile") {
      processFileCreation(istring_stream, user_name, key, filesystem_path);
    } else if (cmd == "exit") {
      exit(EXIT_SUCCESS);
    } else if ((cmd == "adduser") && (user_type == admin)) {
        processAddUser(istring_stream, filesystem_path);
    } else {
      std::cout << "Invalid Command" << std::endl;
    }
    cmd = "";
    filename = "";
    directory_name = "";
    contents="";
  } while (cmd != "exit"); // only exit out of command line when using "exit" cmd

  return 1;
}

#endif // USER_FEATURES_H