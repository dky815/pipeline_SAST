#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <filesystem>

#include "authentication/authentication.h"
#include "features/features.h"
#include "helpers/helper_functions.h"

namespace fs = std::filesystem;

int main(int argc, char *argv[]) {
    std::string filesystemPath = fs::current_path();

    if(fs::exists("filesystem")) {
        if(argc != 2) {
            std::cout << "Invalid keyfile\n" << std::endl;
            return 1;
        } 
        else {
            std::string keyFileName = argv[1];
            std::string userName = getTypeOfUser(keyFileName);
            UserType userType;
            if(userName == "admin")
                userType = UserType::admin;
            else
                userType = UserType::user;

            userFeatures(userName, userType, readEncKeyFromMetadata(userName, ""), filesystemPath);
        }
    } 
    else {
        if(
            !createDirectory("key") ||
            !createDirectory("key/public_keys") ||
            !createDirectory("key/private_keys") ||
            !createDirectory("common") ||
            !createDirectory("shared") ||
            !createDirectory("filesystem")) {
            return 1;
        }

    std::string metadataPath = "common/structure.json";
    std::ofstream metadataFile(metadataPath);
    if (metadataFile) {
        metadataFile << "{\"test\":\"123\"}";
        metadataFile.close();
    } else {
        std::cerr << "Error creating structure.json\n" << std::endl;
        return 1;
    }

    std::string userName = "admin";
    addUser(userName, filesystemPath, true);
    userFeatures(userName, UserType::admin, readEncKeyFromMetadata(userName, ""), filesystemPath);
  }
}
