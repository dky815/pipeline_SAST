#include <iostream>
#include <string>
#include <filesystem>
#include <vector>
#include <sstream>
#include <fstream>
#include <unordered_map>
#include <algorithm>

#include "RSAKeyPairGenerator.h"
#include "RSAKeyPairValidator.h"
#include "RSAEncrypter.h"
#include "AESEncrypter.h"

#include <stdexcept>

std::string usernameChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
std::string filenameChars = "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "/" // std::filesystem will resolve this
                            "0123456789"
                            "!#$%&'()*+,-.:;<=>?@[\\]^_`{|}~ "
                            "\""; // Double quote needs to be escaped and is added separately

// Function to check if the string contains only allowed characters
bool containsOnlyAllowedChars(const std::string &input, const std::string &allowedChars)
{
    return std::all_of(input.begin(), input.end(), [&allowedChars](char c)
                       {
        // Return true if the character is found in the allowedChars string, false otherwise
        return allowedChars.find(c) != std::string::npos; });
}

// use this function when concatenating user input and path
std::filesystem::path sanitizePath(const std::filesystem::path basePath, const std::filesystem::path userPath)
{
    std::filesystem::path sanitizedPath;

    try
    {
        std::filesystem::path normalizedBasePath = std::filesystem::weakly_canonical(basePath);
        std::filesystem::path normalizedUserPath = std::filesystem::weakly_canonical(normalizedBasePath / userPath);

        std::filesystem::path absoluteBasePath = std::filesystem::absolute(normalizedBasePath);
        std::filesystem::path absoluteUserPath = std::filesystem::absolute(normalizedUserPath);
        if (absoluteUserPath.string().find(absoluteBasePath.string()) != 0)
        {
            throw std::runtime_error("Path escape attempt detected.");
        }

        return absoluteUserPath;
    }
    catch (const std::filesystem::filesystem_error &e)
    {
        throw std::runtime_error("Invalid path");
    }
}

class User
{
public:
    std::string username;
    std::filesystem::path rootDir;
    std::filesystem::path personalDir;
    std::filesystem::path sharedDir;
    std::filesystem::path privateKeyDir;
    bool isAdmin = false;

    User(const std::string &_username, const std::filesystem::path &_privateKeyDir, const bool _isAdmin) : username(_username), privateKeyDir(_privateKeyDir), isAdmin(_isAdmin)
    {
        if (isAdmin)
        {
            rootDir = std::filesystem::current_path() / "filesystem";
            personalDir = rootDir;
            sharedDir = rootDir;

            if (!std::filesystem::exists(rootDir))
            {
                std::filesystem::create_directories(rootDir);
            }
            if (!std::filesystem::exists(personalDir))
            {
                std::filesystem::create_directories(personalDir);
            }
            if (!std::filesystem::exists(sharedDir))
            {
                std::filesystem::create_directories(sharedDir);
            }
        }
        else
        {
            rootDir = std::filesystem::current_path() / "filesystem" / username;
            personalDir = rootDir / "personal";
            sharedDir = rootDir / "shared";

            if (!std::filesystem::exists(rootDir))
            {
                std::filesystem::create_directories(rootDir);
            }
            if (!std::filesystem::exists(personalDir))
            {
                std::filesystem::create_directories(personalDir);
            }
            if (!std::filesystem::exists(sharedDir))
            {
                std::filesystem::create_directories(sharedDir);
            }
        }
    }

    std::filesystem::path getPublicKeyPath()
    {
        std::filesystem::path pkeyPath = sanitizePath(std::filesystem::current_path() / "public_keys",
                                                      username + "_public.pem");
        if (std::filesystem::exists(pkeyPath))
        {
            return pkeyPath;
        }
        else
        {
            throw std::runtime_error("User: Cannot find public key of user " + username + ".");
        }
    }
    
    std::filesystem::path getPrivateKeyPath()
    {
        std::filesystem::path pkeyPath = sanitizePath(std::filesystem::current_path(), privateKeyDir);
        if (std::filesystem::exists(pkeyPath))
        {
            return pkeyPath;
        }
        else
        {
            throw std::runtime_error("User: Cannot find public key of user " + username + ".");
        }
    }
};

class EncryptedFileSystem
{
private:
    std::unordered_map<std::string, User> users;
    User *currentUser;
    std::string currentUserName;
    std::filesystem::path currentDirectory;
    bool isOutOfBound = false;

    static bool generateUserKeyPair(const std::string &username, const std::string &privateKeyPath)
    {
        std::filesystem::path userPrivateKeyPath = privateKeyPath;
        std::filesystem::path userPublicKeyPath;
        try
        {
            userPublicKeyPath = sanitizePath(std::filesystem::current_path() / "public_keys", username + "_public.pem");
        }
        catch (const std::runtime_error &e)
        {
            std::cerr << e.what() << std::endl;
            return false;
        }

        // std::filesystem::path userPublicKeyPath = std::filesystem::current_path()/"public_keys"/ (username + "_public.pem");

        RSAKeyPairGenerator generator(2048);

        if (!generator.generateKeyPair())
        {
            std::cerr << "Failed to generate RSA key pair." << std::endl;
            return false;
        }

        if (!generator.savePrivateKey(userPrivateKeyPath))
        {
            std::cerr << "Failed to save private key." << std::endl;
            return false;
        }

        if (!generator.savePublicKey(userPublicKeyPath))
        {
            std::filesystem::remove(userPublicKeyPath);
            std::cerr << "Failed to save public key." << std::endl;
            return false;
        }

        std::cout << "RSA key pair generated and saved successfully." << std::endl;

        return true;
    }

    static bool isUserExist(const std::string &username)
    {
        std::filesystem::path userPublicKeyPath = std::filesystem::current_path() / "public_keys" / (username + "_public.pem");

        return std::filesystem::exists(userPublicKeyPath);
    }

    /*
    bool isOutOfBound(const std::string &directory)
    {

        if (directory == "/" || directory == "~" || directory == "")
        {
            return false; // Go to root directory
        }

        std::filesystem::path userRoot = std::filesystem::weakly_canonical(currentUser->rootDir);
        std::filesystem::path destDir = std::filesystem::weakly_canonical(currentDirectory / directory);

        if (directory[0] == '/')
        {
            destDir = std::filesystem::weakly_canonical(currentUser->rootDir / directory.substr(1));
        }

        if (destDir.string().find(userRoot.string()) != 0)
        {
            // out of bound
            return true;
        }

        return false;
    }
    */

    std::filesystem::path safePath(const std::string &directory)
    {
        if (directory == "/" || directory == "~" || directory == "")
        {
            return currentUser->rootDir; // Go to root directory
        }

        std::filesystem::path userRoot = std::filesystem::weakly_canonical(currentUser->rootDir);
        std::filesystem::path newDir = std::filesystem::weakly_canonical(currentDirectory / directory);

        if (directory[0] == '/')
        {
            newDir = std::filesystem::weakly_canonical(currentUser->rootDir / directory.substr(1));
        }

        if (newDir.string().find(userRoot.string()) != 0)
        {
            // out of bound
            isOutOfBound = true;
            newDir = currentUser->rootDir;
        }

        return newDir;
    }

    bool isInPersonalDir(const std::filesystem::path &dir) //, const std::string& username="")
    {
        /*
        if(currentUser->isAdmin && !username.empty()) {
            std::string personalDir = std::filesystem::absolute(sanitizePath(std::filesystem::current_path() / "filesystem", std::filesystem::path(username) / "/personal")).string();
            std::string newDir = std::filesystem::absolute(dir).string();
            return newDir.find(personalDir) == 0;
        }
        */

        std::string personalDir = std::filesystem::absolute(currentUser->personalDir).string();

        std::string newDir = std::filesystem::absolute(dir).string();

        return newDir.find(personalDir) == 0;
    }
    bool isInSharedDir(const std::filesystem::path &dir) //, const std::string& username="")
    {
        /*
        if(currentUser->isAdmin && !username.empty()) {
            std::string personalDir = std::filesystem::absolute(sanitizePath(std::filesystem::current_path() / "filesystem", std::filesystem::path(username) / "/shared")).string();
            std::string newDir = std::filesystem::absolute(dir).string();
            return newDir.find(personalDir) == 0;
        }
        */
        std::string sharedDir = std::filesystem::absolute(currentUser->sharedDir).string();

        std::string newDir = std::filesystem::absolute(dir).string();

        return newDir.find(sharedDir) == 0;
    }

    std::vector<unsigned char> encryptContents(const std::string& adminPublicKeyPath, const std::string& userPublicKeyPath, const std::vector<unsigned char> aesKey, const std::vector<unsigned char> contents)
    {
        // AES Key encryption flow
        RSAEncrypter rsa;

        // Encrypt the AES key using user's public RSA key file
        std::vector<unsigned char> adminEncryptedAesKey = rsa.encrypt(adminPublicKeyPath, aesKey);
        if (adminEncryptedAesKey.empty())
            return {}; // TODO: need error message
            
        std::vector<unsigned char> userEncryptedAesKey = rsa.encrypt(userPublicKeyPath, aesKey);
        if (userEncryptedAesKey.empty())
            return {}; // TODO: need error message

        
        // File content encryption flow
        // Encrypt contents using AES key and random IV
        std::vector<unsigned char> encryptedContents = AESEncrypter::encrypt(contents, aesKey);
    
        // combine encrypted AES key and encrypted contents
        std::vector<unsigned char> combinedContents(adminEncryptedAesKey.size() + userEncryptedAesKey.size() + encryptedContents.size());
        std::memcpy(combinedContents.data(), adminEncryptedAesKey.data(), adminEncryptedAesKey.size());
        std::memcpy(combinedContents.data() + adminEncryptedAesKey.size(), userEncryptedAesKey.data(), userEncryptedAesKey.size());
        std::memcpy(combinedContents.data() + adminEncryptedAesKey.size() + userEncryptedAesKey.size(), encryptedContents.data(), encryptedContents.size());
        
        return combinedContents;
    }
    
    std::vector<unsigned char> decryptContents(const std::string& privateKeyPath, const bool isAdmin, const std::vector<unsigned char> encryptedBytes)
    {
        // allocate memory to separate data
        std::vector<unsigned char> adminEncryptedAesKey(256); // MUST be 256 for AES-256 encryption (32 characters for AES-256)
        std::vector<unsigned char> userEncryptedAesKey(256); // MUST be 256 for AES-256 encryption (32 characters for AES-256)
        std::vector<unsigned char> encryptedContents(encryptedBytes.size() - 256 - 256);

        // Separate encrypted AES key and encrypted data
        std::memcpy(adminEncryptedAesKey.data(), encryptedBytes.data(), adminEncryptedAesKey.size());
        std::memcpy(userEncryptedAesKey.data(), encryptedBytes.data() + adminEncryptedAesKey.size(), userEncryptedAesKey.size());
        std::memcpy(encryptedContents.data(), encryptedBytes.data() + adminEncryptedAesKey.size() + userEncryptedAesKey.size(), encryptedContents.size());
        
        // AES Key decryption flow
        RSAEncrypter rsa;
        std::vector<unsigned char> aesKey(32); // MUST be 32 for AES-256 encryption (32 characters for AES-256)
        if(isAdmin)
        {
            // Decrypt the AES key using user's private RSA key file
            aesKey = rsa.decrypt(privateKeyPath, adminEncryptedAesKey);
            if (aesKey.empty())
                return {}; // TODO: need error message
        }
        else
        {
            // Decrypt the AES key using user's private RSA key file
            aesKey = rsa.decrypt(privateKeyPath, userEncryptedAesKey);
            if (aesKey.empty())
                return {}; // TODO: need error message
        }
        
        // File content decryption flow
        // Decrypt contents using decrypted AES key
        std::vector<unsigned char> decryptedContents = AESEncrypter::decrypt(encryptedContents, aesKey);
        
        return decryptedContents;
    }
    
    std::vector<unsigned char> decryptContentsUsingAesKey(const std::vector<unsigned char> aesKey, const std::vector<unsigned char> encryptedBytes)
    {
        // allocate memory to separate data
        std::vector<unsigned char> encryptedContents(encryptedBytes.size() - 256 - 256);

        // Separate encrypted data
        std::memcpy(encryptedContents.data(), encryptedBytes.data() + 256 + 256, encryptedContents.size());
        
        // File content decryption flow
        // Decrypt contents using decrypted AES key
        std::vector<unsigned char> decryptedContents = AESEncrypter::decrypt(encryptedContents, aesKey);
        
        return decryptedContents;
    }
    
    std::vector<unsigned char> decryptAesKey(const std::string& privateKeyPath, const bool isAdmin, const std::vector<unsigned char> encryptedBytes)
    {
        // allocate memory to separate data
        std::vector<unsigned char> encryptedAesKey(256); // MUST be 256 for AES-256 encryption (32 characters for AES-256)

        // Choose correct encrypted AES key
        if(isAdmin)
        {
            std::memcpy(encryptedAesKey.data(), encryptedBytes.data(), encryptedAesKey.size());
        }
        else
        {
            std::memcpy(encryptedAesKey.data(), encryptedBytes.data() + encryptedAesKey.size(), encryptedAesKey.size());
        }
        
        // AES Key decryption flow
        RSAEncrypter rsa;
        // Decrypt the AES key using user's private RSA key file
        std::vector<unsigned char> aesKey = rsa.decrypt(privateKeyPath, encryptedAesKey);
        if (aesKey.empty())
            return {}; // TODO: need error message
        
        return aesKey;
    }


public:
    EncryptedFileSystem() : currentUser(nullptr)
    {
        createFileSystemDirectory();
        createPublicKeysDirectory();

        // create admin
        if (!isUserExist("admin"))
        {
            std::string username = "admin";
            if (isUserExist(username))
            {
                std::cerr << "User " << username << " already exists." << std::endl;
                return;
            }

            std::string adminKeyPath;
            std::cout << "Generating admin keys, please provide the path to save the private key:\n";
            std::cin >> adminKeyPath;
            if (!generateUserKeyPair(username, adminKeyPath))
            {
                std::cerr << "Error in generating admin keys.\n";
                return;
            }
        }
    }

    void createPublicKeysDirectory()
    {
        std::filesystem::path publicKeysDir = std::filesystem::current_path() / "public_keys";
        if (!std::filesystem::exists(publicKeysDir))
        {
            std::filesystem::create_directory(publicKeysDir);
        }
    }

    void createFileSystemDirectory()
    {
        std::filesystem::path fileSystemDir = std::filesystem::current_path() / "filesystem";

        if (!std::filesystem::exists(fileSystemDir))
        {
            std::filesystem::create_directory(fileSystemDir);
        }
    }

    bool addUser(const std::string &username)
    {
        // limit username length
        if (username.length() > 20)
        {
            std::cerr << "adduser: Please use a short username (less than 20 characters)." << std::endl;
            return false;
        }

        if (!containsOnlyAllowedChars(username, usernameChars))
        {
            std::cerr << "adduser: Invalid character in username. Please use another one." << std::endl;
            return false;
        }

        if (!currentUser->isAdmin)
        {
            std::cerr << "adduser: Forbidden" << std::endl;
            return false;
        }

        if (username == "admin")
        {
            std::cerr << "adduser: you cannot add another admin." << std::endl;
            return false;
        }

        if (isUserExist(username))
        {
            std::cerr << "User " << username << " already exists." << std::endl;

            return false;
        }

        std::string userKeyPath;
        std::cout << "Generating user keys, please provide the path to save the private key:\n";
        std::cin >> userKeyPath;
        if (!generateUserKeyPair(username, userKeyPath))
        {
            std::cerr << "Error in generating user keys.\n";
            return false;
        }

        // initialize user directories
        User newUser(username, userKeyPath, false);

        return true;
    }

    bool authenticateUser(const std::string &username, const std::string &keyfilePath)
    {

        std::filesystem::path userPublicKeyPath;
        try
        {
            userPublicKeyPath = sanitizePath(std::filesystem::current_path() / "public_keys", username + "_public.pem");
        }
        catch (std::runtime_error &e)
        {
            std::cerr << e.what() << std::endl;
            return false;
        }

        std::filesystem::path userPrivateKeyPath = keyfilePath;
        RSAKeyPairValidator validator(userPublicKeyPath, userPrivateKeyPath);
        if (!validator.loadKeys())
        { // If invalid key file, return error
            std::cerr << "auth: Failed to load RSA keys." << std::endl;
            return false;
        }
        if (!validator.validateKeyPair())
        {
            std::cerr << "auth: User validation failed." << std::endl;
            return false; // Keyfile does not match, authentication failed
        }

        std::cout << "User authenticated" << std::endl;
        // Check if the user exists in the system

        bool userExist = isUserExist(username);
        if (!userExist)
        {
            std::cerr << "auth: User " << username << " does not exist" << std::endl;
            return false;
        }

        if (username == "admin")
        {
            currentUser = new User("admin", userPrivateKeyPath, true);
        }
        else
        {
            currentUser = new User(username, userPrivateKeyPath, false);
        }

        currentDirectory = currentUser->rootDir;

        return true; // Authentication successful
    }

    void cd(const std::string &directory)
    {
        // out of bound check

        std::filesystem::path newDir = safePath(directory);

        if (isOutOfBound)
        {
            std::cerr << "cd: Destination is out of bound. Changing directory to user root /" << std::endl;
            isOutOfBound = false;
        }

        if (std::filesystem::exists(newDir) && std::filesystem::is_directory(newDir))
        {
            currentDirectory = std::filesystem::canonical(newDir);
        }
        else
        {
            std::cout << "cd: Directory does not exist" << std::endl;
        }
    }

    void pwd() const
    {
        // need to be changed - don't show path beyond user's root folder
        std::filesystem::path relativePath = std::filesystem::relative(currentDirectory, currentUser->rootDir);
        if (relativePath.string() == ".")
        {
            std::cout << "/" << std::endl;
        }
        else
        {
            std::cout << "/" << relativePath.string() << std::endl;
        }
    }

    void ls() const
    {
        if (!std::filesystem::exists(currentDirectory) || !std::filesystem::is_directory(currentDirectory))
        {
            std::cerr << "ls: Invalid directory." << std::endl;
            return;
        }

        // Show the current directory (.)
        std::cout << "d -> ." << std::endl;

        // Show the parent directory (..), but only if it's not the root of the filesystem
        if (currentDirectory != currentUser->rootDir)
        {
            std::cout << "d -> .." << std::endl;
        }

        for (const auto &entry : std::filesystem::directory_iterator(currentDirectory))
        {
            std::cout << (entry.is_directory() ? "d" : "f") << " -> " << entry.path().filename().string() << std::endl;
        }
    }

    void mkdir(const std::string &directoryName)
    {
        if (!containsOnlyAllowedChars(directoryName, filenameChars))
        {
            std::cerr << "mkdir: Invalid character in directory name. Please use another one." << std::endl;
            return;
        }

        try
        {
            if (currentUser->isAdmin)
            {
                std::cerr << "mkdir: Forbidden. Admin only has read permission." << std::endl;
                return;
            }

            std::filesystem::path newDir = safePath(directoryName);

            if (isInPersonalDir(newDir))
            {
                if (std::filesystem::exists(newDir))
                {
                    std::cerr << "mkdir: Directory already exists" << std::endl;
                }
                else
                {
                    std::filesystem::create_directories(newDir);
                }
            }
            else
            {
                std::cerr << "mkdir: Forbidden. User has no write permission on the destination." << std::endl;
            }
        }
        catch (std::filesystem::filesystem_error &e)
        {
            std::cerr << "mkdir: Please use a shorter directory name." << std::endl;
        }
    }

    void mkfile(const std::string &filename, const std::string &contents)
    {

        if (!containsOnlyAllowedChars(filename, filenameChars))
        {
            std::cerr << "mkfile: Invalid character in file name. Please use another one." << std::endl;
            return;
        }

        try
        {

            if (currentUser->isAdmin)
            {
                std::cerr << "mkfile: Admin only has read permission." << std::endl;
                return;
            }

            std::filesystem::path newFilePath = safePath(filename);
            std::filesystem::path parentDir = newFilePath.parent_path();

            if (!isInPersonalDir(parentDir))
            {
                std::cerr << "mkfile: Forbidden. Cannot create file here." << std::endl;
                return;
            }
            if (std::filesystem::is_directory(newFilePath))
            {
                std::cerr << "mkfile: Destination is a directory." << std::endl;
                return;
            }

            try
            {
                if (!std::filesystem::exists(parentDir))
                {
                    if (!std::filesystem::create_directories(parentDir))
                    {
                        std::cerr << "mkfile: Failed to create parent directory for the new file." << std::endl;
                        return;
                    }
                }
            }
            catch (const std::filesystem::filesystem_error &e)
            {
                std::cerr << "mkfile: Error in creating destination directory." << std::endl;
                return;
            }

            bool fileExists = std::filesystem::exists(newFilePath);
            // allocate memory to AES key
            std::vector<unsigned char> aesKey(32); // MUST be 32 for AES-256 encryption (32 characters for AES-256)
            if (fileExists)
            {
                // IMPORTANT: If the file exists, it should use the existing AES key to re-encrypt the content
                // read binary from original file
                std::ifstream ifileStream(newFilePath, std::ios::binary | std::ios::ate);
                // Determine the file size
                std::streamsize size = ifileStream.tellg();
                ifileStream.seekg(0, std::ios::beg);
                
                // determine shared file
                std::vector<unsigned char> sharedFileMarker(1);
                bool isSharedFile = false;
                if (!ifileStream.read(reinterpret_cast<char *>(sharedFileMarker.data()), 1))
                {
                    std::cerr << "mkfile: Failed to read the file: " << std::filesystem::relative(newFilePath, currentUser->rootDir) << std::endl;
                    return;
                }
                
                if (sharedFileMarker[0] == 1)
                    isSharedFile = true;

                // Read content from file as binary
                std::vector<unsigned char> encryptedBytes(size - 1);
                if (!ifileStream.read(reinterpret_cast<char *>(encryptedBytes.data()), size - 1))
                {
                    std::cerr << "mkfile: Failed to read the file: " << std::filesystem::relative(newFilePath, currentUser->rootDir) << std::endl;
                    return;
                }
                ifileStream.close();

                if (isSharedFile)
                {
                    std::cerr << "mkfile: cannot modify a shared file" << std::endl;
                    return;
                }

                // AES key decryption flow
                std::string privateKeyFile = currentUser->getPrivateKeyPath();
                aesKey = decryptAesKey(privateKeyFile, false, encryptedBytes);
            }
            else
            {
                // If the file is newly created we then randomly generate the AES key
                aesKey = AESEncrypter::generateKey(32); // random AES key (32 characters for AES-256)
            }

            std::ofstream fileStream(newFilePath, std::ios::binary | std::ios::out | std::ios::trunc);
            if (fileStream)
            {
                std::vector<unsigned char> contentsBinary(contents.begin(), contents.end()); // TODO: This should be the user input as binary, may need sanitize
                
                std::string adminPublicKeyFile = sanitizePath(std::filesystem::current_path() / "public_keys", "admin_public.pem");
                std::string userPublicKeyFile = currentUser->getPublicKeyPath();
                // File content encryption flow
                std::vector<unsigned char> encryptedContents = encryptContents(adminPublicKeyFile, userPublicKeyFile, aesKey, contentsBinary);
                
                // write binary to file
                const char newSharedFileMarker = 0x00;
                fileStream.write(&newSharedFileMarker, 1);
                fileStream.write(reinterpret_cast<const char *>(encryptedContents.data()), encryptedContents.size());
                fileStream.close();
            }
            else
            {
                std::cerr << "mkfile: Forbidden. User has no write permission on the destination." << std::endl;
            }
        }
        catch (std::filesystem::filesystem_error &e)
        {
            std::cerr << "mkfile: Please use a shorter filename." << std::endl;
        }
    }

    void cat(const std::string &filename)
    {
        // admin user
        /*
        if (currentUser->isAdmin)
        {
            std::cerr << "cat: pending implementation for admin user to read user files." << std::endl;

            return;
        }
        */

        // boundary check
        std::filesystem::path filePath = safePath(filename);

        if (!std::filesystem::exists(filePath))
        {
            std::cerr << "cat: File not found." << std::endl;
            return;
        }

        if (std::filesystem::is_directory(filePath))
        {
            std::cerr << "cat: Destination is a directory." << std::endl;
            return;
        }

        if (!isInPersonalDir(filePath) && !isInSharedDir(filePath))
        {
            std::cerr << "cat: Forbidden. Access denied." << std::endl;
            return;
        }

        std::ifstream fileStream(filePath, std::ios::binary | std::ios::ate);
        if (fileStream)
        {
            // Determine the file size
            std::streamsize size = fileStream.tellg();
            fileStream.seekg(0, std::ios::beg);
            
            // determine shared file
            std::vector<unsigned char> sharedFileMarker(1);
            bool isSharedFile = false;
            if (!fileStream.read(reinterpret_cast<char *>(sharedFileMarker.data()), 1))
            {
                std::cerr << "cat: Failed to read the file: " << std::filesystem::relative(filePath, currentUser->rootDir) << std::endl;
                return;
            }
                
            if (sharedFileMarker[0] == 1)
                isSharedFile = true;

            // Read content from file as binary
            std::vector<unsigned char> encryptedBytes(size - 1);
            if (!fileStream.read(reinterpret_cast<char *>(encryptedBytes.data()), size - 1))
            {
                std::cerr << "cat: Failed to read the file: " << std::filesystem::relative(filePath, currentUser->rootDir) << std::endl;
                return;
            }
            fileStream.close();

            // decryption flow
            std::string privateKeyFile = currentUser->getPrivateKeyPath();

            // Decrypt contents and AES key
            std::vector<unsigned char> aesKey = decryptAesKey(privateKeyFile, currentUser->isAdmin, encryptedBytes);
            std::vector<unsigned char> decryptedContents = decryptContents(privateKeyFile, currentUser->isAdmin, encryptedBytes);

            // If cat a shared file, locate and decrypt the original file
            if (isSharedFile)
            {
                std::string originalFilePath(decryptedContents.begin(), decryptedContents.end()); // TODO: May need sanitize
                std::ifstream oringialFileStream(originalFilePath, std::ios::binary | std::ios::ate);
                if (oringialFileStream)
                {
                    // Determine the file size
                    std::streamsize size = oringialFileStream.tellg();
                    oringialFileStream.seekg(0, std::ios::beg);
                    
                    // Although it cannot be shared file, we still have to read the first byte
		    std::vector<unsigned char> sharedFileMarker2(1);
		    if (!oringialFileStream.read(reinterpret_cast<char *>(sharedFileMarker2.data()), 1))
		    {
		        std::cerr << "cat: Failed to read the file: " << std::filesystem::relative(originalFilePath, currentUser->rootDir) << std::endl;
		        return;
		    }
		    
		    // Read content from file as binary
		    std::vector<unsigned char> originalEncryptedBytes(size - 1);
		    if (!oringialFileStream.read(reinterpret_cast<char *>(originalEncryptedBytes.data()), size - 1))
		    {
		        std::cerr << "cat: Failed to read the file: " << std::filesystem::relative(originalFilePath, currentUser->rootDir) << std::endl;
		        return;
		    }
		    oringialFileStream.close();

                    // decryption flow
		    // Decrypt contents
		    std::vector<unsigned char> decryptedOriginalContents = decryptContentsUsingAesKey(aesKey, originalEncryptedBytes);

		    std::cout << std::string(decryptedOriginalContents.begin(), decryptedOriginalContents.end()) << std::endl;
                }
                else
                {
                    std::cerr << "cat: Error in reading original file." << std::endl;
                }
            }
            // If cat a personal file, display decrypted contents
            else
            {
                std::cout << std::string(decryptedContents.begin(), decryptedContents.end()) << std::endl;
            }
        }
        else
        {
            std::cerr << "cat: Error reading file" << std::endl;
        }
    }

    void share(const std::string &filename, const std::string &username)
    {

        if (currentUser->isAdmin)
        {
            std::cerr << "share: Admin only has read permission." << std::endl;
            return;
        }

        if (username == "admin")
        {
            std::cerr << "share: Cannot share a file to admin." << std::endl;
            return;
        }

        std::filesystem::path filePath = safePath(filename);

        if (!std::filesystem::exists(filePath))
        {
            std::cerr << "share: File " << filename << " not exist." << std::endl;
            return;
        }

        if (std::filesystem::is_directory(filePath))
        {
            std::cerr << "share: " << filename << " is a directory." << std::endl;
            return;
        }

        std::filesystem::path sharedDir = sanitizePath(std::filesystem::current_path() / "filesystem", username + "/shared");

        if (!isUserExist(username) || !std::filesystem::exists(sharedDir)) // bypass directory traversal
        {
            std::cerr << "share: User " << username << " not exist." << std::endl;
            return;
        }

        std::filesystem::path targetPath = sanitizePath(sharedDir, currentUser->username + "_" + filename);

        try
        {
            // This case we did not copy file content, we only store re-encrypted AES key and a link (encrypted) to original file
            std::ifstream ifileStream(filePath, std::ios::binary | std::ios::ate);

            // Determine the file size
            std::streamsize size = ifileStream.tellg();
            ifileStream.seekg(0, std::ios::beg);
            
            // determine shared file
	    std::vector<unsigned char> sharedFileMarker(1);
	    bool isSharedFile = false;
	    if (!ifileStream.read(reinterpret_cast<char *>(sharedFileMarker.data()), 1))
	    {
	        std::cerr << "share: Failed to read the file: " << std::filesystem::relative(filePath, currentUser->rootDir) << std::endl;
	        return;
	    }
	    
	    if (sharedFileMarker[0] == 1)
                isSharedFile = true;

            // Read content from file as binary
            std::vector<unsigned char> encryptedBytes(size - 1);
            if (!ifileStream.read(reinterpret_cast<char *>(encryptedBytes.data()), size - 1))
            {
                std::cerr << "share: Failed to read the file: " << std::filesystem::relative(filePath, currentUser->rootDir) << std::endl;
                return;
            }
            ifileStream.close();
            
            if (isSharedFile)
            {
                std::cerr << "share: cannot share a shared file" << std::endl;
                return;
            }
            
            // allocate memory to AES key
            std::vector<unsigned char> aesKey(32); // MUST be 32 for AES-256 encryption (32 characters for AES-256)

            // AES key decryption flow
            std::string privateKeyFile = currentUser->getPrivateKeyPath();
            aesKey = decryptAesKey(privateKeyFile, false, encryptedBytes);

            // AES key and file link re-encryption flow
            std::string receiverPublicKeyFile = sanitizePath(std::filesystem::current_path() / "public_keys", username + "_public.pem");
            std::string adminPublicKeyFile = sanitizePath(std::filesystem::current_path() / "public_keys", "admin_public.pem");

            // TODO: Generate link to actual file and save full path as binary
            std::string originalFilePathString = filePath.string();
            std::vector<unsigned char> contentsBinary(originalFilePathString.begin(), originalFilePathString.end());
            
            // File content encryption flow
            std::vector<unsigned char> encryptedContents = encryptContents(adminPublicKeyFile, receiverPublicKeyFile, aesKey, contentsBinary);

            // write binary to file
            std::ofstream ofileStream(targetPath, std::ios::binary | std::ios::out | std::ios::trunc);
            const char newSharedFileMarker = 0x01; // shared file
            ofileStream.write(&newSharedFileMarker, 1);
            ofileStream.write(reinterpret_cast<const char *>(encryptedContents.data()), encryptedContents.size());
            ofileStream.close();
        }
        catch (std::filesystem::filesystem_error &e)
        {
            std::cerr << "share: Error during sharing a file." << std::endl;
            return;
        }

        std::cout << "File shared successfully." << std::endl;
    }
};

void processCommand(EncryptedFileSystem &filesystem, const std::string &command)
{
    std::istringstream iss(command);
    std::string cmd;
    iss >> cmd;

    if (cmd == "cd")
    {
        std::string dir;
        iss >> dir;
        filesystem.cd(dir);
    }
    else if (cmd == "pwd")
    {
        filesystem.pwd();
    }
    else if (cmd == "ls")
    {
        filesystem.ls();
    }
    else if (cmd == "mkdir")
    {
        std::string dirName;
        iss >> dirName;
        if (dirName.find_first_not_of(' ') == std::string::npos)
        {
            std::cerr << "Usage: mkdir <directory_name>" << std::endl;
            return;
        }

        filesystem.mkdir(dirName);
    }
    else if (cmd == "mkfile")
    {
        std::string filename, contents;
        iss >> filename;
        if (filename.find_first_not_of(' ') == std::string::npos)
        {
            std::cerr << "Usage: mkfile <filename> <contents>" << std::endl;
            return;
        }
        iss.ignore(); // Skip whitespace
        std::getline(iss, contents);
        filesystem.mkfile(filename, contents);
    }
    else if (cmd == "cat")
    {
        std::string filename;
        iss >> filename;
        if (filename.find_first_not_of(' ') == std::string::npos)
        {
            std::cerr << "Usage: cat <filename>" << std::endl;
            return;
        }
        filesystem.cat(filename);
    }
    else if (cmd == "share")
    {
        std::string filename, username;
        iss >> filename >> username;
        if (filename.find_first_not_of(' ') == std::string::npos || username.find_first_not_of(' ') == std::string::npos)
        {
            std::cerr << "Usage: share <filename> <username>" << std::endl;
            return;
        }
        filesystem.share(filename, username);
    }
    else
    {
        std::cerr << "Invalid Command" << std::endl;
    }
}

int main(int argc, char *argv[])
{
    // initialization
    if (argc == 1)
    {
        if (!std::filesystem::exists(std::filesystem::current_path() / "public_keys" / "admin_public.pem"))
        {
            EncryptedFileSystem efs;
            return 0;
        }
    }

    // Check for correct number of arguments
    if (argc != 2)
    {
        std::cerr << "Usage: ./fileserver keyfile_name\n";
        return 1;
    }

    // Initialize the filesystem and directories
    EncryptedFileSystem filesystem;

    std::string keyfile = argv[1];

    // User authentication
    std::string username;
    std::cout << "Enter username: ";
    std::getline(std::cin, username);

    if (!filesystem.authenticateUser(username, keyfile))
    {
        std::cout << "Invalid keyfile" << std::endl;
        return 1;
    }

    std::cout << "Logged in as " << username << std::endl;

    // Command processing loop
    std::string command;
    while (true)
    {
        std::cout << "Enter command: ";
        std::getline(std::cin, command);

        if (command == "exit")
        {
            break;
        }

        // Handle admin specific command 'adduser'
        std::istringstream iss(command);
        std::string cmd;
        iss >> cmd;

        if (cmd == "adduser" && username == "admin")
        {
            std::string newUsername;
            iss >> newUsername;
            if (filesystem.addUser(newUsername))
            {
                std::cout << "User " << newUsername << " added successfully." << std::endl;
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            }

            continue;
        }

        // Process other commands
        processCommand(filesystem, command);
    }

    return 0;
}
