/*
* File Encryption/Decryption: Ensures that all files stored in the filesystem are encrypted 
* and can only be decrypted by the middleware when accessed by an authenticated user.
*/

#ifndef FILESERVER_ENCRYPTION_H
#define FILESERVER_ENCRYPTION_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>

#define BLOCK_SIZE 16 //bytes
#define KEY_SIZE 32 //bytes
#define TAG_SIZE 16 //bytes
#define IV_SIZE 16 //bytes

class Encryption {
public:
    static void encryptFile(const std::string& filePath, const std::string& content, const std::vector<uint8_t>& key);
    static std::string decryptFile(const std::string& filePath, const std::vector<uint8_t>& key);

private:
    static void handleErrors(const std::string& message);
    static void initCipherContext(EVP_CIPHER_CTX*& ctx, const std::vector<uint8_t>& key, const uint8_t* iv, bool encrypt);
};

void Encryption::handleErrors(const std::string& message) {
    std::cerr << message << std::endl;
    exit(EXIT_FAILURE); // It's more conventional to exit with a failure status on error.
}

void Encryption::initCipherContext(EVP_CIPHER_CTX*& ctx, const std::vector<uint8_t>& key, const uint8_t* iv, bool encrypt) {
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors("Cipher context initialization failed.");
    }

    if (encrypt) {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv)) {
            handleErrors("Encryption initialization failed.");
        }
    } else {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv)) {
            handleErrors("Decryption initialization failed.");
        }
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr)) {
        handleErrors("Failed to set IV length.");
    }
}

void Encryption::encryptFile(const std::string& filePath, const std::string& content, const std::vector<uint8_t>& key) {
    uint8_t iv[IV_SIZE];
    RAND_bytes(iv, sizeof(iv));
    unsigned char tag[TAG_SIZE];
    EVP_CIPHER_CTX* ctx;

    initCipherContext(ctx, key, iv, true);

    std::ofstream outputFile(filePath, std::ios::binary);
    if (!outputFile.is_open()) {
        handleErrors("Failed to open output file.");
    }

    std::vector<unsigned char> buffer(content.begin(), content.end());
    buffer.resize(buffer.size() + BLOCK_SIZE); // Ensure space for padding
    int len = 0, ciphertextLen = 0;

    if (1 != EVP_EncryptUpdate(ctx, buffer.data(), &len, buffer.data(), buffer.size())) {
        handleErrors("Encryption failed.");
    }
    ciphertextLen += len;

    if (1 != EVP_EncryptFinal_ex(ctx, buffer.data() + len, &len)) {
        handleErrors("Final encryption step failed.");
    }
    ciphertextLen += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag)) {
        handleErrors("Failed to get tag.");
    }

    outputFile.write(reinterpret_cast<char*>(iv), IV_SIZE);
    outputFile.write(reinterpret_cast<char*>(tag), TAG_SIZE);
    outputFile.write(reinterpret_cast<char*>(buffer.data()), ciphertextLen);

    EVP_CIPHER_CTX_free(ctx);
    outputFile.close();
}

std::string Encryption::decryptFile(const std::string& filePath, const std::vector<uint8_t>& key) {
    std::ifstream inputFile(filePath, std::ios::binary);
    if (!inputFile.is_open()) {
        handleErrors("Failed to open input file.");
    }

    uint8_t iv[IV_SIZE], tag[TAG_SIZE];
    inputFile.read(reinterpret_cast<char*>(iv), IV_SIZE);
    inputFile.read(reinterpret_cast<char*>(tag), TAG_SIZE);

    EVP_CIPHER_CTX* ctx;
    initCipherContext(ctx, key, iv, false);

    std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    std::vector<unsigned char> decryptedText(buffer.size());

    int len = 0, plaintextLen = 0;
    if (1 != EVP_DecryptUpdate(ctx, decryptedText.data(), &len, buffer.data(), buffer.size())) {
        handleErrors("Decryption failed.");
    }
    plaintextLen += len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag)) {
        handleErrors("Failed to set expected tag.");
    }

    if (1 != EVP_DecryptFinal_ex(ctx, decryptedText.data() + len, &len)) {
        handleErrors("Tag verification failed.");
    }
    plaintextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    std::string ptOutput(decryptedText.begin(), decryptedText.begin() + plaintextLen);
    
    // Fix: Delete first character if it's a space
    if (!ptOutput.empty() && ptOutput[0] == ' ') {
        ptOutput.erase(0, 1);
    }

    return ptOutput;
}

#endif // FILESERVER_ENCRYPTION_H
