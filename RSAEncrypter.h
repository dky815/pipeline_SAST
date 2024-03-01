#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>
#include <string>

class RSAEncrypter {
public:
    // Encrypt a message using an RSA public key from a file
    std::vector<unsigned char> encrypt(const std::string& publicKeyFile, const std::vector<unsigned char>& msg) {
        RSA* publicKey = loadPublicKey(publicKeyFile);
        if (!publicKey) {
            std::cerr << "Failed to load public key." << std::endl;
            return {};
        }

        std::vector<unsigned char> encrypted(RSA_size(publicKey));
        int result = RSA_public_encrypt(msg.size(), msg.data(), encrypted.data(), publicKey, RSA_PKCS1_OAEP_PADDING);
        RSA_free(publicKey); // Free the RSA public key

        if (result == -1) {
            printLastError("Encryption failed");
            return {};
        }

        encrypted.resize(result); // Adjust to the actual encrypted size
        return encrypted;
    }

    // Decrypt a message using an RSA private key from a file
    std::vector<unsigned char> decrypt(const std::string& privateKeyFile, const std::vector<unsigned char>& encryptedMsg) {
        RSA* privateKey = loadPrivateKey(privateKeyFile);
        if (!privateKey) {
            std::cerr << "Failed to load private key." << std::endl;
            return {};
        }

        std::vector<unsigned char> decrypted(RSA_size(privateKey));
        int result = RSA_private_decrypt(encryptedMsg.size(), encryptedMsg.data(), decrypted.data(), privateKey, RSA_PKCS1_OAEP_PADDING);
        RSA_free(privateKey); // Free the RSA private key

        if (result == -1) {
            printLastError("Decryption failed");
            return {};
        }
        
        decrypted.resize(result); // Adjust to the actual decrypted size
        return decrypted;
    }

private:
    // Load RSA public key from a file
    RSA* loadPublicKey(const std::string& publicKeyFile) {
        FILE* fp = fopen(publicKeyFile.c_str(), "rb");
        if (!fp) {
            std::cerr << "Unable to open public key file." << std::endl;
            return nullptr;
        }

        RSA* rsa = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);
        fclose(fp);
        return rsa;
    }

    // Load RSA private key from a file
    RSA* loadPrivateKey(const std::string& privateKeyFile) {
        FILE* fp = fopen(privateKeyFile.c_str(), "rb");
        if (!fp) {
            std::cerr << "Unable to open private key file." << std::endl;
            return nullptr;
        }

        RSA* rsa = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
        fclose(fp);
        return rsa;
    }

    // Helper function to print the last OpenSSL error
    void printLastError(const std::string& message) {
        char* err = (char*)malloc(130);
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        std::cerr << message << ": " << err << std::endl;
        free(err);
    }
};
