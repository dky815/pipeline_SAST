#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <iostream>
#include <string>

// USAGE:
// 1. Create RSAKeyPairValidator object with paths to the public and private keys.
// 2. call loadKeys to load public and private keys.
// 3. call validateKeyPair to verify if public and private keys match. It will return True if it matches and False if it does not match.
class RSAKeyPairValidator {
public:
    RSAKeyPairValidator(const std::string& publicKeyPath, const std::string& privateKeyPath)
        : publicKeyPath_(publicKeyPath), privateKeyPath_(privateKeyPath) {}

    ~RSAKeyPairValidator() {
        if (pkeyPublic_) {
            EVP_PKEY_free(pkeyPublic_);
        }
        if (pkeyPrivate_) {
            EVP_PKEY_free(pkeyPrivate_);
        }
    }

    bool loadKeys() {
        pkeyPublic_ = loadPublicKey(publicKeyPath_);
        pkeyPrivate_ = loadPrivateKey(privateKeyPath_);

        return pkeyPublic_ && pkeyPrivate_;
    }

    // Validates if the public and private keys match
    bool validateKeyPair() {
        if (!pkeyPublic_ || !pkeyPrivate_) {
            std::cerr << "Keys not loaded." << std::endl;
            return false;
        }

        int result = EVP_PKEY_eq(pkeyPublic_, pkeyPrivate_);
        return result == 1;
    }

private:
    std::string publicKeyPath_;
    std::string privateKeyPath_;
    EVP_PKEY* pkeyPublic_ = nullptr;
    EVP_PKEY* pkeyPrivate_ = nullptr;

    EVP_PKEY* loadPrivateKey(const std::string& path) {
        FILE* file = fopen(path.c_str(), "rb");
        if (!file) return nullptr;
        EVP_PKEY* pkey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
        fclose(file);
        return pkey;
    }

    EVP_PKEY* loadPublicKey(const std::string& path) {
        FILE* file = fopen(path.c_str(), "rb");
        if (!file) return nullptr;
        EVP_PKEY* pkey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
        fclose(file);
        return pkey;
    }
};
