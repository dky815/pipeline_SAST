#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <memory>
#include <iostream>
#include <string>

// USAGE:
// 1. Create RSAKeyPairGenerator object with keysize. Default is 2048.
// 2. Call generateKeyPair to generate key pair.
// 3. Call savePrivateKey and savePublicKey and specify location to save the private and public key file.
class RSAKeyPairGenerator {
public:
    RSAKeyPairGenerator(int keySize = 2048) : keySize_(keySize) {}

    // Generate RSA key pair using EVP functions
    bool generateKeyPair() {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx) {
            std::cerr << "Error creating EVP_PKEY_CTX." << std::endl;
            return false;
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            std::cerr << "Error initializing key generation." << std::endl;
            return false;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keySize_) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            std::cerr << "Error setting RSA key size." << std::endl;
            return false;
        }

        EVP_PKEY* pkey = NULL;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            std::cerr << "Error generating RSA key pair." << std::endl;
            return false;
        }

        pkey_.reset(pkey); // pkey will be freed when pkey_ is destructed
        EVP_PKEY_CTX_free(ctx);

        return true;
    }

    // Save private key to given filepath using PEM format
    bool savePrivateKey(const std::string& filepath) {
        BIO* bp_private = BIO_new_file(filepath.c_str(), "w+");
        if (!bp_private) {
            std::cerr << "Error opening file for private key: " << filepath << std::endl;
            return false;
        }

        if (PEM_write_bio_PrivateKey(bp_private, pkey_.get(), NULL, NULL, 0, NULL, NULL) != 1) {
            BIO_free_all(bp_private);
            std::cerr << "Error writing private key to file." << std::endl;
            return false;
        }

        BIO_free_all(bp_private);
        return true;
    }

    // Save public key to given filepath using PEM format
    bool savePublicKey(const std::string& filepath) {
        BIO* bp_public = BIO_new_file(filepath.c_str(), "w+");
        if (!bp_public) {
            std::cerr << "Error opening file for public key." << std::endl;
            return false;
        }

        if (PEM_write_bio_PUBKEY(bp_public, pkey_.get()) != 1) {
            BIO_free_all(bp_public);
            std::cerr << "Error writing public key to file." << std::endl;
            return false;
        }

        BIO_free_all(bp_public);
        return true;
    }

private:
    struct EVP_PKEYDeleter {
        void operator()(EVP_PKEY* ptr) const { EVP_PKEY_free(ptr); }
    };

    using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEYDeleter>;

    int keySize_;
    EVP_PKEY_ptr pkey_;
};
