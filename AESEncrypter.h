#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vector>
#include <iostream>
#include <cstring>

namespace AESEncrypter {

    // Function to generate a random AES key of a specified size
    std::vector<unsigned char> generateKey(int keySize) {
        std::vector<unsigned char> key(keySize);
    
        if (RAND_bytes(key.data(), keySize) != 1) {
            // Handle the error; RAND_bytes returns 1 on success, 0 otherwise.
            std::cerr << "Error generating random AES key" << std::endl;
            return {};
        }
    
        return key;
    }
    
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        // AES_BLOCK_SIZE is typically 16 bytes for AES
        std::vector<unsigned char> iv(AES_BLOCK_SIZE);
        // Generate a random IV
        RAND_bytes(iv.data(), iv.size());
    
        // The buffer size includes space for IV, plaintext, and potential padding
        std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH);
        int len;
        int ciphertext_len;
    
        // Initialize the encryption operation with AES-256-CBC
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    
        // Encrypt the plaintext
        EVP_EncryptUpdate(ctx, ciphertext.data() + AES_BLOCK_SIZE, &len, plaintext.data(), plaintext.size());
        ciphertext_len = len + AES_BLOCK_SIZE; // Include the size of the IV
    
        // Finalize the encryption
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + AES_BLOCK_SIZE + len, &len);
        ciphertext_len += len;
    
        EVP_CIPHER_CTX_free(ctx);
    
        // Prepend the IV to the ciphertext
        std::memcpy(ciphertext.data(), iv.data(), AES_BLOCK_SIZE);
    
        ciphertext.resize(ciphertext_len); // Adjust the vector size to the actual ciphertext length
        return ciphertext;
    }
    
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ivAndCiphertext, const std::vector<unsigned char>& key) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        std::vector<unsigned char> iv(AES_BLOCK_SIZE);
        // Extract the IV from the beginning of the input
        std::memcpy(iv.data(), ivAndCiphertext.data(), AES_BLOCK_SIZE);
    
        // The actual ciphertext starts after the IV
        const unsigned char* ciphertext = ivAndCiphertext.data() + AES_BLOCK_SIZE;
        size_t ciphertext_len = ivAndCiphertext.size() - AES_BLOCK_SIZE;
    
        std::vector<unsigned char> plaintext(ciphertext_len + EVP_MAX_BLOCK_LENGTH); // Buffer for plaintext
        int len;
        int plaintext_len;
    
        // Initialize the decryption operation with AES-256-CBC
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    
        // Decrypt the ciphertext
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len);
        plaintext_len = len;
    
        // Finalize the decryption
        EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        plaintext_len += len;
    
        EVP_CIPHER_CTX_free(ctx);
        
        plaintext.resize(plaintext_len); // Adjust the vector size to the actual ciphertext length
        return plaintext;
    }

} // namespace AESEncrypter
