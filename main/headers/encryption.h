#ifndef CMPT785_BIBIFI_ENCRYPTION_H
#define CMPT785_BIBIFI_ENCRYPTION_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include "enc_consts.h"

using namespace std;

void handleErrors(string message);
void encrypt_file(string filePath, string content, vector<uint8_t> keyin);
string decrypt_file(string filePath, vector<uint8_t> keyin);

void handleErrors(string message) {
    cerr << message << endl;
    exit(EXIT_SUCCESS); // sending success signal despite error, to not exit from the program.
}

void encrypt_file(string filePath, string content, vector<uint8_t> keyin) {
    unsigned char* key = keyin.data();
    // generate random iv for each file
    uint8_t iv[IV_SIZE];
    RAND_bytes(iv, sizeof(iv));
    // Buffer for the tag
    unsigned char tag[TAG_SIZE];

    // Generate the output file path.
    string output_filepath = filePath;

    // Open the output file for writing.
    ofstream output_file(output_filepath);
    if (!output_file) {
        handleErrors("Failed to create target file.");
    }

    // Initialize the encryption context.
    EVP_CIPHER_CTX *ctx;
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("Encryption context could not be initialized. Aborting.");

    // Initialise the encryption operation
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))
        handleErrors("Failed to set encryption variables. Aborting.");
    // Set IV length
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL))
        handleErrors("Failed to set encryption variables. Aborting.");

    // Allocate buffers for the plaintext and ciphertext.
    unsigned char plaintext[BLOCK_SIZE];
    unsigned char ciphertext[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int len = 0;
    int ciphertext_len = 0;

    // allocate space for iv and tag at the beginning of the output file
    output_file.write("0", IV_SIZE);
    output_file.write("0", TAG_SIZE);

    // Read data from the input content string and encrypt it in chunks.
    size_t pos = 0;
    size_t length = content.length();
    while (pos < length) {
        int ptlen = length - pos;
        if(ptlen >= BLOCK_SIZE) {
            content.substr(pos, BLOCK_SIZE).copy((char*)plaintext, BLOCK_SIZE);
            ptlen = BLOCK_SIZE;
        }
        else {
            content.substr(pos, ptlen).copy((char*)plaintext, ptlen);
        }
        pos += ptlen;
        
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, ptlen)) {
            handleErrors("Encryption for entered content failed. Aborting.");
        }
        ciphertext_len = len;
        output_file.write((char*)ciphertext, ciphertext_len);
    }

    // Finalize the encryption.
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext, &len)) {
        handleErrors("Finalizing the encryption failed. Aborting.");
    }
    ciphertext_len = len;
    output_file.write((char*)ciphertext, ciphertext_len);

    // Get the tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag))
        handleErrors("Could not get authentication tag. Aborting.");

    // write iv and tag to the output file
    output_file.seekp(0);
    output_file.write((char*)iv, IV_SIZE);
    output_file.write((char*)tag, TAG_SIZE);

    // Clean up the context and close the files.
    EVP_CIPHER_CTX_free(ctx);
    output_file.close();
}

string decrypt_file(string filePath, vector<uint8_t> keyin) {
    unsigned char* key = keyin.data();
    string ptoutput = "";
    // Open the input file for reading.
    ifstream input_file(filePath);
    if (!input_file) {
        handleErrors("Failed to open file: " + filePath);
    }

    // Read tag and IV from the file.
    uint8_t iv[IV_SIZE];
    uint8_t tag[TAG_SIZE];
    input_file.read((char*)iv, IV_SIZE);
    input_file.read((char*)tag, TAG_SIZE);

    // Initialize the decryption context.
    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors("Decryption context could not be initialized.");
    }

    // Initialise the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        handleErrors("Failed to set encryption variables.");
    }

    // Set IV length
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL)) {
        handleErrors("Failed to set encryption variables.");
    }

    // Allocate buffers for the plaintext and ciphertext.
    unsigned char ciphertext[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char decryptedtext[BLOCK_SIZE];
    int len = 0;
    // Read data from the input file and decrypt it in chunks.
    while (input_file) {
        input_file.read((char*)ciphertext, BLOCK_SIZE);
        if (1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, input_file.gcount())) {
            handleErrors("Decryption failed for the given file.");
        }
        string str((char*)decryptedtext, len);
        ptoutput.append(str);
    }

    // Set expected tag
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *)tag)) {
        handleErrors("Failed to set tag for verification.");
    }

    // Finalize the decryption.
    // This step verifies if tag is fine and errors out in case of changes to encrypted files.
    if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext, &len)) {
        handleErrors("Message authentication failed. File has likely been tampered with.");
    }
    string str((char*)decryptedtext, len);
    ptoutput.append(str);

    // Clean up the context and close the files.
    EVP_CIPHER_CTX_free(ctx);
    input_file.close();

    // Delete first character if its a space
    if (!ptoutput.empty() && ptoutput[0] == ' ') { 
        ptoutput.erase(0, 1);
    }

    return ptoutput;
}

#endif // CMPT785_BIBIFI_ENCRYPTION_H
