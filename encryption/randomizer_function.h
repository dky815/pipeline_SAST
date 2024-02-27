#ifndef RANDOMIZER_FUNCTION_H
#define RANDOMIZER_FUNCTION_H

#include "helpers/json.hpp"
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <stdexcept>
#include <filesystem>

namespace fs = std::filesystem;
using json = nlohmann::json;

class FilenameRandomizer {
public:
    static std::string Randomize(int length);
    static json ReadMetadata(const std::string& path_to_metadata);
    static std::string GetFilename(const std::string& randomized_name, const std::string& path_to_metadata);
    static std::string GetRandomizedName(const std::string& filename, const std::string& path_to_metadata);
    static std::string GetRandomizedFilePath(const std::string& filepath, const std::string& path_to_metadata);
    static std::string GetPlaintextFilePath(const std::string& randomized_filepath, const std::string& path_to_metadata);
    static std::string EncryptFilename(const std::string& filename, const std::string& path_to_metadata);
    static std::string DecryptFilename(const std::string& randomized_name, const std::string& path_to_metadata);

private:
    static std::string GenerateRandomString(int length);
};

std::string FilenameRandomizer::GenerateRandomString(int length) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static const char alphanum[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";

    std::uniform_int_distribution<> distr(0, sizeof(alphanum) - 2);

    std::string randomString;
    randomString.reserve(length);

    for (int i = 0; i < length; ++i) {
        randomString += alphanum[distr(gen)];
    }

    return randomString;
}

json FilenameRandomizer::ReadMetadata(const std::string& path_to_metadata) {
    fs::path metadata_path = fs::path(path_to_metadata) / "common" / "structure.json";
    std::ifstream metadata_file(metadata_path);
    if (!metadata_file.is_open()) {
        throw std::runtime_error("Failed to open structure.json file");
    }

    json metadata_json = json::parse(metadata_file);
    return metadata_json;
}

std::string FilenameRandomizer::GetFilename(const std::string& randomized_name, const std::string& path_to_metadata) {
    json metadata_json = ReadMetadata(path_to_metadata);
    if (metadata_json.find(randomized_name) == metadata_json.end()) {
        return "";
    }
    std::string decrypted_name = metadata_json[randomized_name];
    return fs::path(decrypted_name).filename();
}

std::string FilenameRandomizer::GetRandomizedName(const std::string& filename, const std::string& path_to_metadata) {
    json obj = ReadMetadata(path_to_metadata);
    for (auto& [key, value] : obj.items()) {
        if (value == filename) {
            return key;
        }
    }
    return "";
}

std::string FilenameRandomizer::GetRandomizedFilePath(const std::string& filepath, const std::string& path_to_metadata) {
    fs::path path(filepath);
    fs::path randomized_path;
    for (const auto& part : path) {
        randomized_path /= GetRandomizedName(part.string(), path_to_metadata);
    }
    return randomized_path.string();
}

std::string FilenameRandomizer::GetPlaintextFilePath(const std::string& randomized_filepath, const std::string& path_to_metadata) {
    fs::path path(randomized_filepath);
    fs::path plaintext_path;
    for (const auto& part : path) {
        plaintext_path /= GetFilename(part.string(), path_to_metadata);
    }
    return plaintext_path.string();
}

std::string FilenameRandomizer::EncryptFilename(const std::string& filename, const std::string& path_to_metadata) {
    std::string randomized_filename = GenerateRandomString(10);
    json metadata_json = ReadMetadata(path_to_metadata);
    metadata_json[randomized_filename] = filename;
    fs::path metadata_path = fs::path(path_to_metadata) / "common" / "structure.json";
    std::ofstream file(metadata_path);
    file << metadata_json.dump(4);
    return randomized_filename;
}

std::string FilenameRandomizer::DecryptFilename(const std::string& randomized_name, const std::string& path_to_metadata) {
    return GetFilename(randomized_name, path_to_metadata);
}

#endif // RANDOMIZER_FUNCTION_H
