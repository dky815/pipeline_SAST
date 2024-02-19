#ifndef CMPT785_BIBIFI_RANDOMIZER_FUNCTION_H
#define CMPT785_BIBIFI_RANDOMIZER_FUNCTION_H

#include <string.h>
#include <random>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include "json.hpp"
using namespace std;
using json = nlohmann::json;

string Randomizer(int len);
json read_metadata_json(string path_to_metadata);
string get_filename(string randomized_name, string path_to_metadata);
string get_randomized_name(string filename, string path_to_metadata);
string get_randomized_file_path(string filepath, string path_to_metadata);
string get_plaintext_file_path(string randomized_filepath, string path_to_metadata);
string encrypt_filename(string filename, string path_to_metadata);
string decrypt_filename(string randomized_name, string path_to_metadata);

string Randomizer(int len) {
    static random_device rd;
    static mt19937 gen(rd());
    static const char alphanum[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    uniform_int_distribution<> distr(0, sizeof(alphanum) - 2);

    string randomString;
    randomString.reserve(len);

    for (int i = 0; i < len; ++i) {
        randomString += alphanum[distr(gen)];
    }

    return randomString;
}

json read_metadata_json(string path_to_metadata){
    ifstream metadata_file(path_to_metadata + "/metadata/metadata.json");
    if (!metadata_file.is_open()) {
        throw runtime_error("Failed to open metadata.json file");
    }

    json metadata_json = json::parse(metadata_file);
    return metadata_json;
}

string get_filename(string randomized_filename, string path_to_metadata){
    // Parsing JSON object
    ifstream metadata_file(path_to_metadata + "/metadata/metadata.json");
    if (!metadata_file.is_open()) {
        throw runtime_error("Failed to open metadata.json file");
    }
    json metadata_json = json::parse(metadata_file);
    // Fetching randomized_filename filepath mapping
    if (metadata_json[randomized_filename] == nullptr) {
        return "";
    } else {
        string decrypted_name = metadata_json[randomized_filename];
        int delete_upto = decrypted_name.find_last_of('/') + 1;
        decrypted_name.erase(0, delete_upto);
        return decrypted_name;
    }
}

string get_randomized_name(string filename, string path_to_metadata){
    // Create a JSON object
    json obj = read_metadata_json(path_to_metadata);
    string randomized_name;

    // Iterate over the JSON object and check the value of each key
    for (auto itr = obj.begin(); itr != obj.end(); ++itr) {
        if (itr.value() == filename) {
            randomized_name = itr.key();
            break;
        }
    }
    return randomized_name;
}

string get_randomized_file_path(string filepath, string path_to_metadata){
    char separator = '/';
    int i = 0;
    string randomized_path = "";
    // Temporary string used to split the string.
    string s,temp; 
    while (filepath[i] != '\0') {
        if (filepath[i] != separator) {
            // Append the char to the temp string.
            s += filepath[i]; 
        } else {
            temp = get_randomized_name(s, path_to_metadata);
            randomized_path = randomized_path+ "/" + temp;
            s.clear();
        }
        i++;
    }
    // Output the last stored word.
    temp = get_randomized_name(s, path_to_metadata);
    randomized_path = randomized_path+ "/" + temp;
    return randomized_path;
}

string get_plaintext_file_path(string randomized_filepath, string path_to_metadata){
    char separator = '/';
    int i = 1;
    string plaintext_path = "";
    // Temporary string used to split the string.
    string s,temp; 
    while (randomized_filepath[i] != '\0') {
        if (randomized_filepath[i] != separator) {
            // Append the char to the temp string.
            s += randomized_filepath[i]; 
        } else {
            temp = get_filename(s, path_to_metadata);
            plaintext_path = plaintext_path + "/" + temp;
            s.clear();
        }
        i++;
    }
    // Output the last stored word.
    temp = get_filename(s, path_to_metadata);
    plaintext_path = plaintext_path + "/" + temp;
    return plaintext_path;
}

string encrypt_filename(string filename, string path_to_metadata){
    //Generating the random string for filename
    string randomized_filename = Randomizer(10);
    //Reading the metadata JSON for inserting the randomizer-filename mapping
    ifstream metadata_file(path_to_metadata + "/metadata/metadata.json");
    if (!metadata_file.is_open()) {
        throw runtime_error("Failed to open metadata.json file");
    }
    json metadata_json = json::parse(metadata_file);
    json input_json = json::object();
    input_json[randomized_filename] = filename;

    //Inserting the new mapping into the metadata JSON file
    metadata_json.update(input_json.begin(), input_json.end(), true);
    ofstream file(path_to_metadata + "/metadata/metadata.json");

    //Writing into the metadata JSON file and returning the random string
    file << metadata_json;
    return randomized_filename;
}

string decrypt_filename(string randomized_filename, string path_to_metadata){
    string filename;
    //Fetching the filename from the metadata JSON file and returning the filename
    filename = get_filename(randomized_filename, path_to_metadata);
    return filename;
}

#endif // CMPT785_BIBIFI_RANDOMIZER_FUNCTION_H
