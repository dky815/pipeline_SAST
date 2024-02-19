#include <iostream>
#include <sys/stat.h>

#include "headers/user_type.h"
#include "headers/user_authentication.h"
#include "headers/user_features.h"
#include "headers/encryption.h"

using namespace std;

int main(int argc, char *argv[]) {
  string filesystem_path = fs::current_path();
  struct stat sb;
  mode_t mode = 0766;
  if(stat("filesystem", &sb) == 0) {
    // check for correct number arguments
    // ./fileserver counts as 1st argument, keyfile_name counts as 2nd argument
    if(argc != 2) {
      cout << "Invalid keyfile"
          << endl;
      return 1;
    }
    else{
      string keyfile_name = argv[1];
      // user authenticated, allow "available commands" to be run
      string user_name = get_type_of_user(keyfile_name);
      User_type user_type;
      if(user_name == "admin")
        user_type = admin;
      else
        user_type = user;

      // read user's enc key from metadata file
      user_features(user_name, user_type, read_enc_key_from_metadata(user_name, ""), filesystem_path);
    }
  }
  else{
    mode_t old_umask = umask(0); // to ensure the following modes get set
    if (mkdir("public_keys", mode) != 0) {
      cerr << "Error creating public_keys." << endl;
      return 1;
    }
    if (mkdir("private_keys", mode) != 0) {
      cerr << "Error creating private_keys." << endl;
      return 1;
    }
    if (mkdir("metadata", mode) != 0) {
      cerr << "Error creating metadata directory." << endl;
      return 1;
    }
    if (mkdir("shared_files", mode) != 0) {
      cerr << "Error creating shared_files directory." << endl;
      return 1;
    }
    // if (mkfile("metadata.json", "{\"test\":\"123\"}") != 0) {
    //   cerr << "Error creating metadata.json ." << endl;
    //   return 1;
    // }
    if (mkdir("filesystem", mode) != 0) {
      cerr << "Error creating filesystem." << endl;
      return 1;
    }

    string metadata_path = "metadata/metadata.json";
    ofstream metadata_file(metadata_path);
    if (metadata_file) {
        // Write your JSON data to the file here
        metadata_file << "{\"test\":\"123\"}";
        metadata_file.close();
    } else {
    cerr << "Error creating metadata.json" << endl;
    return 1;
}

    umask(old_umask); // Restore the original umask value
    string user_name = "admin";
    add_user(user_name, filesystem_path, true);
    user_features(user_name, admin, read_enc_key_from_metadata(user_name, ""), filesystem_path);
  }
}
