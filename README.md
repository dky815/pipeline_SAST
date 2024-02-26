# CMPT 785 BIBIFI - Build it, Break it, Fix it

Build it - "Encrypted Secure File System"
The encrypted file system will reside on the host file system as a regular file system but with more security. This file
system is being used by multiple clients/users since we can't afford to have different storage for each of our users and
want to optimally use all of the available storage.

<b>Build a C++ executable that acts as a middleware to access the encrypted secure filesystem on a need-to-access basis.
Users looking at the file system on the host machine should not be able to deduce any information from it about the data
as well as the user. </b>

All the groups will implement all the functional requirements listed below.

## Functional Requirements

Access the file system using the below command which should spawn a shell listing all the available commands to the
user.

`./fileserver keyfile_name`

This should create a new directory called "filesystem" in the current directory (if it doesn't already exist) which will
act as our encrypted filesystem. It should also create the admin_keyfile along with creating the filesystem.

Failed login : Print "Invalid keyfile" and exit.

Successful login : Print "Logged in as {username}" and provide a shell with the given features. The current directory
for the new shell will be "/", with personal and shared directories available for the current user.

- 2 types of users (1 admin, N users)
    - User features
        - `cd <directory>`   - The user will provide the directory to move to. It should accept `.` and `..` as current and
          parent directories respectively and support changing multiple directories at once (cd ../../dir1/dir2). cd /
          should take you to the current user’s root directory. If a directory doesn't exist, the user should stay in the
          current directory.
        - `pwd`   - Print the current directory. Each user should have /personal and /shared base directories.
        - `ls`   - List the files and directories in the current directory separated by a new line. You need to show the
          directories `.` and `..` as well. To differentiate between a file and a directory, the output should look as
          follows
            - d -> .
            - d -> ..
            - d -> directory1
            - f -> file1
        - `cat <filename>`   - Read the actual (decrypted) contents of the file. If the file doesn't exist,
          print "<filename> doesn't exist"
        - `share <filename> <username>`   - Share the file with the target user which should appear under the `/shared`
          directory of the target user. The files are shared only with read permission. The shared directory must be
          read-only. If the file doesn't exist, print "File <filename> doesn't exist". If the user doesn't exist,
          print "User <username> doesn't exist". First check will be on the file.
        - `mkdir <directory_name>`   - Create a new directory. If a directory with this name exists, print "Directory
          already exists"
        - `mkfile <filename> <contents>`   - Create a new file with the contents. The contents will be printable ascii
          characters. If a file with <filename> exists, it should replace the contents. If the file was previously
          shared, the target user should see the new contents of the file.
        - `exit`   - Terminate the program.
    - Admin specific features
        - Admin should have access to read the entire file system with all user features
        - `adduser <username>`  - This command should create a keyfile called username_keyfile on the host which will be
          used by the user to access the filesystem. If a user with this name already exists, print "User <username>
          already exists"


## Design Decisions for preventing Specific attacks

### `cd` command
- It doesn't go outside the valid root path which prevents unauthorization access and directory traversal attacks.
- It doesn't accept `backticks` for the directory name which prevents arbitrary code execution or code injection attacks.

### `mkdir <directory_name>` command
- It doesn't go outside the valid root path which prevents unauthorization access and directory traversal attacks.
- It doesn't accept `backticks` for the directory name which prevents arbitrary code execution or code injection attacks.
- It does not accept spaces in the directory names.

### `mkfile <filename> <contents>` command
- It doesn't go outside the valid root path of the user which prevents directory traversal attacks.
- It doesn't accept `backticks` for the directory name which prevents arbitrary code execution or code injection attacks.
- filename can have a max length of 255 characters which can prevent denial of service attack.
- [Checks for valid filenames](https://stackoverflow.com/questions/11794144/regular-expression-for-valid-filename)
  - This guarantees that solely the letters of the English alphabet are employed.
  - There are no spaces at the start or end.
  - Examples: `web.config, hosts, .gitignore, httpd.conf, .htaccess`.
  - The following file creations are allowed
    - `web.config`
    - `httpd.conf`
    - `test.txt`
    - `1.1`
    - `my long file name.txt`
  - The following file creations are NOT allowed (though in reality they're valid):
    - `æøå.txt`
    - `.gitignore`
    - `.htaccess`

### `Encryption Algorithm`
- While it is difficult to declare one cryptographic algorithm absolutely better than all others, in case of file system encryption, using AES was a good bet. 
- Decided to use AES in GCM mode with sufficiently large key and tag sizes, to have message authentication in place, which would avoid attacks on data integrity.
- Security in AES GCM relies heavily on nonce uniqueness, therefore, a unique IV is being generated for each file to be encrypted.


## Running the program Locally

To create executable named `fileserver`, run the following command:
`g++ -std=c++17 -o fileserver main.cpp -L<path_to_openssl>/lib -I<path_to_openssl>/include -lssl -lcrypto`
for macOS it might be: `/usr/local/opt/openssl@3`

- To execute the program, enter `./fileserver keyfile_name` in the cli.

- You can even run it using Docker
  1. docker build -t fileserver .
  2. docker run -it --name fileserver-container fileserver:latest /bin/bash
