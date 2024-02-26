FROM gcc:latest

# Install OpenSSL development packages
RUN apt-get update && \
    apt-get install -y libssl-dev

WORKDIR /root/bibifi

COPY main.cpp .
COPY encryption ./encryption
COPY file_operations ./file_operations
COPY helpers ./helpers
COPY user_management ./user_management

RUN g++ -std=c++17 main.cpp -o fileserver -lssl -lcrypto -I /root/bibifi