FROM gcc:latest

# Install OpenSSL development packages
RUN apt-get update && \
    apt-get install -y libssl-dev

WORKDIR /root/bibifi

COPY main.cpp .
COPY encryption ./encryption
COPY features ./features
COPY helpers ./helpers
COPY authentication ./authentication

RUN g++ -std=c++17 main.cpp -o fileserver -lssl -lcrypto -I /root/bibifi