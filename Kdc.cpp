#include <bits/stdc++.h>
#include <iostream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>
#include <random>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>
#include <iostream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>

using namespace std;
using namespace CryptoPP;

string kdcEncrypt(const string& plainText, const string& key) {
    string cipherText;

    size_t keyLength = key.length();

    
    if (keyLength != 16 && keyLength != 24)
        throw std::runtime_error("Invalid key length. Key must be 16 or 24 bytes for AES encryption");

    
    CryptoPP::SecByteBlock aesKey(reinterpret_cast<const CryptoPP::byte*>(key.data()), keyLength);

   
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption(aesKey, keyLength, aesKey); // Use the same IV as key
    CryptoPP::StringSource(plainText, true, new CryptoPP::StreamTransformationFilter(encryption, new CryptoPP::StringSink(cipherText)));

    return cipherText;
}

string kdcDecrypt(const std::string& cipherText, const std::string& key) {
    string decryptedText;

    size_t keyLength = key.length();

    
    if (keyLength != 16 && keyLength != 24)
        throw std::runtime_error("Invalid key length. Key must be 16 or 24 bytes for AES decryption");

    
    CryptoPP::SecByteBlock aesKey(reinterpret_cast<const CryptoPP::byte*>(key.data()), keyLength);

    
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption(aesKey, keyLength, aesKey);
    CryptoPP::StringSource(cipherText, true, new CryptoPP::StreamTransformationFilter(decryption, new CryptoPP::StringSink(decryptedText)));

    return decryptedText;
}

pair<string, int> receiveMethod(int kdcSocket, int qLength) {
    int clientSocket;
    pair<string, int> pr;
    if (listen(kdcSocket, qLength) != 0) {
        cerr << "Listen failed." << endl;   

        clientSocket =  -1;
        pr = {"nan", clientSocket};
    }
    clientSocket = accept(kdcSocket, nullptr, nullptr);
    if (clientSocket < 0) {
        std::cerr << "KDC accept failed." << std::endl;
        close(clientSocket);

        clientSocket = -1;
        pr = {"nan", clientSocket};
    } else {
        char buffer[10024] = {0};
        recv(clientSocket, buffer, sizeof(buffer), 0);
        cout << "Message from Client: " << buffer << endl;

        string buff = buffer;

        pr = {buff, clientSocket};
    }

    return pr;
}

string generateRandomString(int length) {
    string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, characters.size() - 1);

    string randomString;
    for (int i = 0; i < length; ++i) {
        randomString += characters[dis(gen)];
    }

    return randomString;
}

string GenerateKeyFromInput(const string &input) {
    // Calculate SHA256 hash of the input
    SHA256 hash;
    CryptoPP::byte digest[SHA256::DIGESTSIZE];
    hash.Update(reinterpret_cast<const CryptoPP::byte*>(input.data()), input.size());
    hash.Final(digest);

    // Convert hash to hex string
    HexEncoder encoder;
    string encoded;
    encoder.Attach(new StringSink(encoded));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    return encoded.substr(0, 16); // We take only first 16 characters as a key
}

int main() {

    // Data Table which KDC has contains user id and corresponding key
    map<string, string> db;
    db["Alice"] = "3BC51062973C458D";
    db["Bob"] = "CD9FB1E148CCD844";

    int kdcSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (kdcSocket == -1) {
        cerr << "KDC Socket creation failed." << endl;

        return 0;
    }

    sockaddr_in kdcAddress;
    kdcAddress.sin_family = AF_INET;
    kdcAddress.sin_port = htons(8081);
    kdcAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(kdcSocket, (struct sockaddr*)&kdcAddress, sizeof(kdcAddress))) {
        cerr << "KDC Socket binding failed." << endl;
        close(kdcSocket);

        return 0;
    }
    
    cout << "----------------------Step 1 Starting----------------------------" << endl;
    pair<string, int> pr = receiveMethod(kdcSocket, 5);
    int clientSocket = pr.second;
    string dataReceived1 = pr.first;
    string node1, node2;
    int aliceNonce;
    if (clientSocket != -1) {
        vector<string> tokens;
        string token;
        stringstream ss(dataReceived1);
        while (getline(ss, token, '-')) {
            tokens.push_back(token);
        }
        if (db.find(tokens[0]) != db.end() && db.find(tokens[1]) != db.end()) {
            cout << "Both the users are present in KDC Database" << endl;
            aliceNonce = stoi(tokens[2]);
            node1 = tokens[0];
            node2 = tokens[1];
            cout << "Step 1 completed" << endl;
            cout << tokens[0] << " " << tokens[1] << " " << tokens[2] << endl;
        } else {
            cout << "User not present in KDC Database" << endl;
            close(kdcSocket);
            
            return 0;
        }
    } else {
        cout << "Closing the socket" << endl;
        close(kdcSocket);
        return 0;
    }

    /*------------------------------Step 2---------------------------------------------*/
    cout << "----------------------Step 2 starting-------------------" << endl;
    string randomString = generateRandomString(10);
    string symmetricKeyAB = GenerateKeyFromInput(randomString);

    string ticketForBob = node1 + '-' + symmetricKeyAB;
    string cipherTicketForBob = kdcEncrypt(ticketForBob, db[node2]);

    string step2Data = to_string(aliceNonce) + "---" + node2 + "---" + symmetricKeyAB + "---" + cipherTicketForBob;
    string cipherStep2Data = kdcEncrypt(step2Data, db[node1]);
    const char* message2 = cipherStep2Data.c_str();
    
    if (send(clientSocket, message2, strlen(message2), 0) == -1) {
        cerr << "Sending Failed" << endl;
        close(kdcSocket);
        return 0;
    } else {
        cout << "Sending Successful" << endl;
    }

    return 0;
}