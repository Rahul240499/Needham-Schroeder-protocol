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
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>

using namespace std;

void tokenize(vector<string> &tokens, const string& str, const string& delimiter) {
    size_t pos = 0;
    size_t prevPos = 0;

    // Find the first occurrence of the delimiter
    pos = str.find(delimiter, prevPos);

    // Loop until we've found all occurrences of the delimiter
    while (pos != string::npos) {
        // Extract the token between prevPos and pos
        string token = str.substr(prevPos, pos - prevPos);
        
        // Add the token to the vector
        tokens.push_back(token);

        // Update prevPos to the position after the current delimiter
        prevPos = pos + delimiter.length();

        // Find the next occurrence of the delimiter
        pos = str.find(delimiter, prevPos);
    }

    // Add the last token after the last delimiter (or the whole string if no delimiters found)
    string lastToken = str.substr(prevPos);
    tokens.push_back(lastToken);

}

string Encrypt(const string& plainText, const string& key) {
    string cipherText;

    size_t keyLength = key.length();

    
    if (keyLength != 16 && keyLength != 24)
        throw std::runtime_error("Invalid key length. Key must be 16 or 24 bytes for AES encryption");

    
    CryptoPP::SecByteBlock aesKey(reinterpret_cast<const CryptoPP::byte*>(key.data()), keyLength);

   
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption(aesKey, keyLength, aesKey); // Use the same IV as key
    CryptoPP::StringSource(plainText, true, new CryptoPP::StreamTransformationFilter(encryption, new CryptoPP::StringSink(cipherText)));

    return cipherText;
}

string Decrypt(const std::string& cipherText, const std::string& key) {
    string decryptedText;

    size_t keyLength = key.length();

    
    if (keyLength != 16 && keyLength != 24)
        throw std::runtime_error("Invalid key length. Key must be 16 or 24 bytes for AES decryption");

    
    CryptoPP::SecByteBlock aesKey(reinterpret_cast<const CryptoPP::byte*>(key.data()), keyLength);

    
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption(aesKey, keyLength, aesKey);
    CryptoPP::StringSource(cipherText, true, new CryptoPP::StreamTransformationFilter(decryption, new CryptoPP::StringSink(decryptedText)));

    return decryptedText;
}

pair<string, int> receiveMethod(int bobSocket, int qLength) {
    int aliceSocket;
    pair<string, int> pr;
    if (listen(bobSocket, qLength) != 0) {
        cerr << "Listen failed." << endl;

        aliceSocket =  -1;
        pr = {"nan", aliceSocket};
    }
    aliceSocket = accept(bobSocket, nullptr, nullptr);
    if (aliceSocket < 0) {
        cerr << "alice accept failed." << std::endl;
        close(aliceSocket);

        aliceSocket = -1;
        pr = {"nan", aliceSocket};
    } else {
        char buffer[10024] = {0};
        recv(aliceSocket, buffer, sizeof(buffer), 0);
        cout << "--------------Step 3 starting ------------" << endl;

        cout << "Message from Alice: " << buffer << endl;

        string buff = buffer;

        pr = {buff, aliceSocket};
    }

    return pr;
}

int main() {
    string node1 = "Alice";
    string node2 = "Bob";

    string bobKey = "CD9FB1E148CCD844";

    // Generate random nonce for Alice
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(1, 10000);
    int bobNonce = dis(gen);

    int bobSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (bobSocket == -1) {
        cerr << "Bob Socket creation failed." << endl;

        return 0;
    }

    sockaddr_in bobAddress;
    bobAddress.sin_family = AF_INET;
    bobAddress.sin_port = htons(8085);
    bobAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(bobSocket, (struct sockaddr*)&bobAddress, sizeof(bobAddress))) {
        cerr << "Bob Socket binding failed." << endl;
        close(bobSocket);

        return 0;
    }

    pair<string, int> pr = receiveMethod(bobSocket, 1);
    int aliceSocket = pr.second;
    string encryptedDataReceived1 = pr.first;

    string dataReceivedFromAlice1;
    if (aliceSocket != -1) {
        dataReceivedFromAlice1 = Decrypt(encryptedDataReceived1, bobKey);
        cout << "Decrypted data from Alice is " << dataReceivedFromAlice1 << endl;
    } else {
        cout << "Closing the socket" << endl;
        close(bobSocket);

        return 0;
    }

    cout << "Step 3 completed" << endl;


    cout << "-----------------Step 4 starting--------------------" << endl;
    vector<string> tokens;
    tokenize(tokens, dataReceivedFromAlice1, "-");

    string nodeName = tokens[0];
    string symmetricKeyAB = tokens[1];

    string dataForAlice = to_string(bobNonce);
    string encryptedDataForAlice = Encrypt(dataForAlice, symmetricKeyAB);

    const char *messageForAlice = encryptedDataForAlice.c_str();
    if (send(aliceSocket, messageForAlice, strlen(messageForAlice), 0) == -1) {
        cerr << "Sending Failed" << endl;
        close(bobSocket);
        return 0;
    } else {
        cout << "Sending Successful" << endl;
        cout << "Have sent my nonce " << bobNonce << " to Alice" << endl; 
    }

    cout << "--------------------Step 5 starting--------------------------" << endl;

    char buffer1[10024] = {0};
    recv(aliceSocket, buffer1, sizeof(buffer1), 0);
            
    string buff3 = buffer1;
    string decryptedDataStep5;
    cout << "Encrypted data received from bob is " << buff3 << endl;
    decryptedDataStep5 = Decrypt(buff3, symmetricKeyAB);
    cout << "Decrypted data received from bob is " << decryptedDataStep5 << endl;

    int receivedData = stoi(decryptedDataStep5);

    if (receivedData == bobNonce - 1) {
        cout << "Bob authenticates Alice" << endl;
    }

    cout << "-----------------------Needham Schroder Protocol Finished--------------------------" << endl;
    close(bobSocket);

    return 0;

}

/*
terminate called after throwing an instance of 'CryptoPP::InvalidCiphertext'
  what():  StreamTransformationFilter: ciphertext length is not a multiple of block size
Aborted (core dumped)
*/