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

int sendMethod(int aliceSocket, string node1, string node2, int aliceNonce) {
    string temp = node1 + '-' + node2 + '-' + to_string(aliceNonce);
    const char* message = temp.c_str();
    cout << "------------------Step 1 starting----------------------" << endl;
    cout << "Sending alice user id, bob user id and alice nonce to kdc in hyphen separated format" << endl;
    if (send(aliceSocket, message, strlen(message), 0) == -1) {
        cerr << "Sending Failed" << endl;
        return -1;
    } else {
        cout << "Sending Successful" << endl;
        return 0;
    }
}

int main() {
    string node1 = "Alice";
    string node2 = "Bob";

    string aliceKey = "3BC51062973C458D";

    // Generate random nonce for Alice
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(1, 10000);
    int aliceNonce = dis(gen);

    // Creating socket for Alice
    int aliceSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (aliceSocket == -1) {
        cerr << "Alice Socket creation failed." << endl;
        return 0;
    }

    // Defining server address
    sockaddr_in kdcAddress;
    kdcAddress.sin_family = AF_INET;
    kdcAddress.sin_port = htons(8081);
    kdcAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

    string decryptedDataStep2;
    if (connect(aliceSocket, (struct sockaddr*)&kdcAddress, sizeof(kdcAddress)) != 0) {
        cerr << "Connection with KDC failed." << endl;
        close(aliceSocket);
        return 0;
    } else {
        cout << "Connection establised with KDC for step 1" << endl;
        if (sendMethod(aliceSocket, node1, node2, aliceNonce) == -1) {
            return 0;
        } else {
            cout << "-------------------Step 2 starting-----------------" << endl;
            char buffer[10024] = {0};
            recv(aliceSocket, buffer, sizeof(buffer), 0);
            
            string buff2 = buffer;
            cout << "Encrypted data received from kdc is " << buff2 << endl;
            decryptedDataStep2 = Decrypt(buff2, aliceKey);
            cout << "Decrypted data received from kdc is " << decryptedDataStep2 << endl;            
        }
    }

    vector<string> tokens;
    tokenize(tokens, decryptedDataStep2, "---");
    
    if (aliceNonce == stoi(tokens[0]) && node2 == tokens[1]) {
        cout << "Step 2 completed" << endl;
    } else {
        cout << "Wrong data received from Kdc" << endl;
    }

    cout << "------------------Step 3 starting----------------------" << endl;
    string symmetricKeyAB = tokens[2];
    string encryptedTicketForBob = tokens[3];

    sockaddr_in bobAddress;
    bobAddress.sin_family = AF_INET;
    bobAddress.sin_port = htons(8085);
    bobAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

    close(aliceSocket);
    aliceSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (connect(aliceSocket, (struct sockaddr*)&bobAddress, sizeof(bobAddress)) != 0) {
        cerr << "Connection with bob failed." << endl;
        close(aliceSocket);
        return 0;
    } else {
        cout << "Connection establised with bob for step 3" << endl;
        const char *message1 = encryptedTicketForBob.c_str();
        if (send(aliceSocket, message1, strlen(message1), 0) == -1) {
            cerr << "Sending Failed" << endl;
            return 0;
        } else {
            cout << "Sending Successful" << endl;
        }
    }
    cout << "----------------Step 4 starting----------------------" << endl;
    char buffer1[10024] = {0};
    recv(aliceSocket, buffer1, sizeof(buffer1), 0);
            
    string buff3 = buffer1;
    string decryptedDataStep4;
    cout << "Encrypted data received from bob is " << buff3 << endl;
    decryptedDataStep4 = Decrypt(buff3, symmetricKeyAB);

    int bobNonce = stoi(decryptedDataStep4);
    
    cout << "Decrypted data received from bob is " << decryptedDataStep4 << endl;
    cout << "Alice has authenticated Bob" << endl;
    cout << "Step 4 completed" << endl;

    cout << "-----------------Step 5 starting------------------------------" << endl;
    bobNonce--;
    string strBobNonce = to_string(bobNonce);
    string encryptedData = Encrypt(strBobNonce, symmetricKeyAB);
    cout << "Encrypted data is " << encryptedData << endl;
    const char *message2 = encryptedData.c_str();
    if (send(aliceSocket, message2, strlen(message2), 0) == -1) {
        cerr << "Sending Failed" << endl;
        return 0;
    } else {
        cout << "Sending Successful" << endl;
        close(aliceSocket);
    }


    return 0;
}