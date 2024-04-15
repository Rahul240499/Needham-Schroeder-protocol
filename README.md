**Needham–Schroeder Protocol Implementation**

This repository contains an implementation of the Needham–Schroeder protocol, a key distribution protocol designed to establish a secure communication channel between two parties over an insecure network. The protocol utilizes a trusted Key Distribution Center (KDC) to facilitate secure key exchange.

To run this project, first compile all three files:

```
g++ Kdc.cpp -lcryptopp -o Kdc
g++ Alice.cpp -lcryptopp -o Alice
g++ Bob.cpp -lcryptopp -o Bob
```

Then, execute the following steps in order:

1. Run the Key Distribution Center (KDC).
2. Run Bob, the party receiving communication.
3. Finally, run Alice, the party initiating communication.

Example command to run:

```
./Kdc
./Bob
./Alice
```

**Reference Image:**

![Needham-Schroeder Protocol](needham-schroeder-protocol.png)

*Image Reference: "Cryptography and Network Security: Principles and Practice" by William Stallings*
