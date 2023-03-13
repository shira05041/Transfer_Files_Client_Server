# Transfer_Files_Client_Server

The project implements client-server software that allows files to be transferred encrypted over the network.
The server was written in Python and the client in C++. 
Saving the data was done by SQL tables.
The encryption was done using the crypto library.
The encryption was done as follows: 
the client generated a pair of RSA keys, sent the public key to the server. 
In response, the server returned an AES key encrypted with the public key. 
The client decrypted the key with their private key and so they can communicate with the shared AES key.
Each client is registered in the system with a unique ID, and for additional verification and checking that the information arrived correctly 
and not corrupted, a CRC calculation is performed on the file both at the server and at the client and a comparison is made between them.
