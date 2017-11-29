# Phase 4


For phase three of this project, we were tasked with creating measures to protect from four threats. These threats are Message Reorder, Replay, or Modification; File Leakage; and Token Theft. To overcome Message reorder, replay, or modification, we decided to use a monotonically increasing timestamp on all messages sent, Diffie Hellman (from last phase) to help protect from replay attacks, and encrypt each message using the session key (specifics in T5). In terms of File Leakage, we decided to generate a group key for each group (updating the key as group members change) (specifics in T6). Lastly, to protect against Token Theft, we decided to use the included RSA fingerprint in the token (Specifics in T7).


## T5 Message Reorder, Replay, or Modification


**Description of threat:**  
The possibility of an attacker to reorder, replay, or modify messages is dangerous for our system. Reorder and replay can cause the user and the server to believe they have been authenticated when they haven’t been, and modification can make the server believe it is connected to a different user than it actually is. These are important threats to protect against in order to have a properly secured system.  
**Mechanism:**  
To protect against Reorder attacks and same-session replay attacks every message sent will be sent with a message number. Message numbers will always increase so that once a message has been used once it can not be used again. When a message is received it will be checked against the other received message numbers to make sure that all previous messages have been received. We will have a counter keeping track of the current number of sent and received messages and if one is received out of order it will be put into a queue and processed once we are at that number. Replay attacks are also protected by using a Integrity session key obtained through diffie hellman. Diffie Hellman is the same as in the previous phase except we generate a second key to use soley for integrity thus keeping our confidentiality and integrity mechanisms separate. To protect against modification, each message sent is also sent with an HMAC. The HMAC is computer by doing HMAC(k, m) = H((k XOR opad) || H(k XOR ipad) || m). The opad is 0x5c * 64 and the ipad is 0x36 * 64. This value can be recomputed and if they match then you know the message has not been modified.

**Arguments:**  
Reorder attacks will be protected by numbers since as messages are received they get used if they are in order otherwise are put in a queue until it is their time to get used. This also protects against same-session replay attacks because the messages will stop working after they have been used since the counter will move past their number. For multi-session replay attacks a session key protects against since no messages are encrypted the same way. modification attacks will be protected against since you are using a session key so no else could decrypt them. Also the to add more confusion the key is hashed after being XOR'd with two values who are chosen because of the large hamming distance between them but are also based off the key that attackers don't know. Any change to the message will greatly change this HMAC value so if the verification fails you know the message has been touched.


![T5](https://github.com/EricGhildyal/CS1653CryptoProject/blob/master/reports/images/t5.jpg)


## T6 File Leakage


**Description of threat:**  
File servers are important in the notion of a group file system, but since they are not trusted, there is a big possibility they will attempt to steal files and leak them to other users or administrators. This threats causes a complete breakdown of the security of our system, and therefore is very important to protect against.  
**Mechanism:**  
When a group is created, a 256 bit AES key is generated to represent that group.
The generated key will then be sent to the user (encrypted by the session key) in order to be put into user’s KeyRing with the correct version number  
A KeyRing is a wrapper class for a list of keys, but has the ability to reference multiple keys for each group/reference string, depending on a version number.  
When a file is requested, it will be sent with a version number that corresponds to a key version that the KeyRing stores.  
When a user is deleted from a group, a new key will be generated with an incremented by one version number for the group and sent as needed to group members.
  
**Arguments:**  
This mechanism makes sure all members of a group have the same key and that the key is sent in a secure manner. In order to keep every user up to date and prevent old users from snooping, a new key will be generated every time a user leaves a group. We are using a 256 bit AES key because it is still secure. We do not have to re-encrypt every file because we can assume the user has all the files they had access to downloaded locally already. When a user leaves a group, a new key is generated and the version number incremented by one. When an existing user attempts to retrieve a new file that they do not have the correct version number for, they can request the key from the group server.



![T6](https://github.com/EricGhildyal/CS1653CryptoProject/blob/master/reports/images/t6.jpg)


## T7 Token Theft


**Description of threat:**  
The ability for a file server to steal tokens means that attacker could pretend to be any user on any server. This could even extend to an attacker gaining admin credentials and effectively shutting down the entire server by deleting all the users.  
**Mechanism:**  
As in T4, the user establishes a secure connection with the Group Server using Diffie Hellman and AES in CBC mode.
The user will submit a request for a token to the group server, which includes a username and password.
As in T2, the server will return a signed token, but instead of this token being used for authentication with file servers, it will only be used for further authentication with the group server.
Whenever the user wants to access a file server it must first get a signed token from the group server that includes the public RSA key of a target server. If the user has this cached it may use it, but otherwise they must contact the group server, authenticating with their token and providing the fileserver's public key, to get a new token signed.
The user will then send this new token to file server, which makes the same signature checks for token modification and forgery as in T2, but now also check for the inclusion of the file server's public rsa fingerprint in the signature.  
**Arguments:**  
This mechanism protects against file servers from stealing your key and using it on other servers because of the included RSA fingerprint in the token that will cause any server other than the one listed in the token to reject the token.
This also still protects against token forgery (T3) because the group server still signs the token, and the token without any target servers listed should never be sent to any file servers. This also uses signed Diffie Hellman to establish a session key, so that no information can be stolen by a man-in-the-middle attack or by passive monitoring (T4).


![T7](https://github.com/EricGhildyal/CS1653CryptoProject/blob/master/reports/images/t7.jpg)


## Conclusion
From the mechanisms we designed none of them protect against multiple threats. For each threat, our group took the approach of each of us coming up with a proposed solution then discussing the pros and cons of each until deciding on one. This allowed us to have multiple options and potentially mix our solutions if one of us considered different risks than others. The discussion phase was probably the longest part of the design process as we didn’t choose one until we all agreed with it. After agreeing on one and writing up we then all checked it to make sure it was written the way we discussed it.

## Ongoing Concerns
With T5, we are not modifying any of the algorithms from T1 - T4, the session key is established the same way, and adding timestamps to each request does not impact T1 - T4 in any meaningful way.  
T6 also has no affect on previous algorithms, since our implementation will simply add local encryption on the file servers. Other than the transmission of symmetric group keys, and encrypted data instead of raw data, this has no affect on previous algorithms.  
T7 does have an affect on T1 and T2, since it requires changing the contents of the authentication token. The token that we had for T1 and T2 will now be used solely for group server authentication, to get file server specific tokens. These tokens behave in much the same way, but with the added check by the file server to make sure that they are the target server for that token. Therefore, since no major modifications are made to the tokens other than an addition of one more field, it maintains the security of T1 and T2.


## Extra Credit
For the extra credit portion of this section, we decided to unit test our cryptographic functions to make sure they work as we intend and expect them to. Even though all of our cryptographic functions are through Bouncy Castle, it is still good practice to verify they work correctly for our use cases. In general, wrote our tests in the positive and the negative. In order to do this, we wrote unit tests that created a key, encrypted a string then decrypted it and verifying that the initial string and the output string are the same. To test the negative, we do the same as above, but alter a byte in the ciphertext and test to see if it fails. To test RSA keys, we wrote 2 tests, one for encrypting with public key and decrypting with private key, and another for encrypting with private key and decrypting with public key. To test hashing, we used an online SHA256 hash calculator to hash a string, then compare that hash to the one our program generates. Finally, to test the KeyRing, we create a keyring and populate it with our generated keys. From there, we did the same positive and negative testing. For positive, we saved the keyring and loaded it again to test if the keys are the same. For the negative, we try to call keys that do not exist or try to match keys that should not match. After writing these tests, we are a great deal more certain that we implemented and used these methods correctly across this project.

Tests are in `/src/tests`
You must move them into the main `/src` folder and make sure to add Junit to your `classpath` to run.
