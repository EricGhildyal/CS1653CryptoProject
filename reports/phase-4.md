# Phase 4


For phase three of this project, we were tasked with creating measures to protect from four threats. These threats are Message Reorder, Replay, or Modification; File Leakage; and Token Theft. To overcome Message reorder, replay, or modification, we decided to use a monotonically increasing timestamp on all messages sent, Diffie Hellman (from last phase) to help protect from replay attacks, and encrypt each message using the session key (specifics in T5). In terms of File Leakage, we decided to generate a group key for each group (updating the key as group members change) (specifics in T6). Lastly, to protect against Token Theft, we decided to use the included RSA fingerprint in the token (Specifics in T7).


## T5 Message Reorder, Replay, or Modification 


**Description of threat:**  
The possibility of an attacker to reorder, replay, or modify messages is dangerous for our system. Reorder and replay can cause the user and the server to believe they have been authenticated when they haven’t been, and modification can make the server believe it is connected to a different user than it actually is. These are important threats to protect against in order to have a properly secured system.
**Mechanism:**  
To protect against Reorder attacks and same-session replay attacks every message sent will be sent with a time stamp. We are assuming timestamps always increase.
When a message is received it will be checked against the current time to make sure it is recent. Recent means within 10 minutes.
Replay attacks are also protected by using a session key obtained through diffie hellman as explained in the previous phase.
To protect against modification, each message sent is encrypted with the session key.
**Arguments:**  
Reorder attacks will be protected by timestamps since once all messages are received you can place them in order by time sent. This also protects against same-session replay attacks because the messages will stop working after enough time for the operation(accounting for possible desynced clocks) to occur. For multi-session replay attacks a session key protects against since no messages are encrypted the same way. This also prevents modification since there is no way for them to decrypt/encrypt their own messages without guessing the session key.


![T5](https://github.com/EricGhildyal/CS1653CryptoProject/blob/master/reports/images/t5.jpg)


## T6 File Leakage


**Description of threat:**  
File servers are important in the notion of a group file system, but since they are not trusted, there is a big possibility they will attempt to steal files and leak them to other users or administrators. This threats causes a complete breakdown of the security of our system, and therefore is very important to protect against.
**Mechanism:**  
When a group is created, a 256 bit AES key is generated to represent that group.
The generated key, encrypted by each user’s session key, is sent to all the group members when they connect to the group server if it has changed.
When a user is deleted from a group, files will be re-encrypted and a new key will be generated and sent to all users of the group.
**Arguments:**  
This mechanism makes sure all members of a group have the same key and that the key is sent in a secure manner. In order to keep every user up to date and prevent old users from snooping, a new key will be generated every time a user leaves a group. We are using a 256 bit AES key because it is still secure.


![T6](https://github.com/EricGhildyal/CS1653CryptoProject/blob/master/reports/images/t6.jpg)


## T7 Token Theft


**Description of threat:**  
The ability for a file server to steal tokens means that attacker could pretend to be any user on any server. This could even extend to an attacker gaining admin credentials and effectively shutting down the entire server by deleting all the users.
**Mechanism:**  
As in T4, the user establishes a secure connection with the Group Server using Diffie Hellman and AES in CBC mode.
The user will submit a request for a token to the group server, which includes a username and password.
As in T2, the server will return a signed token, but instead of this token being used for authentication with file servers, it will only be used for further authentication with the group server.
Whenever the user wants to access a file server it must first get a signed token from the group server that includes a target server. If the user has this cached it may use it, but otherwise they must contact the group server, authenticating with their token, to get a new token signed.
The user will then send this new token to file server, which makes the same signature checks for token modification and forgery as in T2, but now also check for the inclusion of the file server's public rsa fingerprint in the signature.
**Arguments:**  
This mechanism protects against file servers from stealing your key and using it on other servers because of the included RSA fingerprint in the token that will cause any server other than the one listed in the token to reject the token.
This also still protects against token forgery (T3) because the group server still signs the token, and the token without any target servers listed should never be sent to any file servers. This also uses signed Diffie Hellman to establish a session key, so that no information can be stolen by a man-in-the-middle attack or by passive monitoring (T4).


![T7](https://github.com/EricGhildyal/CS1653CryptoProject/blob/master/reports/images/t7.jpg)


## Conclusion 
From the mechanisms we designed none of them protect against multiple threats. For each threat, our group took the approach of each of us coming up with a proposed solution then discussing the pros and cons of each until deciding on one. This allowed us to have multiple options and potentially mix our solutions if one of us considered different risks than others. The discussion phase was probably the longest part of the design process as we didn’t choose one until we all agreed with it. After agreeing on one and writing up we then all checked it to make sure it was written the way we discussed it.
