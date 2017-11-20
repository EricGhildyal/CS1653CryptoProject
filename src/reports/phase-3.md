# Phase 3
## Alex Dawson - Dave Rocker - Eric Ghildyal
## akd40 - der62 - erg56

## Introduction
For phase three of this project, we were tasked with creating measures to protect from four threats. These threats are 'Unauthorized Token Issuance', 'Token Modification/Forgery', 'Unauthorized File Servers', and 'Information Leakage via Passive Monitoring'. The first two of these threats we will deal with one protocol. This protocol will use user passwords to authenticate clients, defending against the first threat, and then cryptographically sign the user's token to ensure it is not tampered with (specifics in T1/T2). This will ensure that only authorized users get tokens and that they can’t be modified afterwards.   
For the third threat, we have the issue that anyone can host a file server. Therefore, there can be servers that are hosted maliciously and can be used to steal information. To combat this, when a client first connects to a file server, it will store a fingerprint of the server's public key, warning the user when it changes. If it does not have the key stored, it will add it and send a challenge to authenticate the server.  
For the final threat, we will use Diffie-Hellman to combat Passive Monitoring (specifics in T4). Diffie-Hellman allows two users to agree on a Symmetric Key over a public connection. With this symmetric key, all further traffic between the server and client will be encrypted. This allows privacy even if all communication between a client and server is being intercepted.

## Given Assumptions
#### Overall
All communication is being intercepted
#### Group Server
Fully trusted, properly authenticates users
#### File server
Untrusted unless properly authenticated
#### Clients
Untrusted

## T1 Unauthorized Token Issuance
**Description of threat:**
As our system currently stands any user can request another’s token, this problem leaves our system inherently insecure, as it breaks down the notion of groups and privileges in a file system. For example, with a minimal amount of effort, a user could log in as a professor and remove somebody from a group based on a class so they do not have access to files required to complete graded homework.  

**Mechanism:**
- User connects to group server, with a request for a token, their username and their password, encrypted with the session key received through diffie-hellman as explained in T4.
- The group server decrypts this tuple with the same session key, and authenticates the user's password with a database. This is done by hashing the user's password a random 256 bit salt that will be stored alongside the password.
- Once authenticated, the server returns the user’s token.  
[Diagram after T2]  

**Arguments:**
This process prevents a user from getting another user's token with the assumption that only the owner of the account has both the username and password. We also protect from the possibility of a malicious entity getting the password from the group server by hashing the password with SHA-256 and using a user specific salt of length 256 bits. We are using SHA-256 because it has yet to be broken and it it faster than SHA-384.

## T2 Token Modification/Forgery  

**Description of threat:**
Anything that a client interacts with has the possibility of being tampered with and tokens are no exception. A forged token can have the same effect as switching users by giving the forger access to groups they don’t own, allowing them to see files they should not be able to see, and performing actions under the guise of another user.  

**Mechanism:**
- This process is the same as T1, but the protection from this threat is provided by the use of an RSA signature using the private key of the server on the token at the end of this process.
- User connects to group server, with a request for a token, their username and their password, encrypted with the Session key.  
- The group server decrypts this tuple with the same key, and authenticates the user's password with a database, by hashing the user's password with a salt so it is not stored in plaintext.
- Once authenticated we turn the token into an string representation (ordered by server name, username, and an alphabetically ordered list of groups) then sign with RSA before encrypting it with the session key and sending it back  

**Arguments:**
This process protects against Token Modification by using an RSA signature from the Group Server on the token. We will convert the Token object into a string representation (ordered by server name, username, and an alphabetically ordered list of groups each delimited by '/') and sign that string so there are no differences with changing devices. This token can be authenticated by any fileserver, using the group servers public key, which can be obtained from the group server. This protects against modification because if the user attempts to fake their token, the signature on the token will no longer be valid.  

![Fig1](https://github.com/EricGhildyal/CS1653CryptoProject/tree/master/reports/images/fig1.jpg)  

## T3 Unauthorized File Servers  

**Description of threat:**
Considering any user can run a file server, it should be assumed that there are a lot of unauthorized servers trying to break into the trust system. If a user connects to an unauthorized server, there is no guarantee the server will not steal their authentication and use it illegitimately. Due to this, knowing which servers one can and cannot connect to is a very important part of the overall system’s security.  

**Mechanism:**
- The server creates a key pair and then sends the public key to any client that sends a hello.
- This is placed in a file called *saved_keys* on the client and every subsequent interaction begins with a check for this key.  
[Diagram after T4]


**Arguments:**
The client key-pair is an RSA keypair that is 2048 bits long to ensure basic protection from attackers. We will generate this key-pair client side then send the public key encrypted with the session key. On future visits, the server will encrypt a challenge (2048 bits long) with the provided public key and the user will have to return the correct response in order to be authenticated by the server. The user authenticates each server on subsequent visits because the server should already have their public key.  

##  T4 Information Leakage via Passive Monitoring  

**Description of threat:**
Passive monitoring is extremely important in maintaining a secure system. No matter how many physical or policy steps are present, if data is being transmitted as plain text, anybody can read it and act upon the data. Even encrypted data is susceptible to attacks, due to increasing processing power, old algorithms can become outdated. Once an attacker has some bit of information, they can try a more narrowed set of attack vectors to break the rest of your system.

**Mechanism:**
- Use Diffie Hellman with randomly generated parameters (G - group, q - prime order of the group, g - generator, a - client’s private key,  b - server's private key) to exchange keys between the client and server
- q is a safe prime (A large number chosen and tested so that it is probably prime), g = (a random number in the range 2, q). g^2 c1an not = 1, this ensures that g generates the entire group G and not a subgroup, since a group of prime order q has two subgroup, one of size q and one of size 1. G = ℤ mod q.
- Client and server encrypts all communication using the agreed upon key and AES-256 in CBC mode.

**Arguments:**
	Each request must be encrypted with the agreed upon key in order to ensure the inability of an outsider to decrypt and read any traffic between the server and the client. We are using Diffie-Hellman because it is a lightweight, cryptographically secure key sharing algorithm. We are using AES because it is built into most intel chips and therefore very fast. The group server will be authenticated because it has the user’s private key stored from T3.

![Fig2](https://github.com/EricGhildyal/CS1653CryptoProject/tree/master/reports/images/fig2.jpg)

## Conclusions  
From the mechanisms we designed the only two that go hand in hand are T1 and T2. They are both very similar in design and the implementation will be done using the same code. For each threat our group took the approach of each of us coming up with a proposed solution then discussing the pros and cons of each until deciding on one. This allowed us to have multiple options and potentially mix our solutions if one of us considered different risks than others. The discussion phase was probably the longest part of the design process as we didn’t choose one until we all agreed with it.
