# Phase 3

Overall
	All communication is being intercepted
Group Server
	Fully trusted, properly authenticates users
File server
	Untrusted unless properly authenticated
Clients
	Untrusted

## T1 Unauthorized Token Issuance
	Temp solution: Username and Password protection before token is issued
**Description of threat:**
	As our system currently stands, any user can request another’s token, this problem leaves our system inherently insecure, as it breaks down the notion of groups and privileges in a file system. For example, with a minimal amount of effort, a user could log in as a professor and remove somebody from a group based on a class so they do not have access to files required to complete graded homework.
**Mechanism:**
	
**Arguments:**


## T2 Token Modification/Forgery
	Temp solution: Encrypt tokens and implement checksums to verify data validity
**Description of threat:**
This threat follows many of the same reasons that T1 is unsafe, but takes slightly more effort. Anything that a client interacts with has the possibility of being tampered with and tokens are no exception. A forged token can have the same effect as switching users by giving the forger access to groups they don’t own, allowing them to see files they should not be able to see, and performing actions under the guise of another user.
**Mechanism:**

**Arguments:**


## T3 Unauthorized File Servers
	Temp solution: When connecting to any file server, prompt the user to accept a public key (like ssh) OR make some method of registering a server
**Description of threat:**
	Considering any user can run a file server, it should be assumed that there are a lot of unauthorized servers trying to break into the trust system. If a user connects to an unauthorized server, there is no guarantee the server will not steal their authentication and use it illegitimately. Due to this, knowing which servers one can and cannot connect to is a very important part of the overall system’s security.
**Mechanism:**

**Arguments:**


## T4 Information Leakage via Passive Monitoring
	Temp solution: Encrypt all traffic between servers and clients
**Description of threat:**
	Passive monitoring is extremely important in maintaining a secure system. No matter how many physical or policy steps are present, if data is being transmitted as plain text, anybody can read it and act upon the data. Even using an encryption algorithm might not help depending on the security of the algorithm. Once an attacker has some bit of information, they can assume and try new narrowed attack vectors to break the rest of your system, leading to a further breakdown.
**Mechanism:**

**Arguments:**