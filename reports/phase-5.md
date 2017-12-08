# Phase 5 


**Trust Model**  
Overall  
    - All communication is being intercepted  
Group Server  
	- Fully trusted, properly authenticates users  
File server n  
	- Untrusted unless properly authenticated  
Clients  
	- Untrusted  

## T8 Knowledge of File Existence
Since filenames must be unique across the entire server instead of just the group they are contained in, users have the ability to detect the existence of files in other groups, given that they generate a collision with filenames. This is insecure as it allows users to gleam what information is stored on the server.

## Attack Description

- A user can log in to the file server and upload a file to any group they are a member of
- An attacker can then log in to the file server and upload a file to any group they are a member of
- If the user’s file and attacker’s file have the same name, the attacker will get a “File already exists” error
- The attacker could then keep using this method to test the existence of different files from other groups
- This same risk also applies to file server admins who could just log on and look at file names.

E.g. Someone can attempt to create a file called “ConvesationWithRussia.txt” and they will get a file exists error if it's already on the server.

## Countermeasure

**Mechanism:**
- To protect against this, we will use AES to encrypt the filenames with the same key that we use to encrypt the file in T6, and upload it as such.
- For downloading, we will first request a list of the encrypted file names with the corresponding version numbers.
- We will decrypt each name with the corresponding key, and once we find the file we want, we submit a request for that file using its encrypted name.
**Arguments:** 
	If the file exists in a group not the one you are a part of then it will no longer return a file already exists value. This would allow files to be named the same thing across multiple groups, but also prevent the file server from knowing filenames too.


![T8](https://github.com/EricGhildyal/CS1653CryptoProject/blob/master/reports/images/t8.png)
