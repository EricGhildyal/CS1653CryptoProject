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

A user can log in to the file server and upload a file to any group they are a member of
An attacker can then log in to the file server and upload a file to any group they are a member of
If the user’s file and attacker’s file have the same name, the attacker will get a “File already exists” error
The attacker could then keep using this method to test the existence of different files from other groups

## Countermeasure  

**Description of threat:**  
A user can log in to the file server and upload a file to any group they are a member of.  
An attacker can then log in to the file server, upload a file to any group they are a member of.  
If the user’s file and attacker’s file have the same name, the attacker will get a “File already exists” error. The attacker could then keep using this method to test the existence of files from other groups. This is a problem because an attacker could discover the existence of files and piece together what a group is working on.

**Mechanism:**  
To protect against this, we will store all of a group’s files in a directory with that group name.  
When uploading a file rather then check against the entire filer server directory we will check against that groups directory.  

**Arguments:**  
If the file exists in a group not the one you are a part of then it will no longer return a file already exists value. This would allow files to be named the same thing across multiple groups.


E.g. Someone can attempt to create a file called “ConvesationWithRussia.txt” and they will get a file exists error if it's already on the server.asdasdsa


![T8](https://github.com/EricGhildyal/CS1653CryptoProject/blob/master/reports/images/t8.jpg)