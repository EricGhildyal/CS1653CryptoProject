# Group Information
Alex Dawson - akd40@pitt.edu - AlexKDawson  
David Rocker - der62@pitt.edu - rockaflacka47  
Eric Ghildyal - erg56@pitt.edu - EricGhildyal  

# Section 1
**Property 1: Public Account Access**  
Account Access states that only users with verified accounts can access our system. Accessing the system enables the user to read or write data that they have the correct permissions for. To access the system, user will need to use their login credentials. This ensures that access can be controlled to our filesharing system and unverified users cannot interact with our system in any way. This property assumes that there is a way to register and verify users.  
**Property 2: Permissions**  
Permissions states that each file is assigned a set of permissions restricting which users and groups can read and/or write to that file. This ensures data privacy and that only users with the correct permissions have access to files. When a set of permissions is removed from a user, they no longer have read/write access to the file.  
**Property 3: Ownership Transfer**  
Ownership Transfer states that if a user leaves the system or group, ownership of their groups or files can be delegated to another user. I.e. The account who created that user or the admin of a group containing said file. This prevents groups and files from being freely accessed by everyone or being accessible to no one. This property also ensures that at least one user on a system has admin privileges, so our system in not left unmanaged. This property assumes that each file/group will have its permissions delegated correctly and that there will be no way for another user to obtain permissions maliciously.  
**Property 4:  Account Removal**   
Account Removal states that accounts can be removed by a system Admin or the owner of that account. This ensures that user accounts are deleted either at the user’s request or for good reason. This assumes that Admins have a good reason for removing a user from the system and user accounts are not compromised.  
**Property 5: File Location**   
File Location states that every time a file is uploaded or shared to a group, a copy is made specifically for that group. This prevents issues in which one file shared across multiple groups can be edited for one group, by members of another group. This property does not make any assumptions.  
**Property 6: Groups**  
Groups states that groups are composed of users that all share the same permission over a set of files assigned to that group. Addition of a member to a group can be done by any member of that group, and removal of a member must be done by threshold, or a vote by the group’s current members. This follows the concept of a group based file sharing system, prevents a malicious user from taking control of a group, and removing other users from it. This assumes that less than 51% of the members in a group are malicious.  
**Property 7: File Upload**  
File Upload states that when a file is uploaded, that file is only accessible to the users that uploaded it. That user must add the file to a group in order to let other users read and edit the file. This ensures that when a file is first uploaded, it is by default confidential to the user who created it. This assumes that the user will assign permission correctly and that the user’s account itself is only accessible by the intended user.  
**Property 8: File Integrity**  
File Integrity states that each file is given a checksum stored on server when uploaded and verified against every time the file is accessed. This ensures this file is not corrupted or vulnerable to man in the middle attacks. This assumes that an attacker cannot access the checksum stored on the server and modify its contents.  
**Property 9: File Encryption**  
File Encryption states that files are encrypted with an asymmetric encryption scheme on upload and each  member of the group is distributed this key. This ensures that only members of the group have access to the files. This assumes that there is a secure method of distributing keys  
**Property 10: Active Re-encryption**  
Active Re-encryption states that when a user leaves a group, all the files within that group is re-encrypted and the keys are redistributed to the remaining members of the group. This ensures that when a user leaves the group that they are unable to decrypt any more files within the group. This assumes re-encrypting all the files in a group takes a reasonable amount of time before an ex-user can attempt to access them.  
**Property 11: Key Authority**  
Key Authority states that the Admin of the system is the only person with the ability to issue, revoke, and update keys. This assures that no third-party public key infrastructure that is possibly susceptible to attack opens this system up to attack, too. This property assumes that the Admin of the system is fair and not malicious in their key authority.  
**Property 12: System Compromise**  
System Compromise states that if a compromise is detected every file and group is re-encrypted. This ensures that a leaked key can not be used to access files past the detection. This property assumes that we are able to detect a compromise in a reasonable time.  
**Property 13: Intra-group Permissions:**  
Intra-group Permissions states that all users within a group have permission to read a file, but to write a file the system must verify that the user has write permissions. To do this, each user must first cryptographically sign the file after making a change and re-uploading it. The system will check the signature on the upload, then determine if it is belonged to a user with the correct permissions.This ensures that edits to a file can be verified as being done by the authorized user. This assumes that a user's account is not compromised.  
**Property 14: Private Account Access**  
Private Account Access states that an admin must give each user an account and assign them to groups. This ensures that only people the admin has given an account can access the server and their groups on the server. This property assumes that the Admin gives access to the correct user.  
**Property 15: Local Connection**  
To access the file system a user must be on a valid account connected to the system's intranet. This requires that users physically be on the same network as the system or connected to the system via VPN or VPN like service. This adds an extra level of security to who can access the system. This assumes the intranet is not compromised to allow external traffic.  
**Property 16: Session Timeout**  
Session Timeout states that a user will be required to re-authenticate their login to the system after a set amount of time. This reduces the occurrence of compromised accounts from people leaving their accounts open on a public device. This property assumes that the user has not saved their credentials on a 3rd party service.

# Section 2
## Classroom setting
  This file sharing system will be deployed locally within a university where each user has a university provided account. There are three roles: Admin, Professor, and Student. Admins add users to the system and assign roles. Each professor has a collection of groups within their class, and can assign any user on the system to any of these groups. To access a group, a user must be assigned to it by the professor who owns the group. Only members of the group or the group owner can edit, upload, or delete files. But anyone on the system can view the groups files.  
  This system gives admins the trust to operate the system without exploiting any of the users or their data. It trusts the professors to manage their groups and not exploit any of the files within any group in their control. Finally, it trusts students to respect their group members and to not maliciously remove or edit other students’ files.

Properties:
- Account Removal - This ensures no student with malicious intent can remove another student from the system.
- File Location - This keeps each group's work separate.
- Groups - This allows students to share work and the professor to monitor the work.
- File Upload - This ensures each user only shares the file with whom he decides. 
- File Integrity - This ensures that the file uploaded is the one being accessed and no malicious code has been put in its place.
- File Encryption - This ensures that only students in the group can access the files and no cheating can occur.
- Active Re-Encryption - ensures that once a student leaves a group he can not still access the files. This makes sure there is no way a student could be removed and attempt to hurt the group.
- Key Authority - This ensures only students meant to access the group can do so. Stops students from potentially sharing their key in order to receive help.
- System Compromise - This ensures that if someone accesses a file they are not supposed to or an attack is made on the server every file will be re-secured as soon as the detection is detected. 
- Intra-group Permissions - This assures that changes are made only intentionally by the student. Every change is verified that is in fact the student and is easily logged.
- Private Account Access - This assures that only the students meant to be on the server are on it. Also ensures they are only parts of the group they are supposed to be on.
- Local Network - This ensures that students are in fact students at the school.
- Session Timeout - This ensures no accounts are compromised accidently or purposefully by being left open on a public computer such as a library.



## Public website
This system is hosted publically on a server. Anyone can connect to and create an account on this server. Any user can then create a group of which they become a member. Access to this group is then determined by its members, who can add other members or by majority vote remove others from the group. Within this group, only members can view its files, only the files’ uploader can delete it, and either the owner or an owner delegated group member can delete, overwrite, or edit a file.
This places minimal trust in the hands of basic users by only allowing them to manage their own files and files that they have been delegated permissions over. It places more trust in the collective user base of the system assuming that the majority of users do not want to attack the system and want to keep it functional. It also trusts administrators to police the system fairly in removing malicious users.

Properties:
- Public Account Access - This ensures only users that have created an account can access the system. 
- Permissions - This makes sure only users that should be changing/viewing a file can do so.
- Ownership Transfer - This makes sure a group owner can not hurt the group by leaving and removing all work. Everything about the group will be maintained under a new group leader. 
- Account Removal - This makes sure no user can maliciously remove another user. The owner of that account or an admin must remove them.
- File Location - This stops one group from changing the work/inadvertently working with another group.
- Groups - This allows collaboration on work.
- File Upload - This ensures each user only shares the file with whom he decides. 
- File Integrity - This ensures that the file uploaded is the one being accessed and no malicious code has been put in its place.
- File Encryption - This ensures that only members of the group can access the file and no outsider can see it.
- System Compromise - This ensures that if we detect a information leak, in which private keys could have been obtained, that any further uploads remain secure.
- Active Re-encryption - This ensures that if a user decides to remove access to one of their files from another user, that the files are immediately secured.
- Key Authority - This ensures that all the private keys used to access files are in sync and that we have direct control over key distribution, without allowing a 3rd party access to these keys.
- Session Timeout - This ensures that users accounts are safer in the case that someone leaves their account logged in on a public device.



# Section 3
References: AFS Filesystem, Github, GroupMe, and Google Drive

