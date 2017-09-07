# Group Information
Alex Dawson - akd40@pitt.edu - AlexKDawson  
David Rocker - der62@pitt.edu - rockaflacka47  
Eric Ghildyal - erg56@pitt.edu - EricGhildyal  


# Section 1
## Classroom Setting
**Property 1: System Access**  
System Access states that only those with accounts created by an Admin can access the system. After creation of an account, an Admin provides each user with their credentials which they can use to access the system. Only users who hold an account that was created for them should be able to access and view files. This property assumes that the system has an Admin that will not exploit the system and will add users accurately and in a timely manner  
**Property 2: Role Management**  
Role Management states that each user has a role and these roles are assigned by an Admin at the time of account creation. Possible roles are: Admin, Professor, and Student. Roles are defined as the permissions each user has where Admin supersedes Professor and Professor supersedes Student. This ensures that each user has the least amount of privilege required to utilize the system effectively. This property assumes that Admins will not exploit any users and Professors will not exploits any Students.  
**Property 3: Hierarchical Access**  
Hierarchical Access states that the Admins have access to everything the Professors do and the Professors have access to everything that their Students do. This means that a Professor holds as many permissions over a file as group members who possess the file as long as the file is contained within a group he owns. This gives Admins full ability to control the system, Professors full ability to control their groups, and Students full ability to control their files. This property assumes that Admins will not exploit any users and Professors will not exploits any Students.  
**Property 4: Group Access**  
Group Access states that anyone placed in a group by a Professor has access to read, write, edit, and delete the files contained within that group. This is necessitated by the idea of a group file sharing system and allows corrections be made with ease. This property assumes that Professors and Students will not maliciously harm another Student’s file.  
**Property 6: Ownership Transfer**  
Ownership Transfer states that if a user leaves the system or group, ownership of their groups or files are delegated to the account directly above them. Ie: The account who created that user or the Professor in charge of a group containing said file. This prevents groups and files from being owner-less potentially allowing everyone access. This property assumes that each role will not abuse their abilities.  
**Property 7:  Administrator Delegation**  
Administrator Delegation states that Admins cannot leave the system without first delegating another Admin to take possession of any owned files or groups. If an Admin does not have another active Admin selected as a delegate, their account will not be allowed to be removed from the system. This ensures that the system will always be managed. This property assumes Admins will not be forced into relegating their role and each Admin will not abuse their role.

## Public website
**Property 1: Account Benefit**  
The ownership of an account is required for all users to access the system, to either read from or write to files, or participate in a group. This reduces the potential for a DDOS attack, but also ensures that we can correctly identify users. This property assumes that users keep their credentials secure and thus any access to their account is assumed to be that person.  
**Property 2: Open Access**  
Open access states that anybody who can verify their existence with an email account can create an account on our system, and thus access account holding benefits. Without an account, users cannot access files at all. This is a required functionality in this situation so anybody can access the platform, but also assists in ensuring they are human through email verification. This property assumes that verifying an email is a human act.  
**Property 3: Individual Access**  
Individual Access states that access to files is restricted to the members of the group and excludes system Admins. This ensures that everyone only has the minimum privilege required to operate the system and also prevents a breached Admin account from scraping the entire server. This assumes that direct Admin access to the database is an operation and cannot be done through remote means.  
**Property 4: Group Roles**  
Group Roles states that within each group there will be two kinds of members: members with read/write permissions and users with only read permissions. This allows the sharing of files without allowing every viewer the ability to edit these files. This property assumes the user responsibly delegates permissions and that user accounts are not compromised.  
**Property 5: Secure User Directory**  
Secure User Directory states that there is a directory that allows account holding users to be searchable by other users. Searches can be done on a user's name or email, but will not display any other personal information. This makes the finding of user’s easier for file sharing but keeps users personal info private. This property assumes users’ basic information (name, email) is already known and user is willing to disclose such information.  
**Property 6: Removal by Threshold**  
 Removal by Threshold states that removing someone from a group will be done by a majority vote by the group. This prevents one malicious user from unfairly assuming control of the group and its data. This property assumes there is a fair method of voting and that less than 50% of users are malicious.  
**Property 7:  Account Removal**   
Account Removal states that accounts can be removed by a system Admin or the owner of that account. This ensures that user accounts are deleted either at the user’s request or for good reason. This assumes that Admins have a good reason for removing a user from the system and user accounts are not compromised.  
**Property 8: Data Persistence**  
	Data Persistence states that upon leaving a group, the user has the option of removing the files or making them property of another group member. This allows one user to leave a group without unintentionally removing access to files from other members. This assumes that user accounts are not compromised.  
**Property 9: File Location**   
	File Location states that every time a file is uploaded or shared to a group, a copy is made specifically for that group. This prevents issues in which one file shared across multiple groups can be edited for one group, by members of another group. This property does not make any assumptions.

  # Section 2
## Classroom setting
  This file sharing system will be deployed locally within a university where each user has a university provided account. There are three roles: Admin, Professor, and Student. Admins add users to the system and assign roles. Each professor has a collection of groups within their class, and can assign any user on the system to any of these groups. To access a group, a user must be assigned to it by the professor who owns the group. Only members of the group or the group owner can view, edit, upload, or delete files.  
  This system gives admins the trust to operate the system without exploiting any of the users or their data. It trusts the professors to manage their groups and not exploit any of the files within any group in their control. Finally, it trusts students to respect their group members and to not maliciously remove or edit other students’ files.
- System Access states that only those with accounts created by an Admin can access the system. After creation of an account, an Admin provides each user with their credentials which they can use to access the system.
- Role Management states that each user has a role and these roles are assigned by an Admin at the time of account creation. Possible roles are: Admin, Professor, and Student. Roles are defined as the permissions each user has where admin supersedes professor and professor supersedes student.
- Hierarchical Access states that the Admins have access to everything the Professors do and the Professors have access to everything that their Students do. This means that a professor holds as many permissions over a file as group members who possess the file as long as the file is contained within a group he owns.
- Group Access states that anyone placed in a group by a professor has access to read, write, edit, and delete the files contained within that group.
- Ownership Transfer states that if a user leaves the system or group, ownership of their groups or files are delegated to the account directly above them.
- Administrator Delegation states that admins cannot leave the system without first delegating another admin to take possession of any owned files or groups.

## Public website
	This system is hosted publically on a server. Anyone can connect to and create an account on this server. Any user can then create a group of which they become a member. Access to this group is then determined by its members, who can add other members or by majority vote remove others from the group. Within this group, only members can view its files, only the files’ uploader can delete it, and either the owner or an owner delegated group member can delete, overwrite, or edit a file.
	This places minimal trust in the hands of basic users by only allowing them to manage their own files and files that they have been delegated permissions over. It places more trust in the collective user base of the system assuming that the majority of users do not want to attack the system and want to keep it functional. It also trusts administrators to police the system fairly in removing malicious users.

- The ownership of an account is required for all users to access the system, to either read from or write to files, or participate in a group.
- Open access states that anybody who can verify their existence with an email account can create an account on our system, and thus access account holding benefits.
- Individual Access states that access to files is restricted to the members of the group and excludes system admins.
- Group Roles states that within each group there will be two kinds of members: members with read/write permissions and users with only read permissions.
- Secure User Directory states that there is a directory that allows account holding users to be searchable by other users.
- Removal by Threshold states that removing someone from a group will be done by a majority vote by the group.
- Account Removal states that accounts can be removed by a system admin or the owner of that account.
- Data Persistence states that upon leaving a group, the user has the option of removing the files or making them property of another group member.
- File Location states that every time a file is uploaded or shared to a group, a copy is made specifically for that group.

# Section 3
	References: AFS Filesystem, Github, GroupMe, and Google Drive
