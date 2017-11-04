import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.lang.Integer;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;


public class RunClient {
	//group server ip/group server port/fileserver ip/file server port
	
	public static void main(String[] args) {
		SecretKeySpec fileServKey;
		SecretKeySpec groupServKey;
		GroupClient gcli = new GroupClient();
		if(args.length >= 2){
			if(args[0] != null && args[1] != null)
				gcli.connect(args[0], Integer.parseInt(args[1]));
			else
				gcli.connect(null, GroupServer.SERVER_PORT);
		}
		else
			gcli.connect(null, GroupServer.SERVER_PORT);

		FileClient fcli = new FileClient();
		if(args.length >= 4){
			if(args[2] != null && args[3] != null)
				fcli.connect(args[2], Integer.parseInt(args[3]));
			else
				fcli.connect(null, FileServer.SERVER_PORT);
		}
		else	
			fcli.connect(null, FileServer.SERVER_PORT);
		//Test connections, if one fails: exit
		if(gcli.isConnected()) {
			System.out.println("Group Server Connected!");
			//byte [] byteGKey = gcli.key.toByteArray();
			//groupServKey = new SecretKeySpec(byteGKey, "AES");
		}else{
			System.err.println("Failed to Connect to Group Server");
			return;
		}
			
		if(fcli.isConnected()) {
			System.out.println("File Server Connected!");
			
		}else{
			System.err.println("Failed to Connect to File Server");
			return;
		}
			
		int menuChoice = -1;
		Scanner input = new Scanner(System.in);
		while(menuChoice != 12) {
			do{
				System.out.println("\n---Please select an option---");
				System.out.println("0. Get User Token\n"
								 + "1. Create User\n"
								 + "2. Delete User\n"
								 + "3. Create Group\n"
								 + "4. Delete Group\n"
								 + "5. List Members\n"
								 + "6. Add User to Group\n"
								 + "7. Delete User from Group\n"
								 + "8. List Files\n"
								 + "9. Upload File\n"
								 + "10. Download File\n"
								 + "11. Delete File\n"
								 + "12. Disconnect");
			
				if(input.hasNextInt()) {	
					menuChoice = input.nextInt();
				}else {
					menuChoice = -1;
				}
				input.nextLine(); //Consume the endline
			
			}while(menuChoice < 0 || menuChoice > 12);
			
			switch(menuChoice) {
				
				case 0: //Get Token
					if(getToken(input, gcli))
						System.out.println("Successfully got Token\n");
					else
						System.out.println("User not found");
					break;
					
				case 1: //Create User
					if(gcli.tok != null){
						if(createUser(input, gcli))
							System.out.println("Successfully Created User\n");
						else
							System.out.println("User Creation Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;
				
				case 2: //Delete User
					if(gcli.tok != null){
						if(deleteUser(input, gcli))
							System.out.println("Successfully Deleted User\n");
						else
							System.out.println("User Deletion Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;
				
				case 3: //Create Group
					if(gcli.tok != null){
						if(createGroup(input, gcli))
							System.out.println("Successfully Created Group\n");
						else
							System.out.println("Group Creation Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					
					break;
				
				case 4: //Delete Group
					if(gcli.tok !=null){
						if(deleteGroup(input, gcli))
							System.out.println("Successfully Deleted Group\n");
						else
							System.out.println("Group Deletion Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;
				
				case 5: //List Members
					if(gcli.tok != null){
						if(!listMembers(input, gcli))
							System.out.println("List Members Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;
				
				case 6: //Add User To Group
					if(gcli.tok != null){
						if(addUserToGroup(input, gcli))
							System.out.println("Successfully Added User\n");
						else
							System.out.println("Add Member Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;
				
				case 7: //Delete User From Group
					if(gcli.tok != null){
						if(deleteUserFromGroup(input, gcli))
							System.out.println("Successfully Removed User from Group\n");
						else
							System.out.println("Delete Member Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;
					
				case 8: //List Files
					if(gcli.tok != null){
						if(!listFiles(gcli.tok, fcli))
							System.out.println("List Files Failed\n");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;
				
				case 9: //Upload File
					if(gcli.tok != null){
						uploadFile(input, gcli.tok, fcli);
						System.out.println("");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;
					
				case 10: //Download File
					if(gcli.tok != null){
						downloadFile(input, gcli.tok, fcli);
						System.out.println("");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;
					
				case 11: //Delete File
					if(gcli.tok != null){
						deleteFile(input, gcli.tok, fcli);
						System.out.println();
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;
				
				case 12: //Disconnect
					gcli.disconnect();
					fcli.disconnect();
					break;
			}
		}
	}
	
	public static boolean getToken(Scanner input, GroupClient gcli){
		System.out.println("Which user would you like the token for?");
		String username = input.nextLine();			//Takes in username input from user
		if(username.isEmpty()) {
			System.out.println("Invalid username, please try again: ");
			username = input.nextLine();
		}
		UserToken tok = gcli.getToken(username);		//gets Usertoken from server
		if(tok != null) {
			gcli.tok = tok;							//Saves the token to gclient
			return true;
		}
		return false;
	}
	
	public static boolean createUser(Scanner input, GroupClient gcli){
		UserToken token = gcli.tok;
		if(token.getGroups().contains("ADMIN")){
			System.out.println("Enter username for new user: ");
			String username = input.nextLine();
			if(username.isEmpty()) {
				System.out.println("Invalid username, please try again: ");
				username = input.nextLine();
			}
			return gcli.createUser(username, token);
		}
		else{
			System.out.println("Admin Privledges Required To Create User");
			return false;
		}
	}

	public static boolean deleteUser(Scanner input, GroupClient gcli){
		UserToken token = gcli.tok;
		if(token.getGroups().contains("ADMIN")){
			System.out.println("Enter username to delete: ");
			String username = input.nextLine();
			if(username.isEmpty()) {
				System.out.println("Invalid username, please try again: ");
				username = input.nextLine();
			}
			return gcli.deleteUser(username, token);
		}
		else{
			System.out.println("Admin Privledges Required To delete User");
			return false;
		}
	}

	public static boolean createGroup(Scanner input, GroupClient gcli){
		System.out.println("Enter the name for the group: ");
		String gName = input.nextLine();
		if(gName.isEmpty()) {
			System.out.println("Invalid group name, please try again: ");
			gName = input.nextLine();
		}
		UserToken token = gcli.tok;
		if(gcli.createGroup(gName, token)) {
			return true;
		}
		return false;
				
	}

	public static boolean deleteGroup(Scanner input, GroupClient gcli){
		System.out.println("Enter the name of the group: ");
		String gName = input.nextLine();
		if(gName.isEmpty()) {
			System.out.println("Invalid group name, please try again: ");
			gName = input.nextLine();
		}
		UserToken token = gcli.tok;
		return gcli.deleteGroup(gName, token);
	}

	public static boolean listMembers(Scanner input, GroupClient gcli){
		System.out.println("Enter the name of the group: ");
		String gName = input.nextLine();
		if(gName.isEmpty()) {
			System.out.println("Invalid group name, please try again: ");
			gName = input.nextLine();
		}
		UserToken token = gcli.tok;
		ArrayList<String> members = (ArrayList<String>)gcli.listMembers(gName, token);
		if(members != null) {
			System.out.printf("----List of Members in %s----\n", gName);
			for(String mem : members) {
				System.out.println(mem);
			}
			System.out.println("\n");
			return true;
		}else
			return false;
	}

	public static boolean addUserToGroup(Scanner input, GroupClient gcli){
		System.out.println("Enter the name of the user to add: ");
		String username = input.nextLine();
		if(username.isEmpty()) {
			System.out.println("Invalid username, please try again: ");
			username = input.nextLine();
		}
		System.out.println("Enter the name of the group: ");
		String gName = input.nextLine();
		if(gName.isEmpty()) {
			System.out.println("Invalid group name, please try again: ");
			gName = input.nextLine();
		}
		UserToken token = gcli.tok;
		return gcli.addUserToGroup(username, gName, token);
	}

	public static boolean deleteUserFromGroup(Scanner input, GroupClient gcli){
		System.out.println("Enter the name of the user to remove: ");
		String username = input.nextLine();
		if(username.isEmpty()) {
			System.out.println("Invalid username, please try again: ");
			username = input.nextLine();
		}
		System.out.println("Enter the name of the group: ");
		String gName = input.nextLine();
		if(gName.isEmpty()) {
			System.out.println("Invalid group name, please try again: ");
			gName = input.nextLine();
		}
		UserToken token = gcli.tok;
		return gcli.deleteUserFromGroup(username, gName, token);
	}
	
	public static boolean listFiles(UserToken token, FileClient fcli) {
		try {
			Thread.sleep(1000); //sleep for one second to let server upload file
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		List<String> files = fcli.listFiles(token);
		if(files == null) {
			System.out.println("Something went wrong with your request!");
			return false;
		}
		
		System.out.println("----List of Files----");
		for(String file : files) {
			System.out.println(file);
		}
		return true;
	}
	
	public static boolean uploadFile(Scanner input, UserToken token, FileClient fcli) {
		System.out.println("Please enter the source file name: ");
		String sourceFile = input.nextLine();
		if(sourceFile.isEmpty()) {
			System.out.println("Please enter a valid file name: ");
			sourceFile = input.nextLine();
		}
		System.out.println("Please enter the destination file name: ");
		String destFile = input.nextLine();
		if(destFile.isEmpty()) {
			System.out.println("Please enter a valid file name: ");
			destFile = input.nextLine();
		}
		System.out.println("Please enter the group name: ");
		String group = input.nextLine();
		if(group.isEmpty()) {
			System.out.println("Please enter a valid group name: ");
			group = input.nextLine();
		}
			
		return fcli.upload(sourceFile, destFile, group, token);
	}
	
	public static boolean downloadFile(Scanner input, UserToken token, FileClient fcli) {
		System.out.println("Please enter the source file name: ");
		String sourceFile = input.nextLine();
		if(sourceFile.isEmpty()) {
			System.out.println("Please enter a valid file name: ");
			sourceFile = input.nextLine();
		}
		System.out.println("Please enter the destination file name: ");
		String destFile = input.nextLine();
		if(destFile.isEmpty()) {
			System.out.println("Please enter a valid file name: ");
			destFile = input.nextLine();
		}
		return fcli.download(sourceFile, destFile, token);
	}
	
	public static boolean deleteFile(Scanner input, UserToken token, FileClient fcli) {
		System.out.println("Please enter the file you would like to delete: ");
		String filename = input.nextLine();
		if(filename.isEmpty()) {
			System.out.println("Please enter a valid file name: ");
			filename = input.nextLine();
		}
		return fcli.delete(filename, token);
	}
	
	
}
