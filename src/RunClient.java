import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

import java.io.File;
import java.security.*;


public class RunClient {
	//group server ip/group server port/fileserver ip/file server port

	private static CryptoHelper crypto = new CryptoHelper();

	public static void main(String[] args) {
		SecretKeySpec fileServKey;
		SecretKeySpec groupServKey;
		String fileServPubRSA;
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

		fileServPubRSA = Base64.encodeBase64String(fcli.getPubKeyBytes());
		if(fileServPubRSA == null){
			System.err.println("Failed to get fileservers public key!");
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
					if(getToken(input, gcli, fileServPubRSA))
						System.out.println("Successfully got Token\n");
					else
						System.out.println("User not found or password was incorrect");
					break;

				case 1: //Create User
					if(gcli.groupTokTuple != null){
						if(createUser(input, gcli))
							System.out.println("Successfully Created User\n");
						else
							System.out.println("User Creation Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 2: //Delete User
					if(gcli.groupTokTuple != null){
						if(deleteUser(input, gcli))
							System.out.println("Successfully Deleted User\n");
						else
							System.out.println("User Deletion Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 3: //Create Group
					if(gcli.groupTokTuple != null){
						if(createGroup(input, gcli))
							System.out.println("Successfully Created Group\n");
						else
							System.out.println("Group Creation Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");

					break;

				case 4: //Delete Group
					if(gcli.groupTokTuple !=null){
						if(deleteGroup(input, gcli))
							System.out.println("Successfully Deleted Group\n");
						else
							System.out.println("Group Deletion Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 5: //List Members
					if(gcli.groupTokTuple != null){
						if(!listMembers(input, gcli))
							System.out.println("List Members Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 6: //Add User To Group
					if(gcli.groupTokTuple != null){
						if(addUserToGroup(input, gcli))
							System.out.println("Successfully Added User\n");
						else
							System.out.println("Add Member Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 7: //Delete User From Group
					if(gcli.groupTokTuple != null){
						if(deleteUserFromGroup(input, gcli))
							System.out.println("Successfully Removed User from Group\n");
						else
							System.out.println("Delete Member Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 8: //List Files
					if(gcli.groupTokTuple != null){
						if(!listFiles(gcli.fileTokTuple, fcli, gcli))
							System.out.println("List Files Failed\n");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 9: //Upload File
					if(gcli.groupTokTuple != null){
						uploadFile(input, gcli.fileTokTuple, fcli, gcli);
						System.out.println("");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 10: //Download File
					if(gcli.groupTokTuple != null){
						downloadFile(input, gcli.fileTokTuple, fcli, gcli);
						System.out.println("");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 11: //Delete File
					if(gcli.groupTokTuple != null){
						deleteFile(input, gcli.fileTokTuple, fcli);
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

	public static boolean getToken(Scanner input, GroupClient gcli, String fileServPubRSA){
		java.io.Console console = System.console();
		String username = "";
		String password = "";

		do{
			username = console.readLine("Username: ");	//Takes in username input from user
			password = new String(console.readPassword("Password: ")); //Takes in password input from user
			if(username.isEmpty() || password.isEmpty()){
				System.out.println("Invalid username or password format, please try again!");
			}
			if(username.equalsIgnoreCase("break") || password.equalsIgnoreCase("break"))
				break;
		}while(username.isEmpty() || password.isEmpty());

		TokenTuple groupTokTuple = gcli.getToken(username, password);		//gets Usertoken from server
		TokenTuple fileTokTuple = gcli.getFSToken(username, password, fileServPubRSA);
		if(groupTokTuple == null || fileTokTuple == null){
			return false;
		}
		UserToken tok = groupTokTuple.tok;
		UserToken fsTok = fileTokTuple.tok;

		if(tok != null && fsTok != null) {
			gcli.groupTokTuple = groupTokTuple;							//Saves the token to gclient
			gcli.fileTokTuple = fileTokTuple;
			return true;
		}
		return false;
	}

	public static boolean createUser(Scanner input, GroupClient gcli){
		TokenTuple groupTokTuple = gcli.groupTokTuple;
		if(groupTokTuple.tok.getGroups().contains("ADMIN")){

			java.io.Console console = System.console();
			String username = "";
			String password = "";
			String passwordConfirm = "";

			do{
				username = console.readLine("Username: ");	//Takes in username input from user
				password = new String(console.readPassword("Password: ")); //Takes in password input from user
				passwordConfirm = new String(console.readPassword("Please Retype Password: ")); //Takes in password input from user
				if(username.isEmpty() || password.isEmpty()){
					System.out.println("Invalid username or password format, please try again!");
				}else if(!password.equals(passwordConfirm)){
					System.out.println("Passwords did not match, please try again!");
				}
			}while(username.isEmpty() || password.isEmpty() || !password.equals(passwordConfirm));

			return gcli.createUser(username, password, groupTokTuple);
		}
		else{
			System.out.println("Admin Privledges Required To Create User");
			return false;
		}
	}

	public static boolean deleteUser(Scanner input, GroupClient gcli){
		TokenTuple groupTokTuple = gcli.groupTokTuple;
		if(groupTokTuple.tok.getGroups().contains("ADMIN")){
			System.out.println("Enter username to delete: ");
			String username = input.nextLine();
			if(username.isEmpty()) {
				System.out.println("Invalid username, please try again: ");
				username = input.nextLine();
			}
			return gcli.deleteUser(username, groupTokTuple);
		}
		else{
			System.out.println("Admin Privledges Required To delete User");
			return false;
		}
	}

	public static boolean createGroup(Scanner input, GroupClient gcli){
		System.out.println("Enter the name for the group (cannot contain '/' ',' '[' ']' ':' or ' '): ");
		String gName = input.nextLine();
		while(gName.isEmpty()) {
			System.out.println("Invalid group name, please try again(Enter break to exit): ");
			gName = input.nextLine();
			if(gName.equals("break"))
				return false;
		}
		while(gName.contains("/") || gName.contains(" ") || gName.contains("[") || gName.contains("]") || gName.contains(":") || gName.contains(",")){
			System.out.println("Invalid group name, please try again(Enter break to exit): ");
			gName = input.nextLine();
			if(gName.equals("break"))
				return false;
		}

		TokenTuple groupTokTuple = gcli.groupTokTuple;
		if(gcli.createGroup(gName, groupTokTuple)) {
			return true;
		}
		return false;

	}

	public static boolean deleteGroup(Scanner input, GroupClient gcli){
		System.out.println("Enter the name of the group(cannot contain '/' ',' '[' ']' ':' or ' '): ");
		String gName = input.nextLine();
		while(gName.contains("/") || gName.isEmpty() || gName.contains(" ") || gName.contains("[") || gName.contains("]") || gName.contains(":") || gName.contains(",")) {
			System.out.println("Invalid group name, please try again(Enter break to exit): ");
			gName = input.nextLine();
			if(gName.equals("break"))
				return false;
		}
		TokenTuple groupTokTuple = gcli.groupTokTuple;
		return gcli.deleteGroup(gName, groupTokTuple);
	}

	public static boolean listMembers(Scanner input, GroupClient gcli){
		System.out.println("Enter the name of the group(cannot contain '/' ',' '[' ']' ':' or ' '): ");
		String gName = input.nextLine();
		while(gName.contains("/") || gName.isEmpty() || gName.contains(" ") || gName.contains("[") || gName.contains("]") || gName.contains(":") || gName.contains(",")) {
			System.out.println("Invalid group name, please try again(Enter break to exit): ");
			gName = input.nextLine();
			if(gName.equals("break"))
				return false;
		}
		TokenTuple groupTokTuple = gcli.groupTokTuple;
		ArrayList<String> members = (ArrayList<String>)gcli.listMembers(gName, groupTokTuple);
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
		while(username.isEmpty()) {
			System.out.println("Invalid username, please try again(Enter break to exit): ");
			username = input.nextLine();
			if(username.equals("break"))
				return false;
		}
		System.out.println("Enter the name of the group(cannot contain '/' ',' '[' ']' ':' or ' '): ");
		String gName = input.nextLine();
		while(gName.contains("/") || gName.isEmpty() || gName.contains(" ") || gName.contains("[") || gName.contains("]") || gName.contains(":") || gName.contains(",")) {
			System.out.println("Invalid group name, please try again(Enter break to exit): ");
			gName = input.nextLine();
			if(gName.equals("break"))
				return false;
		}
		TokenTuple groupTokTuple = gcli.groupTokTuple;
		return gcli.addUserToGroup(username, gName, groupTokTuple);
	}

	public static boolean deleteUserFromGroup(Scanner input, GroupClient gcli){
		System.out.println("Enter the name of the user to remove: ");
		String username = input.nextLine();
		while(username.isEmpty()) {
			System.out.println("Invalid username, please try again(Enter break to exit): ");
			username = input.nextLine();
			if(username.equals("break"))
				return false;
		}
		System.out.println("Enter the name of the group(cannot contain '/' ',' '[' ']' ':' or ' '): ");
		String gName = input.nextLine();
		while(gName.contains("/") || gName.isEmpty() || gName.contains(" ") || gName.contains("[") || gName.contains("]") || gName.contains(":") || gName.contains(",")) {
			System.out.println("Invalid group name, please try again: ");
			gName = input.nextLine();
			if(gName.equals("break"))
				return false;
		}
		TokenTuple groupTokTuple = gcli.groupTokTuple;
		return gcli.deleteUserFromGroup(username, gName, groupTokTuple);
	}

	public static boolean listFiles(TokenTuple groupTokTuple, FileClient fcli, GroupClient gcli) {
		try {
			Thread.sleep(1000); //sleep for one second to let server upload file
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		List<String> files = fcli.listFiles(groupTokTuple);
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

	public static boolean uploadFile(Scanner input, TokenTuple groupTokTuple, FileClient fcli, GroupClient gcli) {
		System.out.println("Please enter the source file name: ");
		String sourceFile = input.nextLine();
		while(sourceFile.isEmpty()) {
			System.out.println("Please enter a valid file name(Enter break to exit): ");
			sourceFile = input.nextLine();
			if(sourceFile.equalsIgnoreCase("break"))
				return false;
		}
		System.out.println("Please enter the destination file name: ");
		String destFile = input.nextLine();
		while(destFile.isEmpty()) {
			System.out.println("Please enter a valid file name(Enter break to exit): ");
			destFile = input.nextLine();
			if(destFile.equalsIgnoreCase("break"))
				return false;

		}
		System.out.println("Please enter the group name(cannot contain '/' ',' '[' ']' ':' or ' '): ");
		String gName = input.nextLine();
		while(gName.contains("/") || gName.isEmpty() || gName.contains(" ") || gName.contains("[") || gName.contains("]") || gName.contains(":") || gName.contains(",")) {
			System.out.println("Invalid group name, please try again: ");
			gName = input.nextLine();
			if(gName.equals("break"))
				return false;
		}

		File file = new File(sourceFile);
		if(!file.exists()){
			System.out.println("File doesn't exist!");
			return false;
		}

		// get current key version for a group
		int keyVer = gcli.getGroupKeyVer(gName);
		if(keyVer == -1){
			System.out.println("There was a problem getting the key version");
			return false;
		}
		// get the actual key for that group and version
		Key groupKey = gcli.getGroupKey(gName, keyVer);
		if(groupKey == null){
			System.out.println("There was a problem getting the group key");
			return false;
		}
		return fcli.upload(sourceFile, destFile, gName, groupTokTuple, groupKey, keyVer);
	}

	public static boolean downloadFile(Scanner input, TokenTuple groupTokTuple, FileClient fcli, GroupClient gcli) {
		System.out.println("Please enter the source file name: ");
		String sourceFile = input.nextLine();
		while(sourceFile.isEmpty()) {
			System.out.println("Please enter a valid file name(Enter break to exit): ");
			sourceFile = input.nextLine();
			if(sourceFile.equalsIgnoreCase("break"))
				return false;
		}
		System.out.println("Please enter the destination file name: ");
		String destFile = input.nextLine();
		while(destFile.isEmpty()) {
			System.out.println("Please enter a valid file name(Enter break to exit): ");
			destFile = input.nextLine();
			if(destFile.equalsIgnoreCase("break"))
				return false;
		}
		try{
			// do basic check for file
			File file = new File(destFile);
			if(file.exists()){
				System.out.println("File already exists!");
				return false;
			}
			// get name of group from filename
			String groupName = "[NONE]";
			groupName = fcli.getGroup(sourceFile);
			if(groupName.equals("")){
				System.out.println("There was a problem getting the group");
				return false;
			}
			// System.out.println("name: " + groupName);
			// get file version number from filename
			int version = fcli.getKeyVer(sourceFile);
			if(version == -1){
				System.out.println("There was a problem getting the key version");
				return false;
			}
			// System.out.println("ver: " + version);
			// get the actual key for that group and version
			Key groupKey = gcli.getGroupKey(groupName, version);
			if(groupKey == null){
				System.out.println("There was a problem getting the group key");
				return false;
			}
			return fcli.download(sourceFile, destFile, groupTokTuple, groupKey);
		}catch(Exception e){
			e.printStackTrace();
		}
		return  false;
	}

	public static boolean deleteFile(Scanner input, TokenTuple groupTokTuple, FileClient fcli) {
		System.out.println("Please enter the file you would like to delete: ");
		String filename = input.nextLine();
		while(filename.isEmpty()) {
			System.out.println("Please enter a valid file name: ");
			filename = input.nextLine();
			if(filename.equals("break"))
				return false;
		}
		return fcli.delete(filename, groupTokTuple);
	}


}
