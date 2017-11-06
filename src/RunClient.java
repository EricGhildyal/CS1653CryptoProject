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
						System.out.println("User not found or password was incorrect");
					break;

				case 1: //Create User
					if(gcli.tokTuple != null){
						if(createUser(input, gcli))
							System.out.println("Successfully Created User\n");
						else
							System.out.println("User Creation Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 2: //Delete User
					if(gcli.tokTuple != null){
						if(deleteUser(input, gcli))
							System.out.println("Successfully Deleted User\n");
						else
							System.out.println("User Deletion Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 3: //Create Group
					if(gcli.tokTuple != null){
						if(createGroup(input, gcli))
							System.out.println("Successfully Created Group\n");
						else
							System.out.println("Group Creation Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");

					break;

				case 4: //Delete Group
					if(gcli.tokTuple !=null){
						if(deleteGroup(input, gcli))
							System.out.println("Successfully Deleted Group\n");
						else
							System.out.println("Group Deletion Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 5: //List Members
					if(gcli.tokTuple != null){
						if(!listMembers(input, gcli))
							System.out.println("List Members Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 6: //Add User To Group
					if(gcli.tokTuple != null){
						if(addUserToGroup(input, gcli))
							System.out.println("Successfully Added User\n");
						else
							System.out.println("Add Member Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 7: //Delete User From Group
					if(gcli.tokTuple != null){
						if(deleteUserFromGroup(input, gcli))
							System.out.println("Successfully Removed User from Group\n");
						else
							System.out.println("Delete Member Failed");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 8: //List Files
					if(gcli.tokTuple != null){
						if(!listFiles(gcli.tokTuple, fcli))
							System.out.println("List Files Failed\n");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 9: //Upload File
					if(gcli.tokTuple != null){
						uploadFile(input, gcli.tokTuple, fcli);
						System.out.println("");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 10: //Download File
					if(gcli.tokTuple != null){
						downloadFile(input, gcli.tokTuple, fcli);
						System.out.println("");
					}
					else
						System.out.println("Please get token before attempting other actions");
					break;

				case 11: //Delete File
					if(gcli.tokTuple != null){
						deleteFile(input, gcli.tokTuple, fcli);
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

		TokenTuple tokTuple = gcli.getToken(username, password);		//gets Usertoken from server
		UserToken tok = tokTuple.tok;

		if(tok != null) {
			gcli.tokTuple = tokTuple;							//Saves the token to gclient
			return true;
		}
		return false;
	}

	public static boolean createUser(Scanner input, GroupClient gcli){
		TokenTuple tokTuple = gcli.tokTuple;
		if(tokTuple.tok.getGroups().contains("ADMIN")){

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

			return gcli.createUser(username, password, tokTuple);
		}
		else{
			System.out.println("Admin Privledges Required To Create User");
			return false;
		}
	}

	public static boolean deleteUser(Scanner input, GroupClient gcli){
		TokenTuple tokTuple = gcli.tokTuple;
		if(tokTuple.tok.getGroups().contains("ADMIN")){
			System.out.println("Enter username to delete: ");
			String username = input.nextLine();
			if(username.isEmpty()) {
				System.out.println("Invalid username, please try again: ");
				username = input.nextLine();
			}
			return gcli.deleteUser(username, tokTuple);
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

		TokenTuple tokTuple = gcli.tokTuple;
		if(gcli.createGroup(gName, tokTuple)) {
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
		TokenTuple tokTuple = gcli.tokTuple;
		return gcli.deleteGroup(gName, tokTuple);
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
		TokenTuple tokTuple = gcli.tokTuple;
		ArrayList<String> members = (ArrayList<String>)gcli.listMembers(gName, tokTuple);
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
		TokenTuple tokTuple = gcli.tokTuple;
		return gcli.addUserToGroup(username, gName, tokTuple);
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
		TokenTuple tokTuple = gcli.tokTuple;
		return gcli.deleteUserFromGroup(username, gName, tokTuple);
	}

	public static boolean listFiles(TokenTuple tokTuple, FileClient fcli) {
		try {
			Thread.sleep(1000); //sleep for one second to let server upload file
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		List<String> files = fcli.listFiles(tokTuple);
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

	public static boolean uploadFile(Scanner input, TokenTuple tokTuple, FileClient fcli) {
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
		return fcli.upload(sourceFile, destFile, gName, tokTuple);
	}

	public static boolean downloadFile(Scanner input, TokenTuple tokTuple, FileClient fcli) {
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
		return fcli.download(sourceFile, destFile, tokTuple);
	}

	public static boolean deleteFile(Scanner input, TokenTuple tokTuple, FileClient fcli) {
		System.out.println("Please enter the file you would like to delete: ");
		String filename = input.nextLine();
		while(filename.isEmpty()) {
			System.out.println("Please enter a valid file name: ");
			filename = input.nextLine();
			if(filename.equals("break"))
				return false;
		}
		return fcli.delete(filename, tokTuple);
	}


}
