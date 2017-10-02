import java.util.ArrayList;
import java.util.Scanner;

public class RunGroupClient {

	public static void main(String[] args) {
		GroupClient gcli = new GroupClient();
		gcli.connect(null, GroupServer.SERVER_PORT);
		FileClient fcli = new FileClient();
		fcli.connect(null, FileServer.SERVER_PORT);
		
		if(gcli.isConnected())
			System.out.println("Group Server Connected!");
		else
			System.err.println("Failed to Connect to Group Server");
		
		if(fcli.isConnected())
			System.out.println("File Server Connected!");
		else
			System.err.println("Failed to Connect to File Server");
		if(!gcli.isConnected() || !fcli.isConnected())
			return;
		
		int menuChoice = -1;
		Scanner input = new Scanner(System.in);
		while(menuChoice != 12) {
			do{
				System.out.println("\n---Please select an option---");
				System.out.println("0.GetUserToken\n"
								 + "1.Create User\n"
								 + "2.Delete User\n"
								 + "3.Create Group\n"
								 + "4.Delete Group\n"
								 + "5.List Members\n"
								 + "6.Add User to Group\n"
								 + "7.Delete User from Group\n"
								 + "8.List Files\n"
								 + "9.Upload File\n"
								 + "10.Download File\n"
								 + "11.Delete File\n"
								 + "12.Disconnect");
			
			if(input.hasNextInt()) {	
				menuChoice = input.nextInt();
			}else {
				menuChoice = -1;
			}
			input.nextLine(); 				//Consume the endline
			}while(menuChoice < 0 || menuChoice > 12);
			
			switch(menuChoice) {
				
				case 0: //Get Token
					if(getToken(input, gcli))
						System.out.println("Successful");
					else
						System.out.println("User not found");
					break;
					
				case 1: //Create User
					if(createUser(input, gcli))
						System.out.println("Successful");
					else
						System.out.println("User Creatiion Failed");
					break;
				
				case 2: //Delete User
					if(deleteUser(input, gcli))
						System.out.println("Successful");
					else
						System.out.println("User Deletion Failed");
					break;
				
				case 3: //Create Group
					if(createGroup(input, gcli))
						System.out.println("Successful");
					else
						System.out.println("Group Creation Failed");
					
					break;
				
				case 4: //Delete Group
					if(deleteGroup(input, gcli))
						System.out.println("Successful");
					else
						System.out.println("Group Deletion Failed");
					break;
				
				case 5: //List Members
					if(listMembers(input, gcli))
						System.out.println("Successful");
					else
						System.out.println("List Members Failed");
					break;
				
				case 6: //Add User To Group
					if(addUserToGroup(input, gcli))
						System.out.println("Successful");
					else
						System.out.println("Add Member Failed");
					break;
				
				case 7: //Delete User From Group
					if(deleteUserFromGroup(input, gcli))
						System.out.println("Successful");
					else
						System.out.println("Delete Member Failed");
					break;
					
				case 8: //List Files
					if(listFiles(gcli.tok, fcli))
						System.out.println("Successful");
					else
						System.out.println("Delete Member Failed");
					break;
				
				case 9: //Upload File
					if(uploadFile(input, gcli.tok, fcli))
						System.out.println("Successful");
					else
						System.out.println("Delete Member Failed");
					break;
					
				case 10: //Download File
					if(deleteUserFromGroup(input, gcli))
						System.out.println("Successful");
					else
						System.out.println("Delete Member Failed");
					break;
					
				case 11: //Delete File
					if(deleteUserFromGroup(input, gcli))
						System.out.println("Successful");
					else
						System.out.println("Delete Member Failed");
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
			String name = input.nextLine();
			if(gcli.createUser(name, token))
				return true;
			else
				return false;
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
			String name = input.nextLine();
			if(gcli.deleteUser(name, token))
				return true;
			else
				return false;
		}
		else{
			System.out.println("Admin Privledges Required To delete User");
			return false;
		}
	}

	public static boolean createGroup(Scanner input, GroupClient gcli){
		System.out.println("Enter the name for the group: ");
		String gName = input.nextLine();
		UserToken token = gcli.tok;
		if(gcli.createGroup(gName, token)) {
			System.out.println("tru");
			return true;
		}
		System.out.println("Not tru");
		return false;
				
	}

	public static boolean deleteGroup(Scanner input, GroupClient gcli){
		System.out.println("Enter the name of the group: ");
		String gName = input.nextLine();
		UserToken token = gcli.tok;
		if(gcli.deleteGroup(gName, token))
			return true;
		else
			return false;
	}

	public static boolean listMembers(Scanner input, GroupClient gcli){
		System.out.println("Enter the name of the group: ");
		String gName = input.nextLine();
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
		String name = input.nextLine();
		System.out.println("Enter the name of the group: ");
		String gName = input.nextLine();
		UserToken token = gcli.tok;
		if(gcli.addUserToGroup(name, gName, token))
			return true;
		else
			return false;
	}

	public static boolean deleteUserFromGroup(Scanner input, GroupClient gcli){
		System.out.println("Enter the name of the user to remove: ");
		String name = input.nextLine();
		System.out.println("Enter the name of the group: ");
		String gName = input.nextLine();
		UserToken token = gcli.tok;
		if(gcli.deleteUserFromGroup(name, gName, token))
			return true;
		else
			return false;
	}
	
	//METHOD STUBS TODO Finish these stubs, taking in input correctly and such
	public static boolean listFiles(UserToken token, FileClient fcli) {
		fcli.listFiles(token);
		return true;
	}
	
	public static boolean uploadFile(Scanner input, UserToken token, FileClient fcli) {
		String sourceFile = input.nextLine();
		String destFile = input.nextLine();
		String group = input.nextLine();
		fcli.upload(sourceFile, destFile, group, token);
		return true;
	}
	
	public static boolean downloadFile(Scanner input, UserToken token, FileClient fcli) {
		String sourceFile = input.nextLine();
		String destFile = input.nextLine();
		fcli.download(sourceFile, destFile, token);
		return true;
	}
	
	public static boolean deleteFile(Scanner input, UserToken token, FileClient fcli) {
		String filename = input.nextLine();
		fcli.delete(filename, token);
		return true;
	}
	//END METHOD STUBS
	
}
