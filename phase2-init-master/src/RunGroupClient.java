import java.util.ArrayList;
import java.util.Scanner;

public class RunGroupClient {

	public static void main(String[] args) {
		GroupClient cli = new GroupClient();
		cli.connect(null, GroupServer.SERVER_PORT);
		if(cli.isConnected()) {
			System.out.println("Connected!");
		}else {
			System.err.println("Failed to connect to server.");
			return;
		}
		
		int menuChoice = -1;
		Scanner input = new Scanner(System.in);
		while(menuChoice != 8) {
			do{
				System.out.println("Please select an option:");
				System.out.println("0.GetUserToken\n"
								 + "1.Create User\n"
								 + "2.Delete User\n"
								 + "3.Create Group\n"
								 + "4.Delete Group\n"
								 + "5.List Members\n"
								 + "6.Add User to Group\n"
								 + "7.Delete User from Group\n"
								 + "8.Disconnect");
			menuChoice = input.nextInt();
			input.nextLine(); 				//Consume the endline
			}while(menuChoice < 0 || menuChoice > 8);
			
			switch(menuChoice) {
				
				case 0: //Get Token
					if(getToken(input, cli))
						System.out.println("Successful");
					else
						System.out.println("User not found");
					break;
					
				case 1: //Create User
					if(createUser(input, cli))
						System.out.println("Successful");
					else
						System.out.println("User Creatiion Failed");
					break;
				
				case 2: //Delete User
					if(deleteUser(input, cli))
						System.out.println("Successful");
					else
						System.out.println("User Deletion Failed");
					break;
				
				case 3: //Create Group
					if(createGroup(input, cli))
						System.out.println("Successful");
					else
						System.out.println("Group Creation Failed");
					
					break;
				
				case 4: //Delete Group
					if(deleteGroup(input, cli))
						System.out.println("Successful");
					else
						System.out.println("Group Deletion Failed");
					break;
				
				case 5: //List Members
					if(listMembers(input, cli))
						System.out.println("Successful");
					else
						System.out.println("List Members Failed");
					break;
				
				case 6: //Add User To Group
					if(addUserToGroup(input, cli))
						System.out.println("Successful");
					else
						System.out.println("Add Member Failed");
					break;
				
				case 7: //Delete User From Group
					if(deleteUserFromGroup(input, cli))
						System.out.println("Successful");
					else
						System.out.println("Delete Member Failed");
					break;
				
				case 8: //Disconnect
					cli.disconnect();
					break;
			}
		}
	}
	
	public static boolean getToken(Scanner input, GroupClient cli){
		System.out.println("Which user would you like the token for?");
		String username = input.nextLine();			//Takes in username input from user
		
		UserToken tok = cli.getToken(username);		//gets Usertoken from server
		if(tok != null) {
			cli.tok = tok;							//Saves the token to client
			return true;
		}
		return false;
	}
	
	public static boolean createUser(Scanner input, GroupClient cli){
		UserToken token = cli.tok;
		if(token.getGroups().contains("ADMIN")){
			System.out.println("Enter username for new user: ");
			String name = input.nextLine();
			if(cli.createUser(name, token))
				return true;
			else
				return false;
		}
		else{
			System.out.println("Admin Privledges Required To Create User");
			return false;
		}
	}

	public static boolean deleteUser(Scanner input, GroupClient cli){
		UserToken token = cli.tok;
		if(token.getGroups().contains("ADMIN")){
			System.out.println("Enter username to delete: ");
			String name = input.nextLine();
			UserToken newToken = cli.getToken(name);
			ArrayList<String> groups = (ArrayList<String>)newToken.getGroups();
			for(int i =0; i<groups.size();i++){
				cli.deleteUserFromGroup(name, groups.get(i), token);
			}
			if(cli.deleteUser(name, token))
				return true;
			else
				return false;
		}
		else{
			System.out.println("Admin Privledges Required To delete User");
			return false;
		}
	}

	public static boolean createGroup(Scanner input, GroupClient cli){
		System.out.println("Enter the name for the group: ");
		String gName = input.nextLine();
		UserToken token = cli.tok;
		if(cli.createGroup(gName, token))
			return true;
		else
			return false;
				
	}

	public static boolean deleteGroup(Scanner input, GroupClient cli){
		System.out.println("Enter the name of the group: ");
		String gName = input.nextLine();
		UserToken token = cli.tok;
		if(cli.deleteGroup(gName, token))
			return true;
		else
			return false;
	}

	public static boolean listMembers(Scanner input, GroupClient cli){
		System.out.println("Enter the name of the group: ");
		String gName = input.nextLine();
		UserToken token = cli.tok;
		ArrayList<String> members = (ArrayList<String>)cli.listMembers(gName, token);
		if(members != null)
			return true;
		else
			return false;
	}

	public static boolean addUserToGroup(Scanner input, GroupClient cli){
		System.out.println("Enter the name of the user to add: ");
		String name = input.nextLine();
		System.out.println("Enter the name of the group: ");
		String gName = input.nextLine();
		UserToken token = cli.tok;
		if(cli.addUserToGroup(name, gName, token))
			return true;
		else
			return false;
	}

	public static boolean deleteUserFromGroup(Scanner input, GroupClient cli){
		System.out.println("Enter the name of the user to remove: ");
		String name = input.nextLine();
		System.out.println("Enter the name of the group: ");
		String gName = input.nextLine();
		UserToken token = cli.tok;
		if(cli.deleteUserFromGroup(name, gName, token))
			return true;
		else
			return false;
	}
}
