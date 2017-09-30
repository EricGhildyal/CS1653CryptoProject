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
					
					break;
				
				case 2: //Delete User
					
					break;
				
				case 3: //Create Group
					
					break;
				
				case 4: //Delete Group
					
					break;
				
				case 5: //List Members
					
					break;
				
				case 6: //Add User To Group
					
					break;
				
				case 7: //Delete User From Group
					
					break;
				
				case 8: //Disconnect
					
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
}
