/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.security.*;
import java.util.*;


public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	public UserList userList;
  public ArrayList<Group> groupList = new ArrayList<>();
	public String fname = "";
	public static KeyRing keyRing;
	public CryptoHelper crypto;



	public GroupServer(String dbFileName) {
		super(SERVER_PORT, "ALPHA");
		crypto = new CryptoHelper();
		fname = dbFileName;
		keyRing = new KeyRing("GroupServer");
		if(keyRing.exists()){
			keyRing = crypto.loadRing(keyRing);
		}else{ //create new ring
			keyRing.init();
			KeyPair kp = crypto.getNewKeypair();
			keyRing.addKey("rsa_priv", kp.getPrivate());
			keyRing.addKey("rsa_pub", kp.getPublic());
		}
	}

	public GroupServer(int _port, String dbFileName) {
		super(_port, "ALPHA");
		fname = dbFileName;
		keyRing = new KeyRing("GroupServer");
		if(keyRing.exists()){
			keyRing = crypto.loadRing(keyRing);
		}else{ //create new ring
			keyRing.init();
			KeyPair kp = crypto.getNewKeypair();
			keyRing.addKey("rsa_priv", kp.getPrivate());
			keyRing.addKey("rsa_pub", kp.getPublic());
		}
	}

	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created

		String userFile = "UserList.bin";
		String groupFile = "GroupList.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		//Creates the authentication database, or opens it if it already exists
		File authFile = new File(fname);

		try{
			authFile.createNewFile();
		}catch(Exception e){
			e.printStackTrace();
			System.exit(-1);
		}
		UserPasswordDB authDB = new UserPasswordDB(fname);

		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");

			java.io.Console sysConsole = System.console();
			String username = "";
			String password = "";
			String passwordConfirm = "";

			do{
				username = sysConsole.readLine("Username: ");	//Takes in username input from user
				password = new String(sysConsole.readPassword("Password: ")); //Takes in password input from user
				passwordConfirm = new String(sysConsole.readPassword("Please Retype Password: ")); //Takes in password input from user
				if(username.isEmpty() || password.isEmpty()){
					System.out.println("Invalid username or password format, please try again!");
				}else if(!password.equals(passwordConfirm)){
					System.out.println("Passwords did not match, please try again!");
				}
			}while(username.isEmpty() || password.isEmpty() || !password.equals(passwordConfirm));

			try{
				authDB.add(username, password);
			}catch(Exception f){
				f.printStackTrace();
				System.exit(-1);
			}

			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
			ArrayList<String> admins = new ArrayList<String>();
			admins.add(username);
			groupList.add(new Group(admins, "ADMIN", username));
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		try
		{
			FileInputStream gis = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(gis);
			groupList = (ArrayList<Group>)groupStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("groupList File Does Not Exist. Creating groupList...");
			System.out.println("No groups currently exist.");
		}
		catch(IOException e)
		{
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		//This block listens for connections and creates threads on new connections
		try
		{

			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());
			Socket sock = null;
			GroupThread thread = null;

			while(true)
			{
				sock = serverSock.accept();
				thread = new GroupThread(sock, this, authDB);
				thread.start();
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

	}
}

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		ObjectOutputStream groupOut;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
			groupOut = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			groupOut.writeObject(my_gs.groupList);

		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				ObjectOutputStream groupOut;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
					groupOut = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
					groupOut.writeObject(my_gs.groupList);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}while(true);
	}
}


class Group implements Serializable{
	public ArrayList<String> memberList;
	public String name;
	public String owner;
	static final long serialVersionUID = 7823049212321412923L;

	public Group(ArrayList<String> memberList, String name, String owner) {
		this.memberList = memberList;
		this.name = name;
		this.owner = owner;
	}

	public String toString(){
		return name;
	}
}
