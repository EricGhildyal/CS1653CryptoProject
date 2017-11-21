/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import java.util.Random;
import java.io.IOException;
import java.lang.ClassNotFoundException;
import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.crypto.generators.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.agreement.DHAgreement;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import java.security.*;
import java.math.*;
import javax.crypto.spec.SecretKeySpec;

public class GroupThread extends Thread
{
	private final Socket socket;
	private GroupServer my_gs;
	private UserPasswordDB my_db;
	final ObjectInputStream input;
	final ObjectOutputStream output;
	BigInteger confidentialityKey;
	BigInteger integrityKey;
	CryptoHelper crypto;

	public GroupThread(Socket _socket, GroupServer _gs, UserPasswordDB db) throws IOException, ClassNotFoundException
	{
		crypto = new CryptoHelper();
		socket = _socket;
		my_gs = _gs;
		my_db = db;
		input = new ObjectInputStream(socket.getInputStream());
		output = new ObjectOutputStream(socket.getOutputStream());
	}

	private boolean setupDH(Envelope message){
		try{
			//get the p and g used to create from params from client
			ArrayList<Object> vals = message.getObjContents();
			BigInteger g = (BigInteger)vals.get(0);
			BigInteger p =(BigInteger)vals.get(1);
			BigInteger clientPubKey = (BigInteger)vals.get(2);
			BigInteger clientIntPub = (BigInteger)vals.get(3);
			//define the parameters based off the p and g, generate keys and send the public to client
			DHParameters params = new DHParameters(p, g);
			DHKeyGenerationParameters keyGenParams = new DHKeyGenerationParameters(new SecureRandom(), params);
			DHKeyPairGenerator keyGen = new DHKeyPairGenerator();
			keyGen.init(keyGenParams);
			AsymmetricCipherKeyPair serverKeys = keyGen.generateKeyPair();
			DHPublicKeyParameters publicKeyParam = (DHPublicKeyParameters)serverKeys.getPublic();
			DHPrivateKeyParameters privateKeyParam = (DHPrivateKeyParameters)serverKeys.getPrivate();
			BigInteger pubKey = publicKeyParam.getY();
			AsymmetricCipherKeyPair serverIntKeys = keyGen.generateKeyPair();
			DHPublicKeyParameters publicIntKeyParam = (DHPublicKeyParameters)serverIntKeys.getPublic();
			DHPrivateKeyParameters privateIntKeyParam = (DHPrivateKeyParameters)serverIntKeys.getPrivate();
			BigInteger pubIntKey = publicIntKeyParam.getY();
			Envelope serverPub = new Envelope("key");
			serverPub.addObject(pubKey);
			serverPub.addObject(pubIntKey);
			output.reset();
			output.writeObject(serverPub);
			DHPublicKeyParameters clientPub = new DHPublicKeyParameters(clientPubKey, params);
			//create the agreement to make the session key
			DHBasicAgreement keyAgree = new DHBasicAgreement();
			keyAgree.init(serverKeys.getPrivate());
			confidentialityKey = keyAgree.calculateAgreement(clientPub);
			clientPub = new DHPublicKeyParameters(clientIntPub, params);
			keyAgree = new DHBasicAgreement();
			keyAgree.init(serverIntKeys.getPrivate());
			integrityKey = keyAgree.calculateAgreement(clientPub);
			
			output.reset();
		}catch(Exception e){
			System.out.println("Error during Diffie Hellman exchange: " + e);
			return false;
		}
		return true;
	}

	public void run(){
		boolean proceed = true;
		try{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			//create new AES key from Diffie Hellman
			Key aesKey = null;
			boolean dhDone = false;
			do{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;
				//busy wait until DH is done
				if(!dhDone){
					while(!dhDone){
						System.out.println("dh loop"); //TODO remove
						if(message.getMessage().equals("DHMSGS")){
							if(setupDH(message)){
								dhDone = true;
								aesKey = new SecretKeySpec(confidentialityKey.toByteArray(),"AES");
							}
						}
					}
				}
				else if(message.getMessage().equals("GET")){ //Client wants a token
			
				
				//output.reset();
				//if(message.getMessage().equals("GET")){ //Client wants a token
					
					String username = crypto.decryptAES((byte[])message.getObjContents().get(0), aesKey); //Get the username
					String password = crypto.decryptAES((byte[])message.getObjContents().get(1), aesKey); //Get the password
					
					
					
					if(!crypto.verify(integrityKey, message, input)){
						response = new Envelope("FAIL");
						response.addObject(null);
						output.reset();
						output.writeObject(response);
						crypto.getHash(integrityKey, response, output);
					}
					else{
					
						if(username == null || password == null || !my_db.get(username, password)){
							response = new Envelope("FAIL");
							
							response.addObject(null);
							output.reset();
							output.writeObject(response);
							crypto.getHash(integrityKey, response, output);
						}else{
							UserToken yourToken = createToken(username); //Create a token
							//Respond to the client. On error, the client will receive a null token
							response = new Envelope("OK");
							byte [] tok = new byte[32];
							byte [] uniqueStringHash;
							if(yourToken != null){
								//TODO uniqueStringHash needs to be encrypted with GroupServers private key
								uniqueStringHash = crypto.sha256Bytes(yourToken.toUniqueString());
								tok = crypto.encryptAES(yourToken.toString(), aesKey);
								response.addObject(tok);
								response.addObject(uniqueStringHash);
							}else{
								response.addObject(yourToken);
							}
							output.reset();
							output.writeObject(response);
							crypto.getHash(integrityKey, response, output);
						}
					}
				}else if(message.getMessage().equals("CUSER")){ //Client wants to create a user
					if(message.getObjContents().size() < 4){
						response = new Envelope("FAIL");
					}else{
						if(!crypto.verify(integrityKey, message, input)){
							response = new Envelope("FAIL");
							/*response.addObject(null);
							output.reset();
							output.writeObject(response);*/
						}
						else{
							response = new Envelope("FAIL");
							if(message.getObjContents().get(0) != null){
								if(message.getObjContents().get(1) != null){
									
									String username = crypto.decryptAES((byte[])message.getObjContents().get(0), aesKey); //Get the username
									String password = crypto.decryptAES((byte[])message.getObjContents().get(1), aesKey); //Get the password
									UserToken yourToken = crypto.extractToken(message, 2, aesKey); //Extract the token
									byte[] hashedToken = crypto.decryptAESBytes((byte [])message.getObjContents().get(3), aesKey);
									//TODO checkToken
									if(createUser(username, password, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
						}
					}
					output.reset();
					output.writeObject(response);
					crypto.getHash(integrityKey, response, output);
				}
				else if(message.getMessage().equals("DUSER")){ //Client wants to delete a user
					if(message.getObjContents().size() < 2){
						response = new Envelope("FAIL");
					}else{
						if(!crypto.verify(integrityKey, message, input)){
							response = new Envelope("FAIL");
							/*response.addObject(null);
							output.reset();
							output.writeObject(response);*/
						}
						else{
							response = new Envelope("FAIL");
							if(message.getObjContents().get(0) != null){
								if(message.getObjContents().get(1) != null){
									String username = crypto.decryptAES((byte [])message.getObjContents().get(0), aesKey); //Extract the username
									UserToken yourToken = crypto.extractToken(message, 1, aesKey); //Extract the token
									byte[] hashedToken = crypto.decryptAESBytes((byte [])message.getObjContents().get(2), aesKey);
									//TODO checkToken
									if(deleteUser(username, yourToken)){
										response = new Envelope("OK"); //Success
									}else{
										response = new Envelope("FAIL");
									}
								}
							}
						}
					}
					output.reset();
					output.writeObject(response);
					crypto.getHash(integrityKey, response, output);
				}
				else if(message.getMessage().equals("CGROUP")){ //Client wants to create a group
					if(message.getObjContents().size() < 3){ //check for valid number of args
						response = new Envelope("FAIL");
					}else{
						if(!crypto.verify(integrityKey, message, input)){
							response = new Envelope("FAIL");
							/*response.addObject(null);
							output.reset();
							output.writeObject(response);*/
						}
						else{
							response = new Envelope("FAIL");
							if(message.getObjContents().get(0) != null){ //get groupName
								if(message.getObjContents().get(1) != null){ //get token
									String groupName = crypto.decryptAES((byte [])message.getObjContents().get(0), aesKey); //Extract the username
									UserToken yourToken = crypto.extractToken(message, 1, aesKey); //Extract the token
									byte[] hashedToken = crypto.decryptAESBytes((byte [])message.getObjContents().get(2), aesKey); //Extract signed token hash
									//TODO check token
									if(!groupName.isEmpty() || !groupName.contains("/")|| !groupName.contains("/") || !groupName.contains(" ") || !groupName.contains("[") || !groupName.contains("]") || !groupName.contains(":") || !groupName.contains(",")){
										System.out.println("Creating group");
										if(createGroup(groupName, yourToken)){
											System.out.println("Successful");
											response = new Envelope("OK");
										}
									}
								}
							}
						}
					}
					output.reset();
					output.writeObject(response);
					crypto.getHash(integrityKey, response, output);
				}
				else if(message.getMessage().equals("DGROUP")){ //Client wants to delete a group
					if(message.getObjContents().size() < 3){ //check for valid number of args
						response = new Envelope("FAIL");
					}else{
						if(!crypto.verify(integrityKey, message, input)){
							response = new Envelope("FAIL");
							/*response.addObject(null);
							output.reset();
							output.writeObject(response);*/
						}
						else{
							response = new Envelope("FAIL");
							if(message.getObjContents().get(0) != null){ //get groupName
								if(message.getObjContents().get(1) != null){ //get token
									String groupName = crypto.decryptAES((byte [])message.getObjContents().get(0), aesKey); //Extract the username
									UserToken yourToken = crypto.extractToken(message, 1, aesKey); //Extract the token
									byte[] hashedToken = crypto.decryptAESBytes((byte [])message.getObjContents().get(2), aesKey); //Extract signed token hash
									//TODO check token
									if(!groupName.isEmpty() || !groupName.contains("/")|| !groupName.contains("/") || !groupName.contains(" ") || !groupName.contains("[") || !groupName.contains("]") || !groupName.contains(":") || !groupName.contains(",")){
										if(deleteGroup(groupName, yourToken)){
											response = new Envelope("OK");
										}
									}
								}
							}
						}
					}
					output.reset();
					output.writeObject(response);
					crypto.getHash(integrityKey, response, output);
				}else if(message.getMessage().equals("LMEMBERS")){ //Client wants a list of members in a group
					if(message.getObjContents().size() < 3){ //check for valid number of args
						response = new Envelope("FAIL");
					}else{
						if(!crypto.verify(integrityKey, message, input)){
							response = new Envelope("FAIL");
							/*response.addObject(null);
							output.reset();
							output.writeObject(response);*/
						}
						else{
							response = new Envelope("FAIL");
							if(message.getObjContents().get(0) != null){ //get groupName
								if(message.getObjContents().get(1) != null){ //get token
									String groupName = crypto.decryptAES((byte[])message.getObjContents().get(0), aesKey); //Extract the groupName
									UserToken yourToken = crypto.extractToken(message, 1, aesKey); //Extract the token
									byte[] hashedToken = crypto.decryptAESBytes((byte [])message.getObjContents().get(2), aesKey); //Extract signed token hash
									//TODO check token
									response = new Envelope("OK");
									byte [] mems;
									if(!groupName.isEmpty() || !groupName.contains("/")|| !groupName.contains("/") || !groupName.contains(" ") || !groupName.contains("[") || !groupName.contains("]") || !groupName.contains(":") || !groupName.contains(",")){
										try{
											mems = crypto.encryptAES(listMembers(groupName, yourToken).toString(), aesKey);
											response.addObject(mems);
										}catch(NullPointerException e){
											response = new Envelope("FAIL");
										}
									}
								}
							}
						}
					}
					output.reset();
					output.writeObject(response);
					crypto.getHash(integrityKey, response, output);
				}
				else if(message.getMessage().equals("AUSERTOGROUP")){ //Client wants to add user to a group
					if(message.getObjContents().size() < 4){ //check for valid number of args
						response = new Envelope("FAIL");
					}else{
						if(!crypto.verify(integrityKey, message, input)){
							response = new Envelope("FAIL");
							/*response.addObject(null);
							output.reset();
							output.writeObject(response);*/
						}
						else{
							response = new Envelope("FAIL");
							if(message.getObjContents().get(0) != null){ //get username
								if(message.getObjContents().get(1) != null){ //get groupname
									if(message.getObjContents().get(2) != null){ //get token
										String username = crypto.decryptAES((byte[])message.getObjContents().get(0), aesKey); //Get the username
										String groupName = crypto.decryptAES((byte[])message.getObjContents().get(1), aesKey); //Get the group name
										UserToken yourToken = crypto.extractToken(message, 2, aesKey); //Extract the token
										byte[] hashedToken = crypto.decryptAESBytes((byte [])message.getObjContents().get(3), aesKey); //Extract signed token hash
										//TODO check token
										if(!groupName.isEmpty() || !groupName.contains("/")|| !groupName.contains("/") || !groupName.contains(" ") || !groupName.contains("[") || !groupName.contains("]") || !groupName.contains(":") || !groupName.contains(",")){
											if(addUserToGroup(username, groupName, yourToken)){
												response = new Envelope("OK");
											}
										}
									}
								}
							}
						}
					}
					output.reset();
					output.writeObject(response);
					crypto.getHash(integrityKey, response, output);
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")){ //Client wants to remove user from a group
					if(message.getObjContents().size() < 4){ //check for valid number of args
						response = new Envelope("FAIL");
					}else{
						if(!crypto.verify(integrityKey, message, input)){
							response = new Envelope("FAIL");
							/*response.addObject(null);
							output.reset();
							output.writeObject(response);*/
						}
						else{
							response = new Envelope("FAIL");
							if(message.getObjContents().get(0) != null){ //get username
								if(message.getObjContents().get(1) != null){ //get groupname
									if(message.getObjContents().get(2) != null){ //get token
										String username = crypto.decryptAES((byte[])message.getObjContents().get(0), aesKey); //Get the username
										String groupName = crypto.decryptAES((byte[])message.getObjContents().get(1), aesKey); //Get the password
										UserToken yourToken = crypto.extractToken(message, 2, aesKey); //Extract the token
										byte[] hashedToken = crypto.decryptAESBytes((byte [])message.getObjContents().get(3), aesKey); //Extract signed token hash
										//TODO check token

										if(!groupName.isEmpty() || !groupName.contains("/")|| !groupName.contains("/") || !groupName.contains(" ") || !groupName.contains("[") || !groupName.contains("]") || !groupName.contains(":") || !groupName.contains(",")){
											if(removeUserFromGroup(username, groupName, yourToken)){
												response = new Envelope("OK");
											}
											else{
												response = new Envelope("FAIL");
											}
										}
									}
								}
							}
						}
					}
					output.reset();
					output.writeObject(response);
					crypto.getHash(integrityKey, response, output);
				}else if(message.getMessage().equals("DISCONNECT")){ //Client wants to disconnect
					crypto.saveRing(my_gs.keyRing);
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}else{
					System.out.println(message.getMessage());
					response = new Envelope("FAIL"); //Server does not understand client request
					output.reset();
					output.writeObject(response);
				}
			
			}while(proceed);
		}catch(java.net.SocketException s){
			//do nothing
		}catch(Exception e){
			System.err.println("Error in file thread: " + e);
		}
	}

	//Removes a user from the group on the server
	private boolean removeUserFromGroup(String username, String groupName, UserToken token){
		if(!my_gs.userList.checkUser(username)){
			return false;
		}
		if(my_gs.userList.getUserOwnership(username).contains(groupName)) {
			System.err.println("Cannot remove a user from a group they own.");
			return false;
		}
		for (Group g : my_gs.groupList) {
			if(g.name.equals(groupName)) {				//Finds the group by name
				for (String u : g.memberList) {
					if(u.equals(username)) {			//Finds the user in that group
						g.memberList.remove(u);			//Removes the user
						my_gs.userList.removeGroup(username, groupName);
						return true;
					}
				}
				System.err.printf("Error: User %s not found in group %s!\n", username, groupName);
				return false;
			}
		}
		System.err.printf("Error: Group %s not found!\n", groupName);
		return false;
	}
	//Adds a user to a group on the server
	private boolean addUserToGroup(String username, String groupName, UserToken token){
		if(my_gs.userList.checkUser(username)){
			for (Group g : my_gs.groupList){
				if(g.name.equals(groupName)){ 			//Finds a group by name
					for (String u : g.memberList){
						if(u.equals(username)){ 		//Checks if user is already in the group
							System.err.printf("Error: User %s is already in group %s!\n", username, groupName);
							return false;
						}
					}
					g.memberList.add(username);			//If the user is not in the group, it adds them
					my_gs.userList.addGroup(username, groupName);
					return true;
				}
			}
			System.err.printf("Error: Group %s not found!\n", groupName);
			return false;
		}
		System.err.printf("Error: User %s not found!\n", username);
		return false;
	}

	//Returns all the members in a group
	private ArrayList<String> listMembers(String groupName, UserToken token){
		if(my_gs.groupList.isEmpty())
			return null;
		System.out.println(my_gs.groupList);
		for (Group g : my_gs.groupList) {
			if(g.name.equals(groupName)) {				//Finds the group by name
				return g.memberList;					//Returns the list of members in that group
			}
		}
		System.err.printf("Error: Group %s not found!\n", groupName);
		return null;									//Returns null if the group is not found
	}

	//Creates a group on the server
	private boolean createGroup(String groupName, UserToken token){
		for (Group g : my_gs.groupList) {
			if(g.name.equals(groupName)) {				//Checks if the group already exists
				System.err.printf("Error: Group %s already exists!\n", groupName);
				return false;
			}
		}												//If not, it creates it, adds the creating user to it and returns true
		Group tGroup = new Group(new ArrayList<String>(), groupName, token.getSubject());
		tGroup.memberList.add(token.getSubject());
		my_gs.groupList.add(tGroup);
		my_gs.userList.addGroup(token.getSubject(), groupName);
		return true;
	}

	//Deletes a group from the server
	private boolean deleteGroup(String groupName,UserToken token){
		if(groupName.equals("ADMIN")) {
			System.err.println("The ADMIN group cannot be deleted");
			return false;
		}
		for (Group g : my_gs.groupList) {
			if(g.name.equals(groupName)) {				//Finds group by name
				my_gs.groupList.remove(g);				//Removes that group from the server
				return true;
			}
		}
		System.err.printf("Error: Group %s not found!\n", groupName);
		return false;
	}

	//Method to create tokens
	private UserToken createToken(String username)
	{
		//Check that user exists
		System.out.println("In createToken");
		if(my_gs.userList.checkUser(username)){
			System.out.println("nameExists");
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
			System.out.println(yourToken);
			return yourToken;
		}else{
			System.out.println("Name doesnt exists");
			return null;
		}
	}


	//Method to create a user
	private boolean createUser(String username, String password, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN")){
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}else{

					try{
						my_db.add(username, password);
					}catch(Exception e){
						e.printStackTrace();
						return false;
					}

					my_gs.userList.addUser(username);
					return true;
				}
			}else{
				return false; //requester not an administrator
			}
		}else{
			return false; //requester does not exist
		}
	}

	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		if(!my_gs.userList.checkUser(username))
			return false;
		if(my_gs.userList.getUserOwnership(username).contains("ADMIN")) {
			System.err.println("The owner of the admin group cannot be deleted!");
			return false;
		}

		String requester = yourToken.getSubject();

		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();

					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}

					for(int i = 0; i< deleteFromGroups.size(); i++) {
						System.out.println(removeUserFromGroup(username, deleteFromGroups.get(i), yourToken));
					}

					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}

					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
					}

					//Delete the user from the user list
					my_gs.userList.deleteUser(username);

					//Delete the user from the authDB
					try{
						my_db.remove(username);
					}catch(Exception e){
						System.err.println("ERROR: Could not remove user from auth DB");
						e.printStackTrace();
						return false;
					}
					return true;
				}
				else
				{
					return false; //User does not exist

				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

}
