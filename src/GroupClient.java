/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.security.*;

public class GroupClient extends Client implements GroupClientInterface {
	private byte [] byteFKey;
	private SecretKeySpec key;
	//Diffie Hellman key
	private Key aesKey;
	private CryptoHelper crypto = new CryptoHelper();

	public boolean connect(final String server, final int port){
		boolean ret = super.connect(server, port);
		aesKey = new SecretKeySpec(this.confidentialityKey.toByteArray(), "AES");
		return ret;
	}

	public TokenTuple getToken(String username, String password){
		try{
			UserToken token = null;
			//TODO this object type probably needs to be change once encrypted with server key
			byte [] hashedToken = new byte [32];
			Envelope message = null, response = null;

			//Tell the server to return a token.
			message = new Envelope("GET");
			byte [] usrName = crypto.encryptAES(username, aesKey);
			byte [] pass = crypto.encryptAES(password, aesKey);

			message.addObject(usrName); //Add user name string
			message.addObject(pass); //Add password
			message = crypto.addMessageNumber(message, msgSent);
			output.reset();
			output.writeObject(message);
			msgSent++;
			crypto.getHash(integrityKey, message, output);


			//Get the response from the server
			response = (Envelope)input.readObject();
			if((int)response.getObjContents().get(0) != msgReceived){
				System.out.println("Wrong message received, aborting");
				return null;
			}
			msgReceived++;
			if(!crypto.verify(integrityKey, response, input)){
				System.out.println("Message was modified, aborting");
			}
			else{

				System.out.println("gcli: " + response.getMessage());
				//Successful response
				if(response.getMessage().equals("OK"))
				{
					//If there is a token in the Envelope, return it
					ArrayList<Object> temp = null;
					temp = response.getObjContents();

					if(temp.size() == 2)
					{
						token = crypto.extractToken(response, 0, aesKey);
						//TODO this object type probably needs to be change once encrypted with server key
						hashedToken = (byte[])response.getObjContents().get(1);

						TokenTuple groupTokTuple = new TokenTuple(token, hashedToken);
						return groupTokTuple;
					}
				}
			}
			return null;
		}
		catch(NullPointerException e){
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}

	 }

	 public TokenTuple getFSToken(String username, String password, String targetRSAPub){
 		try{
 			UserToken token = null;
 			//TODO this object type probably needs to be change once encrypted with server key
 			byte [] hashedToken = new byte [32];
 			Envelope message = null, response = null;

 			//Tell the server to return a token.
 			message = new Envelope("GETFS");
 			byte [] usrName = crypto.encryptAES(username, aesKey);
 			byte [] pass = crypto.encryptAES(password, aesKey);
			byte [] target = crypto.encryptAES(targetRSAPub, aesKey);
 			message.addObject(usrName); //Add user name string
			message.addObject(pass); //Add password
			message.addObject(target); //Add target
			message = crypto.addMessageNumber(message, msgSent);
 			output.reset();
			output.writeObject(message);
			msgSent++;
			crypto.getHash(integrityKey, message, output);


			//Get the response from the server
			response = (Envelope)input.readObject();
			if((int)response.getObjContents().get(0) != msgReceived){
				System.out.println("Wrong message received, aborting");
				return null;
			}
			msgReceived++;
			if(!crypto.verify(integrityKey, response, input)){
				System.out.println("Message was modified, aborting");
			}
			else{

				System.out.println("gcli: " + response.getMessage());
				//Successful response
				if(response.getMessage().equals("OK"))
				{
					//If there is a token in the Envelope, return it
					ArrayList<Object> temp = null;
					temp = response.getObjContents();

					if(temp.size() == 2)
					{
						token = crypto.extractToken(response, 0, aesKey);
						//TODO this object type probably needs to be change once encrypted with server key
						hashedToken = (byte[])response.getObjContents().get(1);

						TokenTuple groupTokTuple = new TokenTuple(token, hashedToken);
						return groupTokTuple;
					}
				}
			}
			return null;
		}
		catch(NullPointerException e){
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}

	 }

	 public boolean createUser(String username, String password, TokenTuple groupTokTuple)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a user
				message = new Envelope("CUSER");
				message.addObject(crypto.encryptAES(username, aesKey)); //Add user name string
				message.addObject(crypto.encryptAES(password, aesKey)); //Add password string
				message.addObject(crypto.encryptAES(groupTokTuple.tok.toString(), aesKey)); //Add the requester's token
				message.addObject(crypto.encryptAES(groupTokTuple.hashedToken, aesKey));//Add the signed token hash
				output.reset();
				message = crypto.addMessageNumber(message, msgSent);
				output.writeObject(message);
				msgSent++;
				crypto.getHash(integrityKey, message, output);

				response = (Envelope)input.readObject();
				if((int)response.getObjContents().get(0) != msgReceived){
					System.out.println("Wrong message received, aborting");
					return false;
				}
				msgReceived++;
				if(!crypto.verify(integrityKey, response, input)){
					System.out.println("Message was modified, aborting");
				}
				else{

					//If server indicates success, return true
					if(response.getMessage().equals("OK"))
					{
						output.reset();
						return true;
					}
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteUser(String username, TokenTuple groupTokTuple)
	 {
		 try
			{
				Envelope message = null, response = null;

				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject(crypto.encryptAES(username, aesKey)); //Add user name
				message.addObject(crypto.encryptAES(groupTokTuple.tok.toString(), aesKey));  //Add requester's token
				message.addObject(crypto.encryptAES(groupTokTuple.hashedToken, aesKey));//Add the signed token hash
				output.reset();
				output.writeObject(message);
				crypto.getHash(integrityKey, message, output);
				response = (Envelope)input.readObject();
				if(!crypto.verify(integrityKey, response, input)){
					System.out.println("Message was modified, aborting");
				}
				else{

					//If server indicates success, return true
					if(response.getMessage().equals("OK"))
					{
						output.reset();
						return true;
					}
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean createGroup(String groupname, TokenTuple groupTokTuple)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject(crypto.encryptAES(groupname, aesKey)); //Add the group name string
				message.addObject(crypto.encryptAES(groupTokTuple.tok.toString(), aesKey)); //Add the requester's token
				message.addObject(crypto.encryptAES(groupTokTuple.hashedToken, aesKey));//Add the signed token hash
				output.reset();
				output.writeObject(message);
				crypto.getHash(integrityKey, message, output);
				response = (Envelope)input.readObject();
				if(!crypto.verify(integrityKey, response, input)){
					System.out.println("Message was modified, aborting");
				}
				else{
					//If server indicates success, return true
					if(response.getMessage().equals("OK")){
						output.reset();
						return true;
					}
				}
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteGroup(String groupname, TokenTuple groupTokTuple)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				message.addObject(crypto.encryptAES(groupname, aesKey)); //Add the group name string
				message.addObject(crypto.encryptAES(groupTokTuple.tok.toString(), aesKey)); //Add the requester's token
				message.addObject(crypto.encryptAES(groupTokTuple.hashedToken, aesKey));//Add the signed token hash
				output.reset();
				output.writeObject(message);
				crypto.getHash(integrityKey, message, output);

				response = (Envelope)input.readObject();
				if(!crypto.verify(integrityKey, response, input)){
					System.out.println("Message was modified, aborting");
				}
				else{
					//If server indicates success, return true
					if(response.getMessage().equals("OK"))
					{
						output.reset();
						return true;
					}
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, TokenTuple groupTokTuple)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 byte [] grp = crypto.encryptAES(group, aesKey);
			 byte [] tok = crypto.encryptAES(groupTokTuple.tok.toString(), aesKey);
			 message.addObject(grp); //Add group name string
			 message.addObject(tok); //Add requester's token
			 message.addObject(crypto.encryptAES(groupTokTuple.hashedToken, aesKey));//Add the signed token hash
			 output.reset();
			 output.writeObject(message);
			 crypto.getHash(integrityKey, message, output);

			 response = (Envelope)input.readObject();
			 if(!crypto.verify(integrityKey, response, input)){
				System.out.println("Message was modified, aborting");
			 }
			 else{
				//If server indicates success, return the member list
				if(response.getMessage().equals("OK"))
				{
					output.reset();
					return crypto.extractList(response, 0, aesKey);
					//return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
				}
			 }

			 return null;

		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }

	 public boolean addUserToGroup(String username, String groupname, TokenTuple groupTokTuple)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject(crypto.encryptAES(username, aesKey)); //Add user name string
				message.addObject(crypto.encryptAES(groupname, aesKey)); //Add the group name string
				message.addObject(crypto.encryptAES(groupTokTuple.tok.toString(), aesKey)); //Add the requester's token
				message.addObject(crypto.encryptAES(groupTokTuple.hashedToken, aesKey));//Add the signed token hash
				output.reset();
				output.writeObject(message);
				crypto.getHash(integrityKey, message, output);

				response = (Envelope)input.readObject();
				if(!crypto.verify(integrityKey, response, input)){
					System.out.println("Message was modified, aborting");
				}
				else{
					//If server indicates success, return true
					if(response.getMessage().equals("OK"))
					{
						output.reset();
						return true;
					}
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteUserFromGroup(String username, String groupname, TokenTuple groupTokTuple)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
				message.addObject(crypto.encryptAES(username, aesKey)); //Add user name string
				message.addObject(crypto.encryptAES(groupname, aesKey)); //Add the group name string
				message.addObject(crypto.encryptAES(groupTokTuple.tok.toString(), aesKey)); //Add the requester's token
				message.addObject(crypto.encryptAES(groupTokTuple.hashedToken, aesKey));//Add the signed token hash
				output.reset();
				output.writeObject(message);
				crypto.getHash(integrityKey, message, output);

				response = (Envelope)input.readObject();
				if(!crypto.verify(integrityKey, response, input)){
					System.out.println("Message was modified, aborting");
				}
				else{
					//If server indicates success, return true
					if(response.getMessage().equals("OK"))
					{
						output.reset();
						return true;
					}
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

}
