/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
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
		aesKey = new SecretKeySpec(this.sKey.toByteArray(), "AES");
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
			output.reset();
			output.writeObject(message);

			//Get the response from the server
			response = (Envelope)input.readObject();
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

					TokenTuple tokTuple = new TokenTuple(token, hashedToken);
					return tokTuple;
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

	 public boolean createUser(String username, String password, TokenTuple tokTuple)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a user
				message = new Envelope("CUSER");
				message.addObject(crypto.encryptAES(username, aesKey)); //Add user name string
				message.addObject(crypto.encryptAES(password, aesKey)); //Add password string
				message.addObject(crypto.encryptAES(tokTuple.tok.toString(), aesKey)); //Add the requester's token
				message.addObject(crypto.encryptAES(tokTuple.hashedToken, aesKey));//Add the signed token hash
				output.reset();
				output.writeObject(message);

				response = (Envelope)input.readObject();

				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					output.reset();
					return true;
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

	 public boolean deleteUser(String username, TokenTuple tokTuple)
	 {
		 try
			{
				Envelope message = null, response = null;

				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject(crypto.encryptAES(username, aesKey)); //Add user name
				message.addObject(crypto.encryptAES(tokTuple.tok.toString(), aesKey));  //Add requester's token
				message.addObject(crypto.encryptAES(tokTuple.hashedToken, aesKey));//Add the signed token hash
				output.reset();
				output.writeObject(message);

				response = (Envelope)input.readObject();

				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					output.reset();
					return true;
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

	 public boolean createGroup(String groupname, TokenTuple tokTuple)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject(crypto.encryptAES(groupname, aesKey)); //Add the group name string
				message.addObject(crypto.encryptAES(tokTuple.tok.toString(), aesKey)); //Add the requester's token
				message.addObject(crypto.encryptAES(tokTuple.hashedToken, aesKey));//Add the signed token hash
				output.reset();
				output.writeObject(message);

				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK")){
					output.reset();
					return true;
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

	 public boolean deleteGroup(String groupname, TokenTuple tokTuple)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				message.addObject(crypto.encryptAES(groupname, aesKey)); //Add the group name string
				message.addObject(crypto.encryptAES(tokTuple.tok.toString(), aesKey)); //Add the requester's token
				message.addObject(crypto.encryptAES(tokTuple.hashedToken, aesKey));//Add the signed token hash
				output.reset();
				output.writeObject(message);

				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					output.reset();
					return true;
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
	public List<String> listMembers(String group, TokenTuple tokTuple)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 byte [] grp = crypto.encryptAES(group, aesKey);
			 byte [] tok = crypto.encryptAES(tokTuple.tok.toString(), aesKey);
			 message.addObject(grp); //Add group name string
			 message.addObject(tok); //Add requester's token
			 message.addObject(crypto.encryptAES(tokTuple.hashedToken, aesKey));//Add the signed token hash
			 output.reset();
			 output.writeObject(message);

			 response = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 {
				 output.reset();
				return crypto.extractList(response, 0, aesKey);
				//return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
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

	 public boolean addUserToGroup(String username, String groupname, TokenTuple tokTuple)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject(crypto.encryptAES(username, aesKey)); //Add user name string
				message.addObject(crypto.encryptAES(groupname, aesKey)); //Add the group name string
				message.addObject(crypto.encryptAES(tokTuple.tok.toString(), aesKey)); //Add the requester's token
				message.addObject(crypto.encryptAES(tokTuple.hashedToken, aesKey));//Add the signed token hash
				output.reset();
				output.writeObject(message);

				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					output.reset();
					return true;
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

	 public boolean deleteUserFromGroup(String username, String groupname, TokenTuple tokTuple)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
				message.addObject(crypto.encryptAES(username, aesKey)); //Add user name string
				message.addObject(crypto.encryptAES(groupname, aesKey)); //Add the group name string
				message.addObject(crypto.encryptAES(tokTuple.tok.toString(), aesKey)); //Add the requester's token
				message.addObject(crypto.encryptAES(tokTuple.hashedToken, aesKey));//Add the signed token hash
				output.reset();
				output.writeObject(message);

				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					output.reset();
					return true;
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
