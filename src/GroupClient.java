/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;

public class GroupClient extends Client implements GroupClientInterface {
	private byte [] byteFKey;
	private SecretKeySpec key;
	private AESAndHash enc;

	public boolean connect(final String server, final int port){
		boolean ret = super.connect(server, port);
		enc = new AESAndHash(new SecretKeySpec(this.sKey.toByteArray(), "AES"));
		return ret;
	}

	public TokenTuple getToken(String username, String password)
	 {
		try
		{
			UserToken token = null;
			//TODO this object type probably needs to be change once encrypted with server key
			byte [] hashedToken = new byte [32];
			Envelope message = null, response = null;

			//Tell the server to return a token.
			message = new Envelope("GET");
			byte [] usrName = enc.encryptAES(username);
			byte [] pass = enc.encryptAES(password);
			message.addObject(usrName); //Add user name string
			message.addObject(pass); //Add password
			output.reset();
			output.writeObject(message);

			//Get the response from the server
			response = (Envelope)input.readObject();

			//Successful response
			if(response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it

				ArrayList<Object> temp = null;
				temp = response.getObjContents();

				if(temp.size() == 2)
				{
					token = enc.extractToken(response, 0);
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
				message.addObject(enc.encryptAES(username)); //Add user name string
				message.addObject(enc.encryptAES(password)); //Add password string
				message.addObject(enc.encryptAES(tokTuple.tok.toString())); //Add the requester's token
				message.addObject(enc.encryptAESBytes(tokTuple.hashedToken));//Add the signed token hash
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
				message.addObject(enc.encryptAES(username)); //Add user name
				message.addObject(enc.encryptAES(tokTuple.tok.toString()));  //Add requester's token
				message.addObject(enc.encryptAESBytes(tokTuple.hashedToken));//Add the signed token hash
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
				message.addObject(enc.encryptAES(groupname)); //Add the group name string
				message.addObject(enc.encryptAES(tokTuple.tok.toString())); //Add the requester's token
				message.addObject(enc.encryptAESBytes(tokTuple.hashedToken));//Add the signed token hash
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

	 public boolean deleteGroup(String groupname, TokenTuple tokTuple)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				message.addObject(enc.encryptAES(groupname)); //Add the group name string
				message.addObject(enc.encryptAES(tokTuple.tok.toString())); //Add the requester's token
				message.addObject(enc.encryptAESBytes(tokTuple.hashedToken));//Add the signed token hash
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
			 byte [] grp = enc.encryptAES(group);
			 byte [] tok = enc.encryptAES(tokTuple.tok.toString());
			 message.addObject(grp); //Add group name string
			 message.addObject(tok); //Add requester's token
			 message.addObject(enc.encryptAESBytes(tokTuple.hashedToken));//Add the signed token hash
			 output.reset();
			 output.writeObject(message);

			 response = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 {
				 output.reset();
				return enc.extractList(response, 0);
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
				message.addObject(enc.encryptAES(username)); //Add user name string
				message.addObject(enc.encryptAES(groupname)); //Add the group name string
				message.addObject(enc.encryptAES(tokTuple.tok.toString())); //Add the requester's token
				message.addObject(enc.encryptAESBytes(tokTuple.hashedToken));//Add the signed token hash
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
				message.addObject(enc.encryptAES(username)); //Add user name string
				message.addObject(enc.encryptAES(groupname)); //Add the group name string
				message.addObject(enc.encryptAES(tokTuple.tok.toString())); //Add the requester's token
				message.addObject(enc.encryptAESBytes(tokTuple.hashedToken));//Add the signed token hash
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
