/* FileClient provides all the client functionality regarding the file server */

import java.io.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;


public class FileClient extends Client implements FileClientInterface {
	private byte [] byteFKey;
	private SecretKeySpec key;
	//Diffie Hellman key
	private Key aesKey;
	private CryptoHelper crypto = new CryptoHelper();

	public boolean connect(final String server, final int port){
		boolean ret = super.connect(server, port);
		aesKey = new SecretKeySpec(this.confidentialityKey.toByteArray(), "AES");
		// ret is false, no connection made so we don't want to check with the user
		if(!ret){
			return false;
		}
		//returns the users choice to connect
		return checkConn();
	}

	private boolean checkConn(){
		KeyRing savedKeys = new KeyRing("SavedKeys");
		if(savedKeys.exists()){
			savedKeys = crypto.loadRing(savedKeys);
		}else{
			savedKeys.init();
		}
		//get key from file server
		byte[] keyBytes  = getPubKey();
		//turn byte[] key into Key object
		X509EncodedKeySpec ks = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = null;
		try {
			 kf = KeyFactory.getInstance("RSA", "BC");
		} catch (Exception e) {
			e.printStackTrace();
		}
		Key remotePubKey = null;
		try {
			remotePubKey = (Key)kf.generatePublic(ks);
		} catch (Exception e) {
			e.printStackTrace();					
		}
		Scanner reader = new Scanner(System.in);
		//check if we have a key for this server
		Key savedPubKey = savedKeys.getKey("rsa_pub_gs");
		if(savedPubKey == null){
			System.out.println("You are connecting to a new file server. Its public key is:\n\n"
			 + Base64.encodeBase64String(keyBytes) + "\n\nWould you like to connect to this server? (Y/n)");
			String input = reader.nextLine().toLowerCase();
			while(!input.equals("y") && !input.equals("n")){
				System.out.println("Please enter 'Y' or 'N':");
				input = reader.nextLine().toLowerCase();
			}
			if(input.equals("y")){
				savedKeys.addKey("rsa_pub_gs", remotePubKey);
				crypto.saveRing(savedKeys);
				return true;
			}else{
				return false;
			}
		}else{ //we have connected to this server already
			if(savedPubKey.equals(remotePubKey)){
				System.out.println("File Server recognized. Connecting now!");
				return true;
			}else{
				System.out.println("\n WARNING!! Saved key and remote key didn't match! WARNING!! \n");
				return false;
			}
			
		}
	}

	public byte[] getPubKey(){
		Envelope env = new Envelope("PUBKEY");
		try{
			//don't touch this....I know it's not right, but it breaks when you add getHash
			output.writeObject(env);
			env = (Envelope)input.readObject();
			if(env.getMessage().equals("OK")){
				if(!crypto.verify(integrityKey, env, input)){
					System.out.println("Message was modified, aborting");
					return null;
				}
				return crypto.decryptAESBytes((byte[])env.getObjContents().get(0), aesKey);
			}
			return null;
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
	}

	public boolean delete(String filename, TokenTuple tokTuple) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
		byte [] path = crypto.encryptAES(remotePath, aesKey);
		byte [] tok = crypto.encryptAES(tokTuple.tok.toString(), aesKey);
	    env.addObject(path);
	    env.addObject(tok);
		env.addObject(crypto.encryptAES(tokTuple.hashedToken, aesKey));//Add the signed token hash
	    try {
			output.reset();
			output.writeObject(env);
			crypto.getHash(integrityKey, env, output);
			env = (Envelope)input.readObject();
			if(!crypto.verify(integrityKey, env, input)){
				System.out.println("Message was modified, aborting");
				return false;
			}
			else{

				if (env.getMessage().compareTo("OK")==0) {
					System.out.printf("File %s deleted successfully\n", filename);
				}
				else {
					System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
					return false;
				}
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}

		return true;
	}

	public boolean download(String sourceFile, String destFile, TokenTuple tokTuple, Key groupKey) {
		byte[] encodedKey = Base64.encodeBase64(groupKey.getEncoded());
		System.out.println(new String(encodedKey));
		if (sourceFile.charAt(0)=='/') {
			sourceFile = sourceFile.substring(1);
		}

		File file = new File(destFile);
		try {
			if (!file.exists()) {
				file.createNewFile();
				FileOutputStream fos = new FileOutputStream(file);

				Envelope env = new Envelope("DOWNLOADF"); //Success
				byte [] srcF = crypto.encryptAES(sourceFile, aesKey);
				byte [] tok = crypto.encryptAES(tokTuple.tok.toString(), aesKey);
				env.addObject(srcF);
				env.addObject(tok);
				env.addObject(crypto.encryptAES(tokTuple.hashedToken, aesKey));//Add the signed token hash
				output.reset();
				output.writeObject(env);
				crypto.getHash(integrityKey, env, output);
				env = (Envelope)input.readObject();
				if(!crypto.verify(integrityKey, env, input)){
					System.out.println("Message was modified, aborting");
					return false;
				}
				while(env.getMessage().compareTo("CHUNK")==0) {
					try{
						//TODO this is where the decryption happens
						// byte[] decodeBase64 = Base64.decodeBase64((byte [])env.getObjContents().get(0));
						byte[] val = (byte [])env.getObjContents().get(0);
						byte[] buffer = crypto.decryptAESBytes(val, groupKey);
						byte[] byteN = crypto.decryptAESBytes((byte [])env.getObjContents().get(1), aesKey);
						int n = Integer.parseInt(new String(byteN));

						// System.out.println("encbuf: " + new String(decodeBase64));
						System.out.println("N: " + n);
						System.out.println("buf: " + new String(buffer));

						// byte[] decrypted = crypto.decryptAESBytes(buffer, groupKey);

						fos.write(buffer, 0, n);

						// System.out.printf(".");
						env = new Envelope("DOWNLOADF"); //Success
						output.reset();
						output.writeObject(env);
						crypto.getHash(integrityKey, env, output);
						env = (Envelope)input.readObject();
						if(!crypto.verify(integrityKey, env, input)){
							System.out.println("Message was modified, aborting");
							return false;
						}
					}catch(Exception e){
						e.printStackTrace();
					}
				}
				fos.close();
				if(env.getMessage().compareTo("EOF")==0) {
					fos.close();
					System.out.printf("\nTransfer successful file %s\n", sourceFile);
					env = new Envelope("OK"); //Success
					output.reset();
					output.writeObject(env);
					crypto.getHash(integrityKey, env, output);
					if(!crypto.verify(integrityKey, env, input)){
						System.out.println("Message was modified, aborting");
						return false;
					}
				}else{
					System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
					file.delete();
					return false;
				}
			}else{
				System.out.printf("Error file already exists %s\n", destFile);
				return false;
			}

		} catch (IOException e1) {
			System.out.printf("Error couldn't create file1 %s\n", destFile);
			return false;
		}
		catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}
		return true;
	}

	public boolean upload(String sourceFile, String destFile, String group, TokenTuple tokTuple, Key groupKey, int keyVer) {
		byte[] encodedKey = Base64.encodeBase64(groupKey.getEncoded());
		System.out.println(new String(encodedKey));
		if(key == null && this.isConnected()){
			byteFKey = confidentialityKey.toByteArray();
			key = new SecretKeySpec(byteFKey, "AES");
		}
		if (destFile.charAt(0)!='/') { //insert "/" at beginning of filename if it doesn't exist
		 destFile = "/" + destFile;
		}
		byte [] srcFile = crypto.encryptAES(sourceFile, aesKey);
		byte [] destinationFile = crypto.encryptAES(destFile, aesKey);
		byte [] grpName = crypto.encryptAES(group, aesKey);
		byte [] tok = crypto.encryptAES(tokTuple.tok.toString(), aesKey);
		try{
			Envelope message = null, env = null;

			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(destinationFile);
			 message.addObject(grpName);
			 message.addObject(tok);
			 message.addObject(crypto.encryptAES(tokTuple.hashedToken, aesKey));//Add the signed token hash
			 output.reset();
			 output.writeObject(message);
			 crypto.getHash(integrityKey, message, output);

			@SuppressWarnings("resource")
			FileInputStream fis = new FileInputStream(sourceFile);

			 env = (Envelope)input.readObject();
			 if(!crypto.verify(integrityKey, env, input)){
				System.out.println("Message was modified, aborting");
				return false;
			}

			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY")){
				System.out.printf("\nMeta data upload successful");
			}else{
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						// System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}
					//TODO this is where the encryption happens
					byte[] ciphertext = crypto.encryptAES(buf, groupKey);
					// byte[] ciphertextBase64 = Base64.encodeBase64(ciphertext);

					message.addObject(ciphertext);
					message.addObject(new Integer(n));
					output.reset();
					output.writeObject(message);
					crypto.getHash(integrityKey, message, output);
					env = (Envelope)input.readObject();
					if(!crypto.verify(integrityKey, env, input)){
						System.out.println("Message was modified, aborting");
						return false;
					}
			 }while (fis.available()>0);

			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0){
				message = new Envelope("EOF");
				message.addObject(new Integer(keyVer));
				output.reset();
				output.writeObject(message);
				crypto.getHash(integrityKey, message, output);
				env = (Envelope)input.readObject();
				if(!crypto.verify(integrityKey, env, input)){
					System.out.println("Message was modified, aborting");
					return false;
				}

				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {
					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }
			}
			 else {
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(TokenTuple tokTuple) {
		 try{
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");
			 message.addObject(crypto.encryptAES(tokTuple.tok.toString(), aesKey)); //Add requester's token
			 message.addObject(crypto.encryptAES(tokTuple.hashedToken, aesKey));//Add the signed token hash
			 output.reset();
			 output.writeObject(message);
			 crypto.getHash(integrityKey, message, output);
			 e = (Envelope)input.readObject();
			 if(!crypto.verify(integrityKey, e, input)){
				System.out.println("Message was modified, aborting");
			}
			else{
				//If server indicates success, return the member list
				if(e.getMessage().equals("OK")){
					String rec = crypto.decryptAES((byte [])e.getObjContents().get(0), aesKey);
					List<String> ret = crypto.extractList(e, 0, aesKey);
					return ret; //This cast creates compiler warnings. Sorry.
				 }
			}
			return null;
		 }catch(Exception ex){
			System.err.println("Error in listFiles: " + ex.getMessage());
			ex.printStackTrace(System.err);
			return null;
		}
	}

	public String getGroup(String fileName){
		try{
			Envelope message = null, resp = null;

			//Tell the server to return the member list
			message = new Envelope("GETGROUPFROMFILE");
			message.addObject(fileName);
			output.reset();
			output.writeObject(message);
			resp = (Envelope)input.readObject();
			//sometimes we need to consume an extra message or 2
			//super SUPER hacky, sorry
			while(!resp.getMessage().equals("OK-GROUP") && !resp.getMessage().equals("FAIL")){
				System.out.println("Loop group: " + resp.getMessage());
				resp = (Envelope)input.readObject();
			}
			if(resp.getMessage().equals("OK-GROUP")){
				return (String)resp.getObjContents().get(0);
			}else{
				return "";
			}
		}catch(Exception e){
			e.printStackTrace();
		}
		return "";
	}

	public int getKeyVer(String name){
		try{
			Envelope message = null, resp = null;
			//Tell the server to return the member list
			message = new Envelope("GETKEYVERFROMFILE");
			message.addObject(name);
			output.reset();
			output.writeObject(message);
			resp = (Envelope)input.readObject();

			//sometimes we need to consume an extra message or 2
			//super SUPER hacky, sorry
			while(!resp.getMessage().equals("OK-FILE") && !resp.getMessage().equals("FAIL")){
				System.out.println("Loop file: " + resp.getMessage());
				resp = (Envelope)input.readObject();
			}
			if(resp.getMessage().equals("OK-FILE")){
				Integer val = (Integer)resp.getObjContents().get(0);
				return val.intValue();
			}else{
				System.out.println(resp.getMessage());
				return -1;
			}
		}catch(Exception e){
			e.printStackTrace();
		}
		return -1;
	}
}
