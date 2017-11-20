/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.security.*;


public class FileClient extends Client implements FileClientInterface {
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
			byte [] a = crypto.HMAC(this.integrityKey.toByteArray(), message);
			message = new Envelope("INTEGRITY");
			message.addObject(a);
			output.reset();
			output.writeObject(message);
		    env = (Envelope)input.readObject();

			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}

		return true;
	}

	public boolean download(String sourceFile, String destFile, TokenTuple tokTuple) {

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
				byte [] a = crypto.HMAC(this.integrityKey.toByteArray(), message);
				message = new Envelope("INTEGRITY");
				message.addObject(a);
				output.reset();
				output.writeObject(message);
				env = (Envelope)input.readObject();

				while (env.getMessage().compareTo("CHUNK")==0) {
					try{
						String asdf = crypto.decryptAES((byte [])env.getObjContents().get(0), aesKey);

						byte [] tra = asdf.getBytes();

						String inasdf = crypto.decryptAES((byte [])env.getObjContents().get(1), aesKey);
						Integer temp = Integer.parseInt(inasdf);

						fos.write(tra, 0, temp);

						// System.out.printf(".");
						env = new Envelope("DOWNLOADF"); //Success
						output.reset();
						output.writeObject(env);
						env = (Envelope)input.readObject();
					}
					catch(Exception e){
						System.out.println(e);
						while(true){}
					}
				}
				fos.close();

				if(env.getMessage().compareTo("EOF")==0) {
						fos.close();
						System.out.printf("\nTransfer successful file %s\n", sourceFile);
						env = new Envelope("OK"); //Success
						output.reset();
						output.writeObject(env);
				}
				else {
						System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
						file.delete();
						return false;
				}
			}

			else {
				System.out.printf("Error couldn't create file %s\n", destFile);
				return false;
			}


		} catch (IOException e1) {

			System.out.printf("Error couldn't create file %s\n", destFile);
			return false;


		}
		catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}
			return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(TokenTuple tokTuple) {

		 try
		 {
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");
			 byte [] tok = crypto.encryptAES(tokTuple.tok.toString(), aesKey);
			 //TODO add hash
			 message.addObject(tok); //Add requester's token
			 message.addObject(crypto.encryptAES(tokTuple.hashedToken, aesKey));//Add the signed token hash
			 output.reset();
			 output.writeObject(message);

			 e = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 {
				String rec = crypto.decryptAES((byte [])e.getObjContents().get(0), aesKey);
				List<String> ret = crypto.extractList(e, 0, aesKey);
				return (List<String>)ret; //This cast creates compiler warnings. Sorry.
			 }

			 return null;

		 }
		 catch(Exception ex)
			{
				System.err.println("Error in listFiles: " + ex.getMessage());
				ex.printStackTrace(System.err);
				return null;
			}
	}


	public boolean upload(String sourceFile, String destFile, String group,
			TokenTuple tokTuple) {
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


			 @SuppressWarnings("resource")
			FileInputStream fis = new FileInputStream(sourceFile);

			 env = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 {
				System.out.printf("Meta data upload successful\n");

			}
			 else {

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

					message.addObject(buf);
					message.addObject(new Integer(n));
					output.reset();
					output.writeObject(message);


					env = (Envelope)input.readObject();


			 }
			 while (fis.available()>0);

			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 {

				message = new Envelope("EOF");
				output.reset();
				output.writeObject(message);

				env = (Envelope)input.readObject();
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


}
