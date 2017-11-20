/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.*;
import java.io.*;
import java.security.*;
import java.math.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
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



public class FileThread extends Thread
{
	private FileServer my_fs;
	private final Socket socket;
	final ObjectInputStream input;
	final ObjectOutputStream output;
	BigInteger confidentialityKey;
	BigInteger integrityKey;
	CryptoHelper crypto;

	public FileThread(Socket _socket, FileServer my_fs) throws IOException, ClassNotFoundException
	{
		this.my_fs = my_fs;
		System.out.println("Setting up connection...");
		crypto = new CryptoHelper();
		socket = _socket;
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
			System.out.println(confidentialityKey);
			System.out.println(integrityKey);
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
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			Envelope response;
			Key aesKey = null;
			boolean dhDone = false;
			do{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				//Busy wait until DH is done
				while(!dhDone){
					System.out.println("dh loop"); //TODO remove
					if(message.getMessage().equals("DHMSGS")){
						if(setupDH(message)){
							dhDone = true;
							aesKey = new SecretKeySpec(confidentialityKey.toByteArray(),"AES");
						}
						else
							System.out.println("FAIL");
					}
				}

				// Handler to list files that this user is allowed to see
				if(message.getMessage().equals("LFILES")){
					ArrayList<String> list = listFiles(message, aesKey);
					response = new Envelope("OK");
					byte [] ls = crypto.encryptAES(list.toString(), aesKey);
					response.addObject(ls);
					output.reset();
					output.writeObject(response);
				}
				/*if(message.getMessage().equals("DHMSGS")){
					setupDH(message);
				}*/
				if(message.getMessage().equals("UPLOADF")){
					//decrypt transmission here
					if(message.getObjContents().size() < 4){
						response = new Envelope("FAIL-BADCONTENTS");
					}else{
						String path = crypto.decryptAES(((byte [])message.getObjContents().get(0)), aesKey);
						String grp = crypto.decryptAES(((byte [])message.getObjContents().get(1)), aesKey);
						String token = crypto.decryptAES(((byte [])message.getObjContents().get(2)), aesKey);

						if(path == null) {
							response = new Envelope("FAIL-BADPATH");
						}else if(grp == null) {
							response = new Envelope("FAIL-BADGROUP");
						}else if(token == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}else{
							response = uploadFile(path, grp, token, message, aesKey);
						}
					}
					output.reset();
					output.writeObject(response);
				}
				else if (message.getMessage().compareTo("DOWNLOADF")==0) {

					String remotePath = crypto.decryptAES((byte [])message.getObjContents().get(0), aesKey);
					Token t = (Token)crypto.extractToken(message, 1, aesKey);
					byte[] hashedToken = crypto.decryptAESBytes((byte [])message.getObjContents().get(2), aesKey); //Extract signed token hash
					//TODO check token
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						message = new Envelope("ERROR_FILEMISSING");
						output.reset();
						output.writeObject(message);

					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						message = new Envelope("ERROR_PERMISSION");
						output.reset();
						output.writeObject(message);
					}else{
						try{
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								message = new Envelope("ERROR_NOTONDISK");
								output.reset();
								output.writeObject(message);
							}else {
								@SuppressWarnings("resource")
								FileInputStream fis = new FileInputStream(f);

								do {
									byte[] buf = new byte[4096];
									if (message.getMessage().compareTo("DOWNLOADF")!=0) {
										System.out.printf("Server error: %s\n", message.getMessage());
										break;
									}
									message = new Envelope("CHUNK");
									int n = fis.read(buf); //can throw an IOException
									if (n > 0) {
										// System.out.printf(".");
									} else if (n < 0) {
										System.out.println("Read error");
									}
									String toEnc = new String(buf, "UTF-8");
									byte [] buffer = crypto.encryptAES(toEnc, aesKey);
									byte [] byteN = crypto.encryptAES((new Integer(n)).toString(), aesKey);
									message.addObject(buffer);
									message.addObject(byteN);
									//message.addObject(new Integer(n));
									output.reset();
									output.writeObject(message);
									message = (Envelope)input.readObject();
								}
								while (fis.available()>0);
								//If server indicates success, return the member list
								if(message.getMessage().compareTo("DOWNLOADF")==0){
									message = new Envelope("EOF");
									output.reset();
									output.writeObject(message);

									message = (Envelope)input.readObject();
									if(message.getMessage().compareTo("OK")==0) {
										System.out.printf("File data upload successful\n");
									}else{
										System.out.printf("Upload failed: %s\n", message.getMessage());
									}
								}else{
									System.out.printf("Upload failed: %s\n", message.getMessage());
								}
							}
						}
						catch(Exception e1){
							System.err.println("Error: " + message.getMessage());
							e1.printStackTrace(System.err);
						}
					}
				}
				else if (message.getMessage().compareTo("DELETEF")==0) {

					String remotePath = crypto.decryptAES((byte [])message.getObjContents().get(0), aesKey);
					Token t = (Token)crypto.extractToken(message, 1, aesKey);
					byte[] hashedToken = crypto.decryptAESBytes((byte [])message.getObjContents().get(2), aesKey); //Extract signed token hash
					//TODO check token
					message = deleteFile(remotePath, t);
					output.reset();
					output.writeObject(message);
				}
				else if(message.getMessage().equals("DISCONNECT"))
				{
					crypto.saveRing(my_fs.keyRing);
					socket.close();
					proceed = false;
				}else{
					response = new Envelope("FAIL"); //Server does not understand client request
					output.reset();
					output.writeObject(response);
				}
			} while(proceed);
		}catch(java.net.SocketException s){
			//do nothing
		}catch(Exception message){
			System.err.println("Error in file thread: " + message);
		}
	}

	private ArrayList<String> listFiles(Envelope message, Key aesKey){
		ArrayList<String> list = new ArrayList<String>();
		UserToken yourToken = crypto.extractToken(message, 0, aesKey);
		byte[] hashedToken = crypto.decryptAESBytes((byte [])message.getObjContents().get(1), aesKey); //Extract signed token hash
		//TODO check token
		List<String> groups = yourToken.getGroups(); //list of current groups user is a member of
		FileList tmp = FileServer.fileList; //list of files on the server
		for(ShareFile f :tmp.getFiles()) {
			String group = f.getGroup();
			if(groups.contains(group)) //compare this file's group to our user group list
				list.add(f.getPath());
		}
		return list;
	}

	private Envelope uploadFile(String path, String grp, String token, Envelope message, Key aesKey){
		Envelope response = new Envelope("FAIL");
		String remotePath = path;
		String group = grp;
		UserToken yourToken = crypto.extractToken(message, 2, aesKey); //Extract token
		byte[] hashedToken = crypto.decryptAESBytes((byte [])message.getObjContents().get(3), aesKey); //Extract signed token hash
		//TODO check token
		try{
			if (FileServer.fileList.checkFile(remotePath)) {
				System.out.printf("Error: file already exists at %s\n", remotePath);
				response = new Envelope("FAIL-FILEEXISTS"); //Success
			}
			else if (!yourToken.getGroups().contains(group)) {
				System.out.printf("Error: user missing valid token for group %s\n", group);
				System.out.print(yourToken.getGroups());
				response = new Envelope("FAIL-UNAUTHORIZED"); //Success
			}
			else  {
				File file = new File("shared_files/"+remotePath.replace('/', '_'));
				file.createNewFile();
				FileOutputStream fos = new FileOutputStream(file);
				System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

				response = new Envelope("READY"); //Success
				output.reset();
				output.writeObject(response);

				message = (Envelope)input.readObject();
				while (message.getMessage().compareTo("CHUNK")==0) {
					fos.write((byte[])message.getObjContents().get(0), 0, (Integer)message.getObjContents().get(1));
					response = new Envelope("READY"); //Success
					output.reset();
					output.writeObject(response);
					message = (Envelope)input.readObject();
				}

				if(message.getMessage().compareTo("EOF")==0) {
					System.out.printf("Transfer successful file %s\n", remotePath);
					FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
					response = new Envelope("OK"); //Success
				}
				else {
					System.out.printf("Error reading file %s from client\n", remotePath);
					response = new Envelope("ERROR-TRANSFER"); //Success
				}
				fos.close();
			}
		}catch(Exception ex){
			System.out.println("Error uploading file: " + message);
		}
		return response;
	}

	private Envelope deleteFile(String remotePath, Token t){
		Envelope response = new Envelope("FAIL");
		ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
		if (sf == null) {
			System.out.printf("Error: File %s doesn't exist\n", remotePath);
			response = new Envelope("ERROR_DOESNTEXIST");
		}
		else if (!t.getGroups().contains(sf.getGroup())){
			System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
			response = new Envelope("ERROR_PERMISSION");
		}else {
			try{
				File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));
				if (!f.exists()) {
					System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
					response = new Envelope("ERROR_FILEMISSING");
				}else if (f.delete()) {
					System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
					FileServer.fileList.removeFile("/"+remotePath);
					response = new Envelope("OK");
				}else{
					System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
					response = new Envelope("ERROR_DELETE");
				}
			}
			catch(Exception e1){
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				response = new Envelope(e1.getMessage());
			}
		}
		return response;
	}
}
