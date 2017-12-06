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
import java.security.spec.X509EncodedKeySpec;
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
import org.apache.commons.codec.binary.Base64;



public class FileThread extends Thread
{
	private FileServer my_fs;
	private final Socket socket;
	final ObjectInputStream input;
	final ObjectOutputStream output;
	private BigInteger confidentialityKey;
	private BigInteger integrityKey;
	private CryptoHelper crypto;
	private ArrayList<Envelope> msgs;
	private int msgSent;
	private int msgReceived;

	public FileThread(Socket _socket, FileServer my_fs) throws IOException, ClassNotFoundException
	{
		this.my_fs = my_fs;
		System.out.println("Setting up connection...");
		crypto = new CryptoHelper();
		socket = _socket;
		msgs = new ArrayList<Envelope>();
		msgSent = 0;
		msgReceived = 0;
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
			serverPub = crypto.addMessageNumber(serverPub, msgSent);
			output.reset();
			output.writeObject(serverPub);
			msgSent++;
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
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			Envelope response;
			Key aesKey = null;
			boolean dhDone = false;
			Envelope message;
			do{
				try{
					if(msgs.get(msgReceived) != null){
						message = msgs.get(msgReceived);
					}else{
						message = (Envelope)input.readObject();
					}
				}catch(IndexOutOfBoundsException e){
					message = (Envelope)input.readObject();
				}
				System.out.println("Request received: " + message.getMessage());
				if(message.getObjContents().get(0).getClass() == byte[].class){
					System.out.println(new String((byte[])message.getObjContents().get(0)));
				}
				if((int)message.getObjContents().get(0) != msgReceived){
					for(int i = 0; i < msgReceived; i ++){
						try{
							if(msgs.get(i) == null)
								msgs.add(i, null);
						}
						catch(Exception e){
							msgs.add(i, null);
						}
					}
					msgs.add((int)message.getObjContents().get(0), message);
					while((int)message.getObjContents().get(0) != msgReceived){
						message = (Envelope)input.readObject();
					}
				}else{
					Envelope noNum = message;
					message = crypto.removeMessageNumber(message);
					msgReceived++;
					//DO NOT DO ANYTHING UNTIL DH IS DONE
					if(!dhDone){
						if(message.getMessage().equals("DHMSGS")){
							if(setupDH(message)){
								dhDone = true;
								aesKey = new SecretKeySpec(confidentialityKey.toByteArray(),"AES");
							}
						}
					}
					//RETURN THIS SERVERS PUBLIC RSA KEY
					//Message Structure: {}
					else if(message.getMessage().equals("PUBKEY")){
						System.out.println("GOT TO PUB KEY");
						Key pubKey = my_fs.keyRing.getKey("rsa_pub");
						System.out.println(Base64.encodeBase64String(pubKey.getEncoded()));
						if(pubKey != null){
							response = new Envelope("OK");
							byte[] pubKeyByte = crypto.encryptAES(pubKey.getEncoded(), aesKey);
							response.addObject(pubKeyByte);
						}
						else{
							response = new Envelope("FAIL-PUBKEY_FETCH_ERROR");
						}
						response = crypto.addMessageNumber(response, msgSent);
						output.reset();
						output.writeObject(response);
						msgSent++;
						crypto.getHash(integrityKey, response, output);
					}
					//RETURN GROUP THAT A FILE BELONGS TO
					else if(message.getMessage().equals("GETGROUPFROMFILE")){
						if(crypto.verify(integrityKey, message, input)){
							response = new Envelope("FAIL");
						}else{
							String name = (String)message.getObjContents().get(0);
							String groupName = my_fs.fileList.findGroup(name);
							if(groupName != null){
								response = new Envelope("OK-GROUP");
								response.addObject(groupName);
							}else{
								// System.out.println("GETGROUP FAILED...........");
								response = new Envelope("FAIL");
							}
						}
						response = crypto.addMessageNumber(response, msgSent);
						msgSent++;
						output.reset();
						output.writeObject(response);
						// crypto.getHash(integrityKey, response, output);
					}
					//RETURN KEY VERSION THAT A FILE BELONGS TO
					else if(message.getMessage().equals("GETKEYVERFROMFILE")){
						if(crypto.verify(integrityKey, message, input)){
							response = new Envelope("FAIL");
						}else{
							String name = (String)message.getObjContents().get(0);
							int version = my_fs.fileList.findKeyVersion(name);
							if(version > -1){
								response = new Envelope("OK-FILE");
								response.addObject(new Integer(version));
							}else{
								// System.out.println("GETVERSION FAILED...........");
								response = new Envelope("FAIL");
							}
						}
						response = crypto.addMessageNumber(response, msgSent);
						msgSent++;
						output.reset();
						output.writeObject(response);
						// crypto.getHash(integrityKey, response, output);
					}
					//LIST ALL THE FILES THE REQUESTING USER IS ALLOWED TO SEE
					//Message Structure: {stringifiedToken, tokenSignature}
					else if(message.getMessage().equals("LFILES")){
						if(crypto.verify(integrityKey,message, input)){
							response = new Envelope("FAIL");
						}
						else{
							TokenTuple tokenTuple  = new TokenTuple(crypto.extractToken(message, 0, aesKey), crypto.decryptAESBytes((byte[])message.getObjContents().get(1), aesKey));
							List<String> list = listFiles(tokenTuple, aesKey);
							if(!crypto.checkTarget(tokenTuple.tok.getTarget(), my_fs.keyRing.getKey("rsa_pub"))){
								response = new Envelope("FAIL-INCORRECTTARGET");
							}else{
								response = new Envelope("OK");
								byte [] ls = crypto.encryptAES(list.toString(), aesKey);
								response.addObject(ls);
							}
						}
						response = crypto.addMessageNumber(response, msgSent);
						msgSent++;
						output.reset();
						output.writeObject(response);
						crypto.getHash(integrityKey, response, output);
					}
					//UPLOAD A FILE
					//Message Structure: {destinationFile, groupName, stringifiedToken, tokenSignature}
					else if(message.getMessage().equals("UPLOADF")){
						//decrypt transmission here
						if(message.getObjContents().size() < 4){
							response = new Envelope("FAIL-BADCONTENTS");
						}
						else if(!crypto.verify(integrityKey, noNum, input)){
							response = new Envelope("FAIL-MESSAGEMODIFIED");
						}
						else{
							//String path = crypto.decryptAES(((byte [])message.getObjContents().get(0)), aesKey);
							String path = new String((byte [])message.getObjContents().get(0));
							String grp = crypto.decryptAES(((byte [])message.getObjContents().get(1)), aesKey);
							TokenTuple tokenTuple  = new TokenTuple(crypto.extractToken(message, 2, aesKey), crypto.decryptAESBytes((byte[])message.getObjContents().get(3), aesKey));
							String name = new String((byte [])message.getObjContents().get(4));
							if(path == null) {
								response = new Envelope("FAIL-BADPATH");
							}else if(grp == null) {
								response = new Envelope("FAIL-BADGROUP");
							}else if(tokenTuple.tok == null) {
								response = new Envelope("FAIL-BADTOKEN");
							}else if(!crypto.checkTarget(tokenTuple.tok.getTarget(), my_fs.keyRing.getKey("rsa_pub"))){
								response = new Envelope("FAIL-INCORRECTTARGET");
							}else {
								response = uploadFile(path, grp, tokenTuple.tok, name, message, aesKey); //get rid of / in name
							}
							response = crypto.addMessageNumber(response, msgSent);
							output.reset();
							output.writeObject(response);
							msgSent++;
							crypto.getHash(integrityKey, response, output);
						}
					}
					//DOWNLOAD A FILE
					//Message Structure: {sourceFile, stringifiedToken, tokenSignature}
					else if (message.getMessage().compareTo("DOWNLOADF")==0) {
						String remotePath = new String((byte[])message.getObjContents().get(0));
						TokenTuple tokenTuple  = new TokenTuple(crypto.extractToken(message, 1, aesKey), crypto.decryptAESBytes((byte[])message.getObjContents().get(2), aesKey));
						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
						if(sf == null){ //file not found
							response = new Envelope("FAIL");
						}
						else if(!crypto.checkTarget(tokenTuple.tok.getTarget(), my_fs.keyRing.getKey("rsa_pub"))){
							response = new Envelope("FAIL-INCORRECTTARGET");
						}
						else if (sf == null) {
							response = new Envelope("ERROR_FILEMISSING");
						}
						else if(!crypto.verify(integrityKey, noNum, input)){
							response = new Envelope("FAIL");
						}
						else if (!tokenTuple.tok.getGroups().contains(sf.getGroup())){
							response = new Envelope("ERROR_PERMISSION");
						}else{
							int version = sf.getKeyVersion();
							String group = sf.getGroup();
							response = downloadFile(message, remotePath, aesKey, version, group);
						}
						message = crypto.addMessageNumber(message, msgSent);
						output.reset();
						output.writeObject(message);
						msgSent++;
						crypto.getHash(integrityKey, message, output);
					}
					//DELETE A FILE
					//Message Structure: {fileToDelete, stringifiedToken, tokenSignature}
					else if (message.getMessage().compareTo("DELETEF")==0) {
						if(!crypto.verify(integrityKey, noNum, input)){
							response = new Envelope("FAIL");
						}else{
						String remotePath = crypto.decryptAES((byte [])message.getObjContents().get(0), aesKey);
						TokenTuple requestTokTup  = new TokenTuple(crypto.extractToken(message, 1, aesKey), crypto.decryptAESBytes((byte[])message.getObjContents().get(2), aesKey));

						if(!requestTokTup.tok.getTarget().equals(Base64.encodeBase64String(my_fs.keyRing.getKey("rsa_pub").getEncoded()))){
							response = new Envelope("FAIL-INCORRECTTARGET");
						}
						else{
							//TODO check token
							message = deleteFile(remotePath, requestTokTup.tok);
						}
					}
						message = crypto.addMessageNumber(message, msgSent);
						output.reset();
						output.writeObject(message);
						msgSent++;
						crypto.getHash(integrityKey, message, output);
					}

					//DISCONNECT
					//Message Structure: {}
					else if(message.getMessage().equals("DISCONNECT")){
						crypto.saveRing(my_fs.keyRing);
						socket.close();
						proceed = false;
					}

					//UNRECOGNIZED REQUEST
					else{
						response = new Envelope("FAIL-UNRECOGNIZED"); //Server does not understand client request
						output.reset();
						output.writeObject(response);
						crypto.getHash(integrityKey, response, output);
					}
				}
			} while(proceed);
		}catch(java.io.EOFException eof){
			//do nothing
		}catch(java.net.SocketException s){
			//do nothing
		}catch(Exception e){
			e.printStackTrace();
		}
	}

	private List<String> listFiles(TokenTuple tokenTuple, Key aesKey){
		List<String> list = new ArrayList<String>();
		UserToken token = tokenTuple.tok;
		List<String> groups = token.getGroups(); //list of current groups user is a member of
		FileList tmp = FileServer.fileList; //list of files on the server
		for(ShareFile f : tmp.getFiles()) {
			String group = f.getGroup();
			if(groups.contains(group)){ //compare this file's group to our user group list
				list.add(f.getName());
			}
		}
		return list;
	}

	private Envelope uploadFile(String path, String grp, UserToken token, String name, Envelope message, Key aesKey){
		Envelope response = new Envelope("FAIL");
		String remotePath = path;
		String group = grp;
		UserToken yourToken = token; //Extract token
		try{
			if (FileServer.fileList.checkFile(remotePath)) {
				System.out.printf("Error: file already exists at %s\n", remotePath);
				response = new Envelope("FAIL-FILEEXISTS"); //Success
			}
			else if (!yourToken.getGroups().contains(group)) {
				System.out.printf("Error: user missing valid token for group %s\n", group);
				// System.out.print(yourToken.getGroups());
				response = new Envelope("FAIL-UNAUTHORIZED");
			}
			else  {
				File file = new File("shared_files/"+remotePath.replace('/', '_'));
				file.createNewFile();
				FileOutputStream fos = new FileOutputStream(file);
				System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

				response = new Envelope("READY"); //Success
				response = crypto.addMessageNumber(response, msgSent);
				output.reset();
				output.writeObject(response);
				msgSent++;
				crypto.getHash(integrityKey, response, output);

				message = (Envelope)input.readObject();
				if(!crypto.verify(integrityKey, message, input)){
					response = new Envelope("FAIL-modified");
					/*response.addObject(null);*/
					//output.reset();

				}
				else if((int)message.getObjContents().get(0) != msgReceived){
					System.out.println("FAIL-Messages out of order");
					response = new Envelope("FAIL-OUT OF ORDER");
					//break;
				}

				else{
					msgReceived++;
					message = crypto.removeMessageNumber(message);
					while (message.getMessage().compareTo("CHUNK")==0) {
						System.out.println("SENDING CHUNK");
						fos.write((byte[])message.getObjContents().get(0), 0, (Integer)message.getObjContents().get(1));
						response = new Envelope("READY"); //Success
						response = crypto.addMessageNumber(response, msgSent);
						output.reset();
						output.writeObject(response);
						msgSent++;
						crypto.getHash(integrityKey, response, output);

						message = (Envelope)input.readObject();
						if(!crypto.verify(integrityKey, message, input)){
							response = new Envelope("FAIL-modified");
							break;
						}
						else if((int)message.getObjContents().get(0) != msgReceived){
							response = new Envelope("Messages out of order");
							break;
						}
						message = crypto.removeMessageNumber(message);
						msgReceived++;
					}

					if(message.getMessage().compareTo("EOF")==0) {
						System.out.printf("Transfer successful file %s\n", remotePath);
						response = new Envelope("OK"); //Success
						output.reset();
						//TODO ADD MESSAGE NUMBER
						response = crypto.addMessageNumber(response, msgSent);
						output.reset();
						output.writeObject(response);
						msgSent++;
						crypto.getHash(integrityKey, response, output);
						int ver = ((Integer)message.getObjContents().get(0)).intValue();
						FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath, ver, name);
						System.out.println("Adding file named: " + name);
					}
					else {
						System.out.printf("Error reading file %s from client\n", remotePath);
						response = new Envelope("ERROR-TRANSFER"); //Success
					}
				}
				fos.close();
			}
		}catch(Exception ex){
			System.out.println("Error uploading file: " + message);
		}
		return response;
	}

	private Envelope deleteFile(String remotePath, UserToken t){
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

	//TODO probably should clean this up
	private Envelope downloadFile(Envelope message, String remotePath, Key aesKey, int version, String groupName){
		Envelope response = new Envelope("OK");
		try{
			File f = new File("shared_files/_"+remotePath.replace('/', '_'));
			if (!f.exists()) {
				System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
				response = new Envelope("ERROR_NOTONDISK");
				return response;
			}else{
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
					if(n > 0) {
						// System.out.printf(".");
					} else if(n < 0) {
						System.out.println("Read error");
					}
					byte [] bufferEnc = crypto.encryptAES(buf, aesKey);
					byte [] byteN = crypto.encryptAES((new Integer(n)).toString(), aesKey);
					message.addObject(bufferEnc);
					message.addObject(byteN);
					message = crypto.addMessageNumber(message, msgSent);
					output.reset();
					output.writeObject(message);
					msgSent++;
					crypto.getHash(integrityKey, message, output);
					message = (Envelope)input.readObject();
					if(!crypto.verify(integrityKey, message, input)){
						response = new Envelope("FAIL-MESSAGEMODIFIED");
						break;
					}
					else if((int)message.getObjContents().get(0) != msgReceived){
						System.out.println("FAIL-Messages out of order");
						break;
					}
					msgReceived++;
					message = crypto.removeMessageNumber(message);
				}while (fis.available()>0);

				//If server indicates success, return the member list
				if(message.getMessage().compareTo("DOWNLOADF")==0){
					message = new Envelope("EOF");
					message = crypto.addMessageNumber(message, msgSent);
					output.reset();
					output.writeObject(message);
					msgSent++;
					crypto.getHash(integrityKey, message, output);

					message = (Envelope)input.readObject();
					if(!crypto.verify(integrityKey, message, input)){
						response = new Envelope("FAIL-MESSAGEMODIFIED");
						System.out.println("Upload Failed - Message Modified");
					}
					else if((int)message.getObjContents().get(0) != msgReceived){
						response = new Envelope("FAIL-Messages out of order");
						System.out.println("Upload Failed - messages out of order");
					}
					else{
						msgReceived++;
						message = crypto.removeMessageNumber(message);
						if(message.getMessage().compareTo("OK")==0) {
							System.out.printf("File data upload successful\n");
						}else{
							System.out.printf("Upload failed: %s\n", message.getMessage());
						}
					}
				}else{
					System.out.printf("Upload failed: %s\n", message.getMessage());
				}
			}
		}catch(Exception e1){
			System.err.println("Error: " + e1);
			e1.printStackTrace();
			response = new Envelope("ERROR" + e1.getMessage());
		}
		return response;
	}
}
