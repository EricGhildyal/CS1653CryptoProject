/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

//import com.sun.crypto.provider.DHKeyPairGenerator;

import java.security.*;
import java.util.Scanner;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.math.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.util.Random;
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




public class FileThread extends Thread
{
	private final Socket socket;
	final ObjectInputStream input;
	final ObjectOutputStream output;

	public FileThread(Socket _socket) throws IOException, ClassNotFoundException
	{
		socket = _socket;
		input = new ObjectInputStream(socket.getInputStream());
		output = new ObjectOutputStream(socket.getOutputStream());
		Envelope gMSG = (Envelope)input.readObject();
		
		Envelope pMSG = (Envelope)input.readObject();

		Envelope clientPubMSG = (Envelope)input.readObject();

		ArrayList<Object> nums = gMSG.getObjContents();
		BigInteger g = (BigInteger)nums.get(0);
		nums = pMSG.getObjContents();
		BigInteger p =(BigInteger)nums.get(0);
		nums = clientPubMSG.getObjContents();
		BigInteger clientPubKey = (BigInteger)nums.get(0);
		

		DHParameters params = new DHParameters(p, g);
		DHKeyGenerationParameters keyGenParams = new DHKeyGenerationParameters(new SecureRandom(), params);
		DHKeyPairGenerator keyGen = new DHKeyPairGenerator();
		keyGen.init(keyGenParams);
		AsymmetricCipherKeyPair serverKeys = keyGen.generateKeyPair();
		DHPublicKeyParameters publicKeyParam = (DHPublicKeyParameters)serverKeys.getPublic();
		DHPrivateKeyParameters privateKeyParam = (DHPrivateKeyParameters)serverKeys.getPrivate();
		BigInteger pubKey = publicKeyParam.getY();
		Envelope serverPub = new Envelope("key");
		serverPub.addObject(pubKey);
		output.writeObject(serverPub);
		output.flush();
		DHPublicKeyParameters clientPub = new DHPublicKeyParameters(clientPubKey, params);
		DHBasicAgreement keyAgree = new DHBasicAgreement();
		keyAgree.init(serverKeys.getPrivate());
		
		BigInteger key = keyAgree.calculateAgreement(clientPub);
		output.reset();
		

	}

	public void run()
	{
		boolean proceed = true;
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			
			Envelope response;



			
			

			//AlgorithmParameterGenerator params = Algoritm.ParameterGenerator.getInstance("DH");
			//params.init(256);
			
			do
			{
				Envelope e = (Envelope)input.readObject();
				System.out.println("Request received: " + e.getMessage());

				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES"))
				{
					List<String> list = new ArrayList<String>();

					UserToken yourToken = (UserToken)e.getObjContents().get(0);
					List<String> groups = yourToken.getGroups(); //list of current groups user is a member of
					FileList tmp = FileServer.fileList; //list of files on the server
					for(ShareFile f :tmp.getFiles()) {
						String group = f.getGroup();
						if(groups.contains(group)) //compare this file's group to our user group list
							list.add(f.getPath());
					}
					response = new Envelope("OK");
					response.addObject(list);
					output.reset();
					output.writeObject(response);
				}
				if(e.getMessage().equals("UPLOADF"))
				{

					if(e.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token

							if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
							}
							else if (!yourToken.getGroups().contains(group)) {
								System.out.printf("Error: user missing valid token for group %s\n", group);
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

								e = (Envelope)input.readObject();
								while (e.getMessage().compareTo("CHUNK")==0) {
									fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									output.reset();
									output.writeObject(response);
									e = (Envelope)input.readObject();
								}

								if(e.getMessage().compareTo("EOF")==0) {
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
						}
					}
					output.reset();
					output.writeObject(response);
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						output.reset();
						output.writeObject(e);

					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						output.reset();
						output.writeObject(e);
					}
					else {

						try
						{
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							e = new Envelope("ERROR_NOTONDISK");
							output.reset();
							output.writeObject(e);

						}
						else {
							@SuppressWarnings("resource")
							FileInputStream fis = new FileInputStream(f);

							do {
								byte[] buf = new byte[4096];
								if (e.getMessage().compareTo("DOWNLOADF")!=0) {
									System.out.printf("Server error: %s\n", e.getMessage());
									break;
								}
								e = new Envelope("CHUNK");
								int n = fis.read(buf); //can throw an IOException
								if (n > 0) {
									// System.out.printf(".");
								} else if (n < 0) {
									System.out.println("Read error");

								}


								e.addObject(buf);
								e.addObject(new Integer(n));

								output.reset();
								output.writeObject(e);

								e = (Envelope)input.readObject();


							}
							while (fis.available()>0);

							//If server indicates success, return the member list
							if(e.getMessage().compareTo("DOWNLOADF")==0)
							{

								e = new Envelope("EOF");
								output.reset();
								output.writeObject(e);

								e = (Envelope)input.readObject();
								if(e.getMessage().compareTo("OK")==0) {
									System.out.printf("File data upload successful\n");
								}
								else {

									System.out.printf("Upload failed: %s\n", e.getMessage());

								}

							}
							else {

								System.out.printf("Upload failed: %s\n", e.getMessage());

							}
						}
						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);

						}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_DOESNTEXIST");
					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
					}
					else {

						try
						{


							File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_FILEMISSING");
							}
							else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
								FileServer.fileList.removeFile("/"+remotePath);
								e = new Envelope("OK");
							}
							else {
								System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_DELETE");
							}


						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							e = new Envelope(e1.getMessage());
						}
					}
					output.reset();
					output.writeObject(e);

				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

}
