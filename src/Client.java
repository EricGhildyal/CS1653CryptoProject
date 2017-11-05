import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import org.bouncycastle.crypto.generators.*;
import org.bouncycastle.crypto.params.*;	
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import java.util.Random;
import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.crypto.agreement.DHAgreement;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;


//import javax.crypto.interfaces.DHPublicKey;
//import javax.crypto.spec.DHParameterSpec;

import java.io.NotSerializableException;

public abstract class Client {

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	public UserToken tok;
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;
	public BigInteger sKey;


	/**
	 * Connects to server from param server on port param port
	 *
	 * @param server server hostname/issuer of token
	 * @param port port that server is connected to
	 * @return Whether or not the connection was sucessful or not
	 */
	public boolean connect(final String server, final int port){
		try {	
			this.sock = new Socket(server, port);
			output = new ObjectOutputStream(this.sock.getOutputStream());  //Declare the output and input streams
			input = new ObjectInputStream(this.sock.getInputStream());
			//generate parameters
			Provider bcp = new BouncyCastleProvider();
			DHParametersGenerator paramGen = new DHParametersGenerator();
			SecureRandom secRand = new SecureRandom();
			paramGen.init(255, 90, secRand);
			DHParameters params = paramGen.generateParameters();
			BigInteger g = params.getG();
			BigInteger p = params.getP();
			
			//generate keys and send p, g, and public key to server
			DHKeyGenerationParameters keyGenParams = new DHKeyGenerationParameters(secRand, params);
			DHKeyPairGenerator keyGen = new DHKeyPairGenerator();
			keyGen.init(keyGenParams);
			AsymmetricCipherKeyPair clientKeys = keyGen.generateKeyPair();
			DHPublicKeyParameters publicKeyParam = (DHPublicKeyParameters)clientKeys.getPublic();
			DHPrivateKeyParameters privateKeyParam = (DHPrivateKeyParameters)clientKeys.getPrivate();
			BigInteger pubKey = publicKeyParam.getY();
			Envelope gMSG = new Envelope("g");
			gMSG.addObject(g);
			output.writeObject(gMSG);
			
			Envelope pMSG = new Envelope("p");
			pMSG.addObject(p);
			output.writeObject(pMSG);
			
			Envelope pubMSG = new Envelope("pubKey");
			pubMSG.addObject(pubKey);
			output.writeObject(pubMSG);
			
	
			

			//get server public key and agree on a session key
			Envelope servPubKey = (Envelope)input.readObject();
			ArrayList<Object> pub = servPubKey.getObjContents();
			BigInteger serverPub = (BigInteger)pub.get(0);
			
			DHPublicKeyParameters servPub = new DHPublicKeyParameters(serverPub, params);
			DHBasicAgreement keyAgree = new DHBasicAgreement();
			keyAgree.init(clientKeys.getPrivate());
			
			sKey = keyAgree.calculateAgreement(servPub);
			System.out.println(sKey.bitLength());
			output.reset();
			
						
		}catch(Exception e){
			System.out.println("There was an error in connecting to the server: " + e);
			return false;
		}
		return true;
	}

	public boolean isConnected() {
		if (sock == null || !sock.isConnected()) {
			return false;
		}
		else {
			return true;
		}
	}

	public void disconnect()	 {
		if (isConnected()) {
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				output.writeObject(message);
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
